package com.squirtle.gadget;

import com.squirtle.core.callgraph.CallGraph;
import soot.SootMethod;

import java.util.*;
import java.util.logging.Logger;

/**
 * Gadget链简化器（Flash的simplyGC策略）
 * 
 * 核心功能：检测并简化链条中的循环
 * 例如：A → B → C → D → C → E 简化为 A → C → E
 * 
 * 原理：
 * 1. 检测链条中重复出现的方法（按子签名）
 * 2. 如果可以直接从第一次出现跳到第二次出现，则删除中间节点
 * 3. 这样可以发现更短的有效路径
 * 
 * @author BugTurtle
 */
public class GadgetChainSimplifier {
    
    private static final Logger logger = Logger.getLogger(GadgetChainSimplifier.class.getName());
    
    private final CallGraph callGraph;
    
    public GadgetChainSimplifier(CallGraph callGraph) {
        this.callGraph = callGraph;
    }
    
    /**
     * 简化gadget链（Flash的simplyGC算法）
     * 
     * @param chain 原始链条
     * @return 简化后的链条
     */
    public GadgetChain simplify(GadgetChain chain) {
        List<CallGraph.CallEdge> edges = chain.getEdges();
        
        if (edges.size() <= 2) {
            return chain;  // 太短，无需简化
        }
        
        // 转换为source→sink顺序（Flash的处理方式）
        List<CallGraph.CallEdge> forwardEdges = new ArrayList<>(edges);
        Collections.reverse(forwardEdges);
        
        // 执行循环检测和简化
        List<CallGraph.CallEdge> simplified = detectAndRemoveLoops(forwardEdges, chain.getSource());
        
        // 如果没有简化，返回原链条
        if (simplified.size() == forwardEdges.size()) {
            return chain;
        }
        
        // 转回sink→source顺序
        Collections.reverse(simplified);
        
        // 创建简化后的链条
        return new GadgetChain(simplified, chain.getSource(), chain.getSink(), chain.getCategory());
    }
    
    /**
     * 检测并移除循环
     * 
     * Flash的核心逻辑：
     * - 遍历链条，记录每个方法的子签名
     * - 如果发现重复的子签名，检查是否可以跳过中间部分
     * - 如果可以，则创建新的"短路"边
     */
    private List<CallGraph.CallEdge> detectAndRemoveLoops(
            List<CallGraph.CallEdge> edges, SootMethod source) {
        
        List<String> subSigList = new ArrayList<>();
        List<CallGraph.CallEdge> result = new ArrayList<>();
        
        // 遍历每条边
        for (int i = 0; i < edges.size(); i++) {
            CallGraph.CallEdge edge = edges.get(i);
            SootMethod caller = edge.getCaller();
            // 使用完整签名（包含类名）而不是子签名，避免误判不同类的同名方法为循环
            String fullSig = caller.getSignature();
            
            // 检查是否出现过这个完整签名
            if (subSigList.contains(fullSig)) {
                // 找到第一次出现的位置
                int firstOccurrence = subSigList.lastIndexOf(fullSig);
                
                    // 只处理非起点的循环（Flash的策略）
                if (firstOccurrence > 0) {
                    // 尝试简化：删除从firstOccurrence到当前位置的中间节点
                    if (canSimplify(result, firstOccurrence, i, edges, source)) {
                        logger.fine(String.format("简化循环：检测到 %s 重复出现，从位置 %d 到 %d",
                            fullSig, firstOccurrence, i));
                        
                        // 执行简化：删除从firstOccurrence到end的边
                        int removeCount = subSigList.size() - firstOccurrence;
                        for (int j = 0; j < removeCount; j++) {
                            subSigList.remove(subSigList.size() - 1);
                            result.remove(result.size() - 1);
                        }
                        
                        // 创建短路边：从前一个边直接跳到当前方法
                        CallGraph.CallEdge shortcut = createShortcutEdge(
                            result.get(result.size() - 1), caller);
                        result.add(shortcut);
                        subSigList.add(fullSig);
                        
                        // 添加当前边
                        result.add(edge);
                        subSigList.add(edge.getCallee().getSignature());
                        
                        continue;
                    }
                }
            }
            
            // 正常添加
            subSigList.add(fullSig);
            result.add(edge);
        }
        
        return result;
    }
    
    /**
     * 检查是否可以简化
     * 
     * Flash的检查条件：
     * 1. 不是静态调用（需要通过对象传递污点）
     * 2. 从source到重复节点的路径仍然可控
     */
    private boolean canSimplify(List<CallGraph.CallEdge> currentPath, 
                               int loopStart, int currentIndex,
                               List<CallGraph.CallEdge> fullPath,
                               SootMethod source) {
        
        // 检查前一条边是否是静态调用
        if (currentPath.size() > loopStart) {
            CallGraph.CallEdge prevEdge = currentPath.get(loopStart - 1);
            if (prevEdge.getCallType() == CallGraph.CallType.STATIC) {
                return false;  // 静态调用不能简化
            }
        }
        
        // Flash还会检查可控性，但BugTurtle已经在剪枝阶段处理了
        // 所以这里简化检查：只要在剪枝图中，就认为可控
        
        return true;
    }
    
    /**
     * 创建短路边
     * 
     * 从prevEdge的调用点直接跳到targetMethod
     */
    private CallGraph.CallEdge createShortcutEdge(CallGraph.CallEdge prevEdge, 
                                                  SootMethod targetMethod) {
        // 创建一个新的边：prevEdge.caller → targetMethod
        // 保持prevEdge的caller，但callee改为targetMethod
        
        return new CallGraph.CallEdge(
            prevEdge.getCaller(),
            targetMethod,
            prevEdge.getCallSite(),
            prevEdge.getCallType()
        );
    }
    
    /**
     * 批量简化
     */
    public List<GadgetChain> simplifyAll(List<GadgetChain> chains) {
        List<GadgetChain> simplified = new ArrayList<>();
        
        int originalTotal = 0;
        int simplifiedTotal = 0;
        
        for (GadgetChain chain : chains) {
            int originalLen = chain.getLength();
            GadgetChain simpleChain = simplify(chain);
            int simplifiedLen = simpleChain.getLength();
            
            simplified.add(simpleChain);
            
            originalTotal += originalLen;
            simplifiedTotal += simplifiedLen;
            
            if (simplifiedLen < originalLen) {
                logger.fine(String.format("链条简化：%d → %d 步", originalLen, simplifiedLen));
            }
        }
        
        if (originalTotal > simplifiedTotal) {
            logger.info(String.format("简化统计：总步数 %d → %d，减少 %d 步（%.1f%%）",
                originalTotal, simplifiedTotal, originalTotal - simplifiedTotal,
                100.0 * (originalTotal - simplifiedTotal) / originalTotal));
        }
        
        return simplified;
    }
}

