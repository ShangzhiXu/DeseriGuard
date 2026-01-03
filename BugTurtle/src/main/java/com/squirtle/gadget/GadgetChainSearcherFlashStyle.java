package com.squirtle.gadget;

import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.pruning.CallEdgeControllabilityAnalyzer;
import soot.SootMethod;

import java.io.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * Gadget链搜索器 - 严格基于Flash实现
 * 
 * 核心策略（完全模仿Flash的GCCollectorAfterProcess）：
 * 1. 反向DFS：从sink往source搜索
 * 2. 可控性剪枝：每步检查边的可控性（使用BugTurtle的可控性图）
 * 3. 防护机制：超时、深度限制、循环检测
 * 4. LCS去重：相似度>0.8视为重复
 * 5. 输出格式：与Flash完全一致
 * 
 * 与Flash的区别：
 * - Flash：动态传播可控性（TCList）
 * - BugTurtle：直接查询CallEdgeControllabilityAnalyzer的结果
 * 
 * @author BugTurtle
 */
public class GadgetChainSearcherFlashStyle {
    
    private static final Logger logger = Logger.getLogger(GadgetChainSearcherFlashStyle.class.getName());
    
    // Flash的配置参数
    private static final int MAX_LEN = 12;              // 最大链长度
    private static final int SINK_MAX_TIME = 180;       // 每个sink最多搜索时间(秒)
    private static final double LCS_THRESHOLD = 0.8;    // LCS相似度阈值
    
    private final CallGraph callGraph;
    private final SourceSinkManager sourceSinkManager;
    private final Map<CallGraph.CallEdge, CallEdgeControllabilityAnalyzer.Controllability> edgeControllability;
    
    private final Set<List<String>> foundGadgetChains = new HashSet<>();
    private final Map<String, Set<List<String>>> dedupMap = new HashMap<>();
    
    private PrintWriter outputWriter;
    private int totalChains = 0;
    
    public GadgetChainSearcherFlashStyle(
            CallGraph callGraph,
            SourceSinkManager sourceSinkManager,
            Map<CallGraph.CallEdge, CallEdgeControllabilityAnalyzer.Controllability> edgeControllability) {
        this.callGraph = callGraph;
        this.sourceSinkManager = sourceSinkManager;
        this.edgeControllability = edgeControllability;
    }
    
    /**
     * 执行gadget链搜索（Flash的onFinish等价）
     */
    public void search(String outputPath) {
        try {
            File outputFile = new File(outputPath);
            outputFile.getParentFile().mkdirs();
            this.outputWriter = new PrintWriter(new BufferedWriter(new FileWriter(outputFile)));
            
            logger.info("🚀 开始gadget链搜索（Flash风格）");
            logger.info("配置: MAX_LEN=" + MAX_LEN + ", SINK_MAX_TIME=" + SINK_MAX_TIME + "s, LCS_THRESHOLD=" + LCS_THRESHOLD);
            
            Set<SootMethod> sinks = sourceSinkManager.getSinkMethods();
            logger.info("找到 " + sinks.size() + " 个sink方法");
            
            int sinkCount = 0;
            for (SootMethod sink : sinks) {
                sinkCount++;
                logger.info("[" + sinkCount + "/" + sinks.size() + "] 反向搜索自 " + sink);
                getGadgetChainsFromSink(sink);
            }
            
            logger.info("✅ gadget链搜索完成");
            logger.info("total gadget chains : " + totalChains);
            outputWriter.println("total gadget chains : " + totalChains);
            outputWriter.flush();
            
        } catch (IOException e) {
            logger.severe("输出文件创建失败: " + e.getMessage());
        } finally {
            if (outputWriter != null) {
                outputWriter.close();
            }
        }
    }
    
    /**
     * Flash的getGCs方法：从一个sink开始搜索所有gadget链
     */
    private void getGadgetChainsFromSink(SootMethod sink) {
        // 获取所有调用这个sink的边（反向边）
        Set<CallGraph.CallEdge> incomingEdges = callGraph.getIncomingEdges(sink);
        
        if (incomingEdges.isEmpty()) {
            logger.fine("  sink无入边，跳过: " + sink.getSignature());
            return;
        }
        
        // Flash的逻辑：先检查有多少可控的入边
        int controllableCount = 0;
        for (CallGraph.CallEdge edge : incomingEdges) {
            if (isEdgeControllable(edge)) {
                controllableCount++;
            }
        }
        
        if (controllableCount == 0) {
            logger.fine("  sink无可控入边，跳过");
            return;
        }
        
        // 为每个可控入边启动反向DFS
        int perEdgeTime = (SINK_MAX_TIME * 1000) / controllableCount;
        logger.fine("  找到 " + controllableCount + " 条可控入边，每条分配 " + (perEdgeTime/1000) + "s");
        
        for (CallGraph.CallEdge edge : incomingEdges) {
            if (!isEdgeControllable(edge)) {
                continue;
            }
            
            List<CallGraph.CallEdge> currentChain = new ArrayList<>();
            long startTime = System.currentTimeMillis();
            backwardDFS(sink, edge, currentChain, new HashSet<>(), startTime, perEdgeTime);
        }
    }
    
    /**
     * Flash的backDFS方法：反向深度优先搜索
     * 
     * @param callee 当前方法（被调用者）
     * @param curEdge 当前边
     * @param currentChain 当前链条
     * @param visited 已访问集合
     * @param startTime 搜索开始时间
     * @param timeLimit 时间限制(ms)
     */
    private void backwardDFS(
            SootMethod callee,
            CallGraph.CallEdge curEdge,
            List<CallGraph.CallEdge> currentChain,
            Set<SootMethod> visited,
            long startTime,
            int timeLimit) {
        
        // 1. 防护检查
        if (!visited.add(callee)) {
            return; // 循环检测
        }
        
        if (System.currentTimeMillis() - startTime > timeLimit) {
            visited.remove(callee);
            return; // 超时
        }
        
        // 2. 可控性剪枝（BugTurtle：直接查询边的可控性）
        if (!isEdgeControllable(curEdge)) {
            visited.remove(callee);
            return;
        }
        
        // 3. 获取调用者并添加到链条
        SootMethod caller = curEdge.getCaller();
        currentChain.add(curEdge);
        
        // 4. 判断是否到达source
        if (sourceSinkManager.isSource(caller)) {
            // 找到完整链条！
            List<CallGraph.CallEdge> gadgetChain = new ArrayList<>(currentChain);
            Collections.reverse(gadgetChain); // 反转（source到sink方向）
            
            // Flash的过滤和去重流程
            if (processGadgetChain(gadgetChain)) {
                logAndWriteChain(gadgetChain);
                totalChains++;
            }
        } 
        // 5. 达到最大深度
        else if (currentChain.size() >= MAX_LEN) {
            visited.remove(callee);
            currentChain.remove(currentChain.size() - 1);
            return;
        } 
        // 6. 继续往上搜索
        else {
            Set<CallGraph.CallEdge> incomingEdges = callGraph.getIncomingEdges(caller);
            for (CallGraph.CallEdge edge : incomingEdges) {
                backwardDFS(caller, edge, currentChain, visited, startTime, timeLimit);
            }
        }
        
        // 7. 回溯
        visited.remove(callee);
        currentChain.remove(currentChain.size() - 1);
    }
    
    /**
     * 检查边是否可控（BugTurtle版本：查询预先计算的可控性）
     */
    private boolean isEdgeControllable(CallGraph.CallEdge edge) {
        CallEdgeControllabilityAnalyzer.Controllability controllability = 
            edgeControllability.get(edge);
        
        if (controllability == null) {
            return false; // 未分析的边视为不可控
        }
        
        // Flash的allControllable等价：检查是否CONTROLLABLE
        return controllability == CallEdgeControllabilityAnalyzer.Controllability.CONTROLLABLE;
    }
    
    /**
     * 处理gadget链（过滤和去重）
     */
    private boolean processGadgetChain(List<CallGraph.CallEdge> chain) {
        // Flash的filterEdge和typeCheck在这里
        // 简化版：只进行去重
        
        List<String> chainSignatures = getChainSignatures(chain);
        
        // LCS去重
        if (!dedupChain(chainSignatures)) {
            return false;
        }
        
        foundGadgetChains.add(chainSignatures);
        return true;
    }
    
    /**
     * LCS去重（Flash的dedup方法）
     */
    private boolean dedupChain(List<String> chainSignatures) {
        if (chainSignatures.size() < 2) {
            return false;
        }
        
        String source = chainSignatures.get(0);
        String sink = chainSignatures.get(chainSignatures.size() - 1);
        String key = source + "#" + sink;
        
        // 提取子签名（方法名）
        List<String> subSignatures = extractSubSignatures(chainSignatures);
        
        dedupMap.putIfAbsent(key, new HashSet<>());
        
        // 与已有链条比较LCS相似度
        for (List<String> existingChain : dedupMap.get(key)) {
            double similarity = computeLCS(subSignatures, existingChain);
            if (similarity >= LCS_THRESHOLD) {
                return false; // 重复
            }
        }
        
        dedupMap.get(key).add(subSignatures);
        return true;
    }
    
    /**
     * 计算LCS相似度（Flash的computeLCS方法）
     */
    private static double computeLCS(List<String> list1, List<String> list2) {
        if (list1.isEmpty() || list2.isEmpty()) {
            return 0.0;
        }
        
        int lcsLength = computeLCSLength(list1, list2);
        return (2.0 * lcsLength) / (list1.size() + list2.size());
    }
    
    /**
     * 计算LCS长度（Flash的computeLCSLength方法）
     */
    private static int computeLCSLength(List<String> list1, List<String> list2) {
        int m = list1.size();
        int n = list2.size();
        int[][] dp = new int[m + 1][n + 1];
        
        for (int i = 1; i <= m; i++) {
            String s1 = list1.get(i - 1);
            for (int j = 1; j <= n; j++) {
                String s2 = list2.get(j - 1);
                if (s1.equals(s2)) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
                }
            }
        }
        
        return dp[m][n];
    }
    
    /**
     * 获取链条的方法签名列表
     */
    private List<String> getChainSignatures(List<CallGraph.CallEdge> chain) {
        List<String> signatures = new ArrayList<>();
        
        // 添加source（第一个caller）
        if (!chain.isEmpty()) {
            signatures.add(chain.get(0).getCaller().getSignature());
        }
        
        // 添加中间节点和sink
        for (CallGraph.CallEdge edge : chain) {
            signatures.add(edge.getCallee().getSignature());
        }
        
        return signatures;
    }
    
    /**
     * 提取子签名（方法名）用于LCS比较
     */
    private List<String> extractSubSignatures(List<String> fullSignatures) {
        List<String> subSignatures = new ArrayList<>();
        for (String sig : fullSignatures) {
            subSignatures.add(extractMethodName(sig));
        }
        return subSignatures;
    }
    
    /**
     * 从完整签名提取方法名
     * 例如: "<Class: void method()>" -> "method"
     */
    private String extractMethodName(String signature) {
        if (signature.contains(":")) {
            String methodPart = signature.split(":")[1].trim();
            if (methodPart.contains(" ")) {
                String[] parts = methodPart.split("\\s+");
                if (parts.length >= 2) {
                    String nameAndParams = parts[1];
                    if (nameAndParams.contains("(")) {
                        return nameAndParams.substring(0, nameAndParams.indexOf("("));
                    }
                }
            }
        }
        return signature;
    }
    
    /**
     * 输出gadget链（Flash的logAndWrite方法）
     */
    private void logAndWriteChain(List<CallGraph.CallEdge> chain) {
        try {
            logger.info("发现gadget链 (长度=" + chain.size() + "):");
            
            // 输出source
            SootMethod source = chain.get(0).getCaller();
            String sourceLine = source.getSignature();
            logger.info("  " + sourceLine);
            outputWriter.println(sourceLine);
            
            // 输出每条边（caller -> callee）
            for (CallGraph.CallEdge edge : chain) {
                String calleeLine = edge.getCallee().getSignature();
                
                // 添加可控性信息（简化版）
                CallEdgeControllabilityAnalyzer.Controllability controllability = 
                    edgeControllability.get(edge);
                String controllabilityStr = controllability != null ? controllability.toString() : "UNKNOWN";
                
                logger.info("  " + calleeLine + " [" + controllabilityStr + "]");
                outputWriter.println(calleeLine);
            }
            
            // 空行分隔
            logger.info("");
            outputWriter.println("");
            outputWriter.flush();
            
        } catch (Exception e) {
            logger.warning("输出链条失败: " + e.getMessage());
        }
    }
    
    /**
     * 获取搜索统计信息
     */
    public SearchStatistics getStatistics() {
        return new SearchStatistics(
            totalChains,
            foundGadgetChains.size(),
            sourceSinkManager.getSourceMethods().size(),
            sourceSinkManager.getSinkMethods().size()
        );
    }
    
    /**
     * 搜索统计信息
     */
    public static class SearchStatistics {
        public final int totalChains;
        public final int uniqueChains;
        public final int sourceCount;
        public final int sinkCount;
        
        public SearchStatistics(int totalChains, int uniqueChains, int sourceCount, int sinkCount) {
            this.totalChains = totalChains;
            this.uniqueChains = uniqueChains;
            this.sourceCount = sourceCount;
            this.sinkCount = sinkCount;
        }
        
        @Override
        public String toString() {
            return String.format("Sources=%d, Sinks=%d, TotalChains=%d, UniqueChains=%d",
                sourceCount, sinkCount, totalChains, uniqueChains);
        }
    }
}

