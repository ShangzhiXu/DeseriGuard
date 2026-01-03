package com.squirtle.gadget;

import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.callgraph.CallGraph.CallEdge;
import soot.SootMethod;

import java.util.*;
import java.util.logging.Logger;

/**
 * Gadget链搜索器 - 基于Flash设计
 * 
 * 核心策略：
 * 1. 反向DFS搜索（从sink→source）
 * 2. 多重防护（循环、超时、深度）
 * 3. 链简化（Flash的simplyGC）和去重（Flash的LCS）
 * 
 * 注意：基于pruned graph搜索，不需要再做可控性检查
 * 
 * @author BugTurtle
 */
public class GadgetChainSearcher {
    
    private static final Logger logger = Logger.getLogger(GadgetChainSearcher.class.getName());
    
    private final CallGraph prunedGraph;
    private final SourceSinkManager sourceSinkMgr;
    
    // 搜索参数
    private final int maxDepth;
    private final long sinkMaxTimeMs;
    
    // Flash策略：简化和去重
    private final GadgetChainSimplifier simplifier;
    private final GadgetChainDeduplicator deduplicator;
    
    // 统计
    private int totalChains = 0;
    private int timeoutSinks = 0;
    
    // 在线去重（Flash的策略：边搜索边去重）
    private final Map<String, Set<List<String>>> dedupMap = new HashMap<>();
    private final List<GadgetChain> uniqueChains = new ArrayList<>();
    
    /**
     * 构造函数
     */
    public GadgetChainSearcher(CallGraph prunedGraph, SourceSinkManager sourceSinkMgr) {
        this(prunedGraph, sourceSinkMgr, 12, 180000);
    }
    
    public GadgetChainSearcher(CallGraph prunedGraph, SourceSinkManager sourceSinkMgr,
                              int maxDepth, long sinkMaxTimeMs) {
        this.prunedGraph = prunedGraph;
        this.sourceSinkMgr = sourceSinkMgr;
        this.maxDepth = maxDepth;
        this.sinkMaxTimeMs = sinkMaxTimeMs;
        this.simplifier = new GadgetChainSimplifier(prunedGraph);
        this.deduplicator = new GadgetChainDeduplicator(0.8);  // Flash的阈值
    }
    
    /**
     * 搜索单个sink的gadget链（用于测试）
     */
    public List<GadgetChain> searchSingleSink(SootMethod sink) {
        uniqueChains.clear();
        dedupMap.clear();
        totalChains = 0;
        timeoutSinks = 0;
        
        logger.info("搜索单个Sink: " + sink.getSignature());
        
        long startTime = System.currentTimeMillis();
        searchFromSink(sink, startTime);
        
        logger.info(String.format("搜索完成！原始链: %d 条 → 去重后: %d 条", 
            totalChains, uniqueChains.size()));
        
        return new ArrayList<>(uniqueChains);
    }
    
    /**
     * 搜索所有gadget链（Flash策略：在线去重）
     */
    public List<GadgetChain> searchAll() {
        // 清空之前的结果
        uniqueChains.clear();
        dedupMap.clear();
        totalChains = 0;
        timeoutSinks = 0;
        
        Set<SootMethod> sinks = sourceSinkMgr.getSinkMethods();
        logger.info("开始搜索gadget链（在线去重），共 " + sinks.size() + " 个Sink方法");
        
        int sinkIndex = 0;
        for (SootMethod sink : sinks) {
            sinkIndex++;
            String sinkName = sink.getName();
            logger.info(String.format("[%d/%d] 处理Sink: %s", sinkIndex, sinks.size(), sinkName));
            
            long startTime = System.currentTimeMillis();
            int beforeCount = uniqueChains.size();
            
            // 直接在pruned graph上搜索（不构建子图）
            searchFromSink(sink, startTime);
            
            int foundCount = uniqueChains.size() - beforeCount;
            logger.info(String.format("  新增 %d 条唯一链 (总计: %d, 原始: %d, 耗时 %.2fs)", 
                foundCount, uniqueChains.size(), totalChains, 
                (System.currentTimeMillis() - startTime) / 1000.0));
        }
        
        logger.info(String.format("搜索完成！原始链: %d 条 → 去重后: %d 条, 超时sink: %d 个", 
            totalChains, uniqueChains.size(), timeoutSinks));
        
        return new ArrayList<>(uniqueChains);
    }
    
    /**
     * 从单个Sink搜索
     */
    private void searchFromSink(SootMethod sink, long searchStartTime) {
        // 获取sink的所有入边
        Set<CallEdge> inEdges = prunedGraph.getIncomingEdges(sink);
        if (inEdges.isEmpty()) {
            return;
        }
        
        // 从每条入边开始反向DFS
        for (CallEdge edge : inEdges) {
            List<CallEdge> currentPath = new ArrayList<>();
            Set<SootMethod> visited = new HashSet<>();
            Map<String, Integer> methodNameCount = new HashMap<>();  // 方法名计数
            
            // ✅ 传入真正的sink（从配置中读取的）
            backwardDFS(sink, edge, currentPath, visited, methodNameCount, searchStartTime, sink);
        }
    }
    
    /**
     * 反向DFS核心算法（Flash策略：在线去重）
     * @param realSink 真正的sink（从SourceSinkManager配置中读取的）
     */
    private void backwardDFS(SootMethod callee, CallEdge curEdge, 
                            List<CallEdge> curPath, Set<SootMethod> visited,
                            Map<String, Integer> methodNameCount,
                            long searchStartTime, SootMethod realSink) {
        
        // 防护1: 超时检查
        if (System.currentTimeMillis() - searchStartTime > sinkMaxTimeMs) {
            timeoutSinks++;
            return;
        }
        
        SootMethod caller = curEdge.getCaller();
        
        // 防护2: 循环检测（Flash策略：已访问直接返回，不回溯）
        if (!visited.add(caller)) {
            return;
        }
        
        // 防护3: 同名方法频率限制（打破环路）
        String methodName = caller.getName();
        if (isUtilityMethod(methodName)) {
            int count = methodNameCount.getOrDefault(methodName, 0);
            
            // 🎯 差异化threshold：高风险方法更严格
            int threshold = getMethodThreshold(methodName);
            
            if (count >= threshold) {
                // 该utility方法已经在路径中出现threshold次，跳过
                visited.remove(caller);
                return;
            }
            methodNameCount.put(methodName, count + 1);
        }
        
        // 添加到路径
        curPath.add(curEdge);
        
        // 检查是否到达Source
        if (sourceSinkMgr.isSource(caller)) {
            // ✅ 使用配置中的sink（而不是从curPath提取）
            SourceSinkManager.SinkCategory category = sourceSinkMgr.getSinkCategory(realSink);
            
            // 创建gadget链
            GadgetChain chain = new GadgetChain(
                new ArrayList<>(curPath),
                caller,  // source
                realSink,    // sink（来自配置）
                category
            );
            
            // Flash策略：找到链时立即去重
            addChainWithDedup(chain);
            totalChains++;
        } else if (curPath.size() >= maxDepth) {
            // 防护4: 深度限制，回溯后返回
            if (isUtilityMethod(methodName)) {
                methodNameCount.put(methodName, methodNameCount.get(methodName) - 1);
            }
            visited.remove(caller);
            curPath.remove(curPath.size() - 1);
            return;
        } else {
            // 继续向上搜索
            Set<CallEdge> inEdges = prunedGraph.getIncomingEdges(caller);
            
            // 🎯 第二层优化：高入度方法限制 + 优先级排序
            List<CallEdge> edgesToSearch = selectEdgesToExplore(inEdges, caller);
            
            for (CallEdge edge : edgesToSearch) {
                backwardDFS(caller, edge, curPath, visited, methodNameCount, searchStartTime, realSink);
            }
        }
        
        // 回溯（只在继续搜索的分支才会执行到这里）
        if (isUtilityMethod(methodName)) {
            methodNameCount.put(methodName, methodNameCount.get(methodName) - 1);
        }
        visited.remove(caller);
        curPath.remove(curPath.size() - 1);
    }
    
    /**
     * 判断是否为需要限制的utility方法
     * 注意：不包括<init>，因为很多gadget链需要通过构造函数
     * 
     * 限制原因：这些方法在调用图中形成环路，导致搜索空间爆炸
     * - get/put: 高频方法，是主要的爆炸源
     * - equals/hashCode: 被get/put调用，形成二次爆炸
     * - iterator/hasNext/next: 接口边爆炸源（iterator 1511次调用）
     */
    private boolean isUtilityMethod(String methodName) {
        return methodName.equals("equals") ||
               methodName.equals("hashCode") ||
               methodName.equals("toString") ||
               methodName.equals("clone") ||
               methodName.equals("iterator") ||
               methodName.equals("listIterator") ||
               methodName.equals("hasNext") ||      // 新增：接口边Top2 (7700次)
               methodName.equals("next") ||         // 新增：接口边Top1 (10884次)
               methodName.equals("append") ||
               methodName.equals("get") ||
               methodName.equals("put");
    }
    
    /**
     * 获取不同utility方法的threshold
     * 
     * 基于对16条真实gadget链的分析：
     * - equals/hashCode: 最多出现1-2次，设threshold=2
     * - get/put: 最多出现1-2次，设threshold=2
     * - iterator/hasNext/next: 迭代器方法，threshold=2
     * - toString/clone/append: 较少风险，threshold=3
     * 
     * @param methodName 方法名
     * @return threshold值
     */
    private int getMethodThreshold(String methodName) {
        // 高风险方法：threshold=2
        if (methodName.equals("equals") ||
            methodName.equals("hashCode") ||
            methodName.equals("get") ||
            methodName.equals("put") ||
            methodName.equals("iterator") ||
            methodName.equals("hasNext") ||
            methodName.equals("next")) {
            return 2;
        }
        
        // 中低风险方法：threshold=3
        return 3;
    }
    
    /**
     * 🎯 第二层优化：选择要探索的入边（高入度方法限制 + 优先级排序）
     * 
     * 策略：
     * 1. 如果入度<=100，探索所有边
     * 2. 如果入度>100，按优先级排序后只探索前30条
     *    优先级：gadget包 > 应用类 > JDK类
     * 
     * @param inEdges 所有入边
     * @param callee 被调用方法
     * @return 要探索的边列表
     */
    private List<CallEdge> selectEdgesToExplore(Set<CallEdge> inEdges, SootMethod callee) {
        List<CallEdge> edgeList = new ArrayList<>(inEdges);
        
        // 如果入度不高，探索所有边
        if (edgeList.size() <= 100) {
            return edgeList;
        }
        
        // 高入度方法：按优先级排序
        edgeList.sort((e1, e2) -> {
            int priority1 = getCallerPriority(e1.getCaller());
            int priority2 = getCallerPriority(e2.getCaller());
            return Integer.compare(priority2, priority1);  // 降序（高优先级在前）
        });
        
        // 只取前30条
        return edgeList.subList(0, Math.min(30, edgeList.size()));
    }
    
    /**
     * 获取调用者的优先级（用于高入度方法排序）
     * 
     * @param caller 调用者方法
     * @return 优先级值（越大越优先）
     */
    private int getCallerPriority(SootMethod caller) {
        String packageName = caller.getDeclaringClass().getPackageName();
        String className = caller.getDeclaringClass().getName();
        
        // 优先级1（最高）：已知gadget包
        if (packageName.startsWith("org.apache.commons.collections.functors") ||
            packageName.startsWith("org.apache.commons.collections.map") ||
            packageName.startsWith("org.apache.commons.collections.keyvalue") ||
            className.contains("Transformer") ||
            className.contains("LazyMap") ||
            className.contains("TiedMapEntry")) {
            return 100;
        }
        
        // 优先级2：应用程序类（非JDK）
        if (!packageName.startsWith("java.") && 
            !packageName.startsWith("javax.") &&
            !packageName.startsWith("sun.") &&
            !packageName.startsWith("com.sun.")) {
            return 50;
        }
        
        // 优先级3（最低）：JDK类
        return 10;
    }
    
    /**
     * 搜索并输出到文件
     * 
     * @param outputPath 输出文件路径
     * @param enableTiering 是否按长度分层输出
     */
    public void searchAndOutput(String outputPath, boolean enableTiering) {
        // 执行搜索
        List<GadgetChain> chains = searchAll();
        
        // 输出到文件
        try {
            GadgetChainOutputWriter writer = new GadgetChainOutputWriter(outputPath, enableTiering);
            writer.write(chains);
            
            logger.info("✅ Gadget链已成功输出到: " + outputPath);
            
            // 输出详细报告（可选）
            if (!chains.isEmpty()) {
                String detailedPath = outputPath.replace(".txt", "_detailed.txt");
                writer.writeDetailed(chains, detailedPath);
            }
            
        } catch (Exception e) {
            logger.severe("输出文件失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Flash策略：在线去重（模仿Flash的dedup方法）
     * 
     * 使用source-sink pair + LCS相似度进行去重
     */
    private void addChainWithDedup(GadgetChain chain) {
        // 1. 提取方法签名列表
        List<String> methodSigs = new ArrayList<>();
        for (SootMethod method : chain.getMethods()) {
            methodSigs.add(method.getSignature());
        }
        
        // 2. 生成去重key（source#sink）
        String key = chain.getSource().getSignature() + "#" + chain.getSink().getSignature();
        
        // 3. 提取子签名列表（用于LCS比较）
        List<String> subSigs = new ArrayList<>();
        for (String sig : methodSigs) {
            subSigs.add(extractSubSignature(sig));
        }
        
        // 4. 检查是否与已有链条重复
        dedupMap.putIfAbsent(key, new HashSet<>());
        
        for (List<String> existingSubs : dedupMap.get(key)) {
            double similarity = GadgetChainDeduplicator.computeLCS(existingSubs, subSigs);
            if (similarity >= 0.8) {  // Flash的LCS阈值
                return;  // 重复，丢弃
            }
        }
        
        // 5. 不重复，添加到结果集
        dedupMap.get(key).add(subSigs);
        uniqueChains.add(chain);
    }
    
    /**
     * 提取子签名（去除类名）
     */
    private String extractSubSignature(String fullSignature) {
        // <java.lang.Runtime: java.lang.Process exec(java.lang.String)>
        // → java.lang.Process exec(java.lang.String)
        int colonIndex = fullSignature.indexOf(':');
        if (colonIndex > 0 && colonIndex < fullSignature.length() - 1) {
            String sub = fullSignature.substring(colonIndex + 2);
            return sub.substring(0, sub.length() - 1);  // 去掉末尾的 >
        }
        return fullSignature;
    }
    
    /**
     * 获取统计信息
     */
    public String getStatistics() {
        return String.format("总链数=%d, 去重后=%d, 超时sink数=%d", 
            totalChains, uniqueChains.size(), timeoutSinks);
    }
}
