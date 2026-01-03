package com.squirtle.core.callgraph;

import com.squirtle.core.sink.FlashAlignedSinkRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.SootMethod;

import java.util.*;

/**
 * 调用图剪枝器：删除不可达sink的边，减少误报
 */
public class CallGraphPruner {
    private static final Logger logger = LoggerFactory.getLogger(CallGraphPruner.class);
    
    private final CallGraph graph;
    private final FlashAlignedSinkRegistry sinkRegistry;
    
    public CallGraphPruner(CallGraph graph, FlashAlignedSinkRegistry sinkRegistry) {
        this.graph = graph;
        this.sinkRegistry = sinkRegistry;
    }
    
    /**
     * 剪枝反射方法的边：只保留能到达sink的目标
     * 
     * @param reflectionMethod 反射方法（如Constructor.newInstance）
     * @return 剪枝统计信息
     */
    public PruneResult pruneReflectionMethod(SootMethod reflectionMethod) {
        logger.info("开始剪枝反射方法: {}", reflectionMethod.getSignature());
        
        // 🔥 关键修复：创建边集合的副本，避免在遍历时修改
        Set<CallGraph.CallEdge> outEdges = new HashSet<>(graph.getOutgoingEdges(reflectionMethod));
        int originalCount = outEdges.size();
        
        // 收集所有目标方法
        Set<SootMethod> targets = new HashSet<>();
        for (CallGraph.CallEdge edge : outEdges) {
            targets.add(edge.getCallee());
        }
        
        // 检查每个目标是否能到达sink
        Set<SootMethod> reachableSinks = new HashSet<>();
        Set<SootMethod> unreachable = new HashSet<>();
        
        for (SootMethod target : targets) {
            if (canReachAnySink(target)) {
                reachableSinks.add(target);
            } else {
                unreachable.add(target);
            }
        }
        
        // 删除不可达sink的边
        int removedCount = 0;
        int expectedRemaining = 0;  // 🔥 修复：统计指向可达方法的实际边数
        List<CallGraph.CallEdge> edgesToRemove = new ArrayList<>();
        
        for (CallGraph.CallEdge edge : outEdges) {
            if (unreachable.contains(edge.getCallee())) {
                edgesToRemove.add(edge);
                removedCount++;
            } else {
                // 🔥 统计保留的边
                expectedRemaining++;
            }
        }
        
        // 执行删除
        int actualRemoved = 0;
        int failedRemove = 0;
        for (CallGraph.CallEdge edge : edgesToRemove) {
            boolean removed = graph.removeEdge(edge);
            if (removed) {
                actualRemoved++;
            } else {
                failedRemove++;
            }
        }
        
        // 验证删除是否生效
        int afterRemoval = graph.getOutgoingEdges(reflectionMethod).size();
        
        System.out.println("    删除执行详情:");
        System.out.println("      预期删除: " + removedCount);
        System.out.println("      成功删除: " + actualRemoved);
        System.out.println("      失败删除: " + failedRemove);
        System.out.println("      删除后边数: " + afterRemoval);
        System.out.println("      预期剩余（边数）: " + expectedRemaining);
        System.out.println("      可达方法数: " + reachableSinks.size());
        
        if (actualRemoved != removedCount) {
            System.out.println("      ⚠️ 警告：有" + failedRemove + "条边删除失败！");
            logger.warn("删除失败！预期删除{}, 实际删除{}", removedCount, actualRemoved);
        }
        if (afterRemoval != expectedRemaining) {
            System.out.println("      ⚠️ 警告：删除后边数与预期不符！");
            logger.warn("删除后边数不匹配！预期{}, 实际{}", expectedRemaining, afterRemoval);
        }
        
        logger.info("剪枝完成: 原始边数={}, 保留={} ({}个方法), 删除={}, 剪枝率={:.2f}%",
                originalCount, expectedRemaining, reachableSinks.size(), removedCount,
                (removedCount * 100.0 / originalCount));
        
        return new PruneResult(originalCount, expectedRemaining, removedCount);
    }
    
    /**
     * 检查方法是否能到达任何sink（使用BFS）
     * 
     * @param method 起始方法
     * @return true if 能到达sink
     */
    private boolean canReachAnySink(SootMethod method) {
        // 快速检查：方法本身是否是sink
        if (isSink(method)) {
            return true;
        }
        
        // BFS搜索
        Queue<SootMethod> queue = new LinkedList<>();
        Set<SootMethod> visited = new HashSet<>();
        
        queue.add(method);
        visited.add(method);
        
        // 🔥 优化：提高搜索深度和广度限制
        // 深度限制：从10提高到20（允许更深的调用链）
        // 广度限制：从1000提高到5000（允许更复杂的调用图子树）
        int maxDepth = 20;
        int maxNodes = 5000;
        Map<SootMethod, Integer> depthMap = new HashMap<>();
        depthMap.put(method, 0);
        
        while (!queue.isEmpty()) {
            SootMethod current = queue.poll();
            int depth = depthMap.get(current);
            
            // 超过最大深度，停止搜索
            if (depth >= maxDepth) {
                continue;
            }
            
            // 遍历所有后继
            Set<CallGraph.CallEdge> edges = graph.getOutgoingEdges(current);
            for (CallGraph.CallEdge edge : edges) {
                SootMethod next = edge.getCallee();
                
                // 检查是否是sink
                if (isSink(next)) {
                    return true;
                }
                
                // 继续搜索
                if (!visited.contains(next)) {
                    visited.add(next);
                    queue.add(next);
                    depthMap.put(next, depth + 1);
                }
            }
            
            // 避免搜索过多节点
            if (visited.size() > maxNodes) {
                // 保守策略：如果搜索空间太大，认为可能可达
                conservativeCount++;
                logger.debug("搜索空间过大 (>{}节点)，保守保留: {}", maxNodes, method.getSignature());
                return true;
            }
        }
        
        return false;
    }
    
    private int conservativeCount = 0;  // 因保守策略保留的数量
    
    public int getConservativeCount() {
        return conservativeCount;
    }
    
    /**
     * 检查方法是否是sink（简化版，不检查污点）
     */
    private boolean isSink(SootMethod method) {
        return sinkRegistry.getSinkDefinition(method.getSignature()) != null;
    }
    
    /**
     * 删除死节点（Dead Code Elimination）- 级联迭代版本
     * 
     * 死节点定义：无入边的非入口节点（永远无法被访问到的孤岛）
     * 
     * 🔥 级联删除：删除死节点后，可能产生新的死节点（之前只被死节点引用）
     *    需要多轮迭代直到没有新的死节点
     * 
     * @param entryPoints 入口点集合（readObject等）
     * @return 删除的节点数和边数
     */
    public DeadNodeResult removeDeadNodes(Set<SootMethod> entryPoints) {
        logger.info("开始清理死节点（Dead Code Elimination - 级联迭代）");
        
        int totalRemovedNodes = 0;
        int totalRemovedEdges = 0;
        int iteration = 0;
        int originalNodeCount = graph.getAllMethods().size();
        
        // 🔥 多轮迭代，直到没有新的死节点
        while (true) {
            iteration++;
            
            // 1. 收集所有当前节点
            Set<SootMethod> allNodes = graph.getAllMethods();
            
            // 2. 查找死节点（无入边的非入口节点）
            Set<SootMethod> deadNodes = new HashSet<>();
            
            for (SootMethod method : allNodes) {
                // 入口节点不是死节点
                if (entryPoints.contains(method)) {
                    continue;
                }
                
                // 检查是否有入边
                Set<CallGraph.CallEdge> inEdges = graph.getIncomingEdges(method);
                if (inEdges.isEmpty()) {
                    deadNodes.add(method);
                }
            }
            
            // 没有死节点了，退出迭代
            if (deadNodes.isEmpty()) {
                logger.info("第{}轮：没有发现死节点，迭代结束", iteration);
                break;
            }
            
            logger.info("第{}轮：发现 {} 个死节点", iteration, deadNodes.size());
            
            // 3. 统计死节点的出边数
            int deadEdges = 0;
            for (SootMethod deadNode : deadNodes) {
                deadEdges += graph.getOutgoingEdges(deadNode).size();
            }
            
            // 4. 第一轮显示详细统计
            if (iteration == 1) {
                Map<String, Integer> packageDist = analyzeDeadNodePackages(deadNodes);
                logger.info("死节点包分布（Top 10）:");
                packageDist.entrySet().stream()
                        .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
                        .limit(10)
                        .forEach(e -> System.out.println("  " + e.getKey() + ": " + e.getValue()));
            }
            
            // 5. 删除死节点
            int removedEdges = 0;
            for (SootMethod deadNode : deadNodes) {
                removedEdges += graph.removeMethod(deadNode);
            }
            
            totalRemovedNodes += deadNodes.size();
            totalRemovedEdges += removedEdges;
            
            logger.info("第{}轮：删除 {} 个节点, {} 条边", iteration, deadNodes.size(), removedEdges);
            
            // 安全限制：最多10轮
            if (iteration >= 10) {
                logger.warn("达到最大迭代次数限制（10轮），停止删除");
                break;
            }
        }
        
        logger.info("级联删除完成：共 {} 轮，删除 {} 个节点, {} 条边",
                iteration, totalRemovedNodes, totalRemovedEdges);
        
        return new DeadNodeResult(totalRemovedNodes, totalRemovedEdges, originalNodeCount);
    }
    
    /**
     * 分析死节点的包分布
     */
    private Map<String, Integer> analyzeDeadNodePackages(Set<SootMethod> deadNodes) {
        Map<String, Integer> packageCount = new HashMap<>();
        
        for (SootMethod method : deadNodes) {
            String className = method.getDeclaringClass().getName();
            String packageName = className.contains(".") 
                    ? className.substring(0, className.lastIndexOf('.'))
                    : "(default)";
            
            packageCount.put(packageName, packageCount.getOrDefault(packageName, 0) + 1);
        }
        
        return packageCount;
    }
    
    /**
     * 剪枝结果统计
     */
    public static class PruneResult {
        public final int originalEdges;
        public final int remainingEdges;
        public final int removedEdges;
        
        public PruneResult(int originalEdges, int remainingEdges, int removedEdges) {
            this.originalEdges = originalEdges;
            this.remainingEdges = remainingEdges;
            this.removedEdges = removedEdges;
        }
        
        public double getPruneRate() {
            return (removedEdges * 100.0) / originalEdges;
        }
    }
    
    /**
     * 死节点清理结果统计
     */
    public static class DeadNodeResult {
        public final int removedNodes;
        public final int removedEdges;
        public final int totalNodes;
        
        public DeadNodeResult(int removedNodes, int removedEdges, int totalNodes) {
            this.removedNodes = removedNodes;
            this.removedEdges = removedEdges;
            this.totalNodes = totalNodes;
        }
        
        public double getNodeRemovalRate() {
            return (removedNodes * 100.0) / totalNodes;
        }
    }
}
