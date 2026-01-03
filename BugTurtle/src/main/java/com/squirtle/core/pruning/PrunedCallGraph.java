package com.squirtle.core.pruning;

import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.callgraph.CallGraph.CallEdge;
import com.squirtle.core.callgraph.CallGraph.CallPath;
import com.squirtle.core.pruning.CallEdgeControllabilityAnalyzer.Controllability;
import soot.SootMethod;
import soot.Unit;
import java.util.*;
import java.util.logging.Logger;

/**
 * 剪枝后的调用图
 * 
 * 实现设计文档第五步和第六步：
 * - 基于可控性分析结果剪枝调用图
 * - 只保留可控的边
 * - 保证Soundness（Sound模式）
 * 
 * @author BugTurtle
 * @version 1.0 - 字段敏感污点分析
 */
public class PrunedCallGraph {
    
    private static final Logger logger = Logger.getLogger(PrunedCallGraph.class.getName());
    
    private final CallGraph originalCallGraph;
    private final Map<CallEdge, Controllability> edgeControllability;
    private final boolean soundMode;
    
    private final Set<CallEdge> prunedEdges;  // 保留的边
    private final Set<CallEdge> removedEdges; // 移除的边
    
    /**
     * 构造剪枝后的调用图
     * 
     * @param originalCallGraph 原始调用图
     * @param edgeControllability 边的可控性映射
     * @param soundMode 是否为Sound模式（UNKNOWN视为CONTROLLABLE）
     */
    public PrunedCallGraph(CallGraph originalCallGraph, 
                          Map<CallEdge, Controllability> edgeControllability,
                          boolean soundMode) {
        this.originalCallGraph = originalCallGraph;
        this.edgeControllability = edgeControllability;
        this.soundMode = soundMode;
        this.prunedEdges = new HashSet<>();
        this.removedEdges = new HashSet<>();
        
        performPruning();
    }
    
    /**
     * 执行剪枝
     */
    private void performPruning() {
        logger.info("✂️ 开始剪枝调用图（Sound模式: " + soundMode + "）...");
        
        Set<CallEdge> allEdges = originalCallGraph.getAllEdges();
        
        for (CallEdge edge : allEdges) {
            Controllability c = edgeControllability.getOrDefault(edge, Controllability.UNKNOWN);
            
            boolean keepEdge = shouldKeepEdge(c);
            
            if (keepEdge) {
                prunedEdges.add(edge);
            } else {
                removedEdges.add(edge);
            }
        }
        
        logger.info("✅ 剪枝完成:");
        logger.info("  保留边数: " + prunedEdges.size());
        logger.info("  移除边数: " + removedEdges.size());
        logger.info("  剪枝率: " + String.format("%.2f%%", 
                   (removedEdges.size() * 100.0 / allEdges.size())));
    }
    
    /**
     * 判断是否应该保留边
     */
    private boolean shouldKeepEdge(Controllability c) {
        if (soundMode) {
            // Sound模式：只移除明确UNCONTROLLABLE的边
            return c != Controllability.UNCONTROLLABLE;
        } else {
            // 精确模式：只保留明确CONTROLLABLE的边
            return c == Controllability.CONTROLLABLE;
        }
    }
    
    /**
     * 获取剪枝后的所有边
     */
    public Set<CallEdge> getPrunedEdges() {
        return Collections.unmodifiableSet(prunedEdges);
    }
    
    /**
     * 获取被移除的边
     */
    public Set<CallEdge> getRemovedEdges() {
        return Collections.unmodifiableSet(removedEdges);
    }
    
    /**
     * 获取方法的出边（只包含可控的边）
     */
    public Set<CallEdge> getOutgoingEdges(SootMethod method) {
        Set<CallEdge> outgoing = new HashSet<>();
        
        for (CallEdge edge : originalCallGraph.getOutgoingEdges(method)) {
            if (prunedEdges.contains(edge)) {
                outgoing.add(edge);
            }
        }
        
        return outgoing;
    }
    
    /**
     * 获取方法的入边（只包含可控的边）
     */
    public Set<CallEdge> getIncomingEdges(SootMethod method) {
        Set<CallEdge> incoming = new HashSet<>();
        
        for (CallEdge edge : originalCallGraph.getIncomingEdges(method)) {
            if (prunedEdges.contains(edge)) {
                incoming.add(edge);
            }
        }
        
        return incoming;
    }
    
    /**
     * 获取调用点的边（只包含可控的边）
     */
    public Set<CallEdge> getCallSiteEdges(Unit callSite) {
        Set<CallEdge> edges = new HashSet<>();
        
        for (CallEdge edge : originalCallGraph.getCallSiteEdges(callSite)) {
            if (prunedEdges.contains(edge)) {
                edges.add(edge);
            }
        }
        
        return edges;
    }
    
    /**
     * 获取直接调用的方法（只包含可控的边）
     */
    public Set<SootMethod> getDirectCallees(SootMethod caller) {
        Set<SootMethod> callees = new HashSet<>();
        
        for (CallEdge edge : getOutgoingEdges(caller)) {
            callees.add(edge.getCallee());
        }
        
        return callees;
    }
    
    /**
     * 获取可达的所有方法（只通过可控的边）
     */
    public Set<SootMethod> getReachableMethods(SootMethod startMethod) {
        Set<SootMethod> reachable = new HashSet<>();
        Queue<SootMethod> worklist = new LinkedList<>();
        
        worklist.offer(startMethod);
        reachable.add(startMethod);
        
        while (!worklist.isEmpty()) {
            SootMethod current = worklist.poll();
            
            for (SootMethod callee : getDirectCallees(current)) {
                if (reachable.add(callee)) {
                    worklist.offer(callee);
                }
            }
        }
        
        return reachable;
    }
    
    /**
     * 查找调用路径（只通过可控的边）
     */
    public List<CallPath> findCallPaths(SootMethod from, SootMethod to, int maxDepth) {
        List<CallPath> paths = new ArrayList<>();
        
        findCallPathsRecursive(from, to, new ArrayList<>(), new HashSet<>(), paths, maxDepth);
        
        return paths;
    }
    
    private void findCallPathsRecursive(SootMethod current, SootMethod target,
                                       List<CallEdge> currentPath, Set<SootMethod> visited,
                                       List<CallPath> allPaths, int remainingDepth) {
        if (remainingDepth <= 0) return;
        
        if (current.equals(target)) {
            allPaths.add(new CallPath(new ArrayList<>(currentPath)));
            return;
        }
        
        if (visited.contains(current)) return;
        visited.add(current);
        
        for (CallEdge edge : getOutgoingEdges(current)) {
            currentPath.add(edge);
            findCallPathsRecursive(edge.getCallee(), target, currentPath, visited, allPaths, remainingDepth - 1);
            currentPath.remove(currentPath.size() - 1);
        }
        
        visited.remove(current);
    }
    
    /**
     * 创建只包含剪枝后边的新CallGraph
     */
    public CallGraph toCallGraph() {
        CallGraph newGraph = new CallGraph();
        
        for (CallEdge edge : prunedEdges) {
            newGraph.addCall(edge.getCaller(), edge.getCallee(), 
                           edge.getCallSite(), edge.getCallType());
        }
        
        return newGraph;
    }
    
    /**
     * 获取剪枝统计
     */
    public PruningStatistics getStatistics() {
        int originalCount = originalCallGraph.getEdgeCount();
        int prunedCount = prunedEdges.size();
        int removedCount = removedEdges.size();
        
        Map<CallGraph.CallType, Integer> removedByType = new HashMap<>();
        for (CallEdge edge : removedEdges) {
            CallGraph.CallType type = edge.getCallType();
            removedByType.put(type, removedByType.getOrDefault(type, 0) + 1);
        }
        
        Map<CallGraph.CallType, Integer> keptByType = new HashMap<>();
        for (CallEdge edge : prunedEdges) {
            CallGraph.CallType type = edge.getCallType();
            keptByType.put(type, keptByType.getOrDefault(type, 0) + 1);
        }
        
        return new PruningStatistics(originalCount, prunedCount, removedCount, 
                                     removedByType, keptByType);
    }
    
    /**
     * 剪枝统计信息
     */
    public static class PruningStatistics {
        private final int originalEdgeCount;
        private final int prunedEdgeCount;
        private final int removedEdgeCount;
        private final Map<CallGraph.CallType, Integer> removedEdgesByType;
        private final Map<CallGraph.CallType, Integer> keptEdgesByType;
        
        public PruningStatistics(int originalEdgeCount, int prunedEdgeCount, 
                                int removedEdgeCount,
                                Map<CallGraph.CallType, Integer> removedEdgesByType,
                                Map<CallGraph.CallType, Integer> keptEdgesByType) {
            this.originalEdgeCount = originalEdgeCount;
            this.prunedEdgeCount = prunedEdgeCount;
            this.removedEdgeCount = removedEdgeCount;
            this.removedEdgesByType = new HashMap<>(removedEdgesByType);
            this.keptEdgesByType = new HashMap<>(keptEdgesByType);
        }
        
        public int getOriginalEdgeCount() { return originalEdgeCount; }
        public int getPrunedEdgeCount() { return prunedEdgeCount; }
        public int getRemovedEdgeCount() { return removedEdgeCount; }
        
        public double getPruningRate() {
            if (originalEdgeCount == 0) return 0.0;
            return (removedEdgeCount * 100.0) / originalEdgeCount;
        }
        
        public Map<CallGraph.CallType, Integer> getRemovedEdgesByType() {
            return Collections.unmodifiableMap(removedEdgesByType);
        }
        
        public Map<CallGraph.CallType, Integer> getKeptEdgesByType() {
            return Collections.unmodifiableMap(keptEdgesByType);
        }
        
        @Override
        public String toString() {
            return String.format("PruningStats{original=%d, kept=%d, removed=%d, rate=%.2f%%}",
                               originalEdgeCount, prunedEdgeCount, removedEdgeCount, getPruningRate());
        }
    }
}
