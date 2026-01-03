package com.squirtle.core.taint.summary;

import soot.SootField;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import com.squirtle.core.fields.ControllableFieldGraph;
import com.squirtle.core.pruning.PrunedCallGraph;

import java.util.*;

/**
 * 全局污点状态（Global Taint State）
 * 
 * 整个污点分析的全局状态管理器，负责：
 * - 管理所有方法的污点摘要
 * - 管理全局字段污点状态
 * - 管理worklist队列
 * - 提供调用图查询接口
 * 
 * @see docs/减少UNKNOWN边的方案.md
 * @author BugTurtle
 * @version 2.0 - Summary-based Taint Analysis
 */
public class GlobalTaintState {
    
    /** 所有方法的污点摘要 */
    private final Map<SootMethod, MethodTaintSummary> summaries;
    
    /** 全局字段污点状态（流不敏感、对象不敏感） */
    private final Map<SootField, Boolean> globalFieldTaints;
    
    /** Worklist队列（待处理的方法） */
    private final Queue<SootMethod> worklist;
    
    /** Worklist集合（快速检查重复） */
    private final Set<SootMethod> worklistSet;
    
    /** 调用图 */
    private final CallGraph callGraph;
    
    /** 剪枝后的调用图 */
    private final PrunedCallGraph prunedCallGraph;
    
    /** 可控字段图 */
    private final ControllableFieldGraph controllableFieldGraph;
    
    /**
     * 构造函数
     * 
     * @param callGraph 调用图
     * @param prunedCallGraph 剪枝后的调用图
     * @param controllableFieldGraph 可控字段图
     */
    public GlobalTaintState(CallGraph callGraph, 
                           PrunedCallGraph prunedCallGraph,
                           ControllableFieldGraph controllableFieldGraph) {
        this.summaries = new HashMap<>();
        this.globalFieldTaints = new HashMap<>();
        this.worklist = new LinkedList<>();
        this.worklistSet = new HashSet<>();
        this.callGraph = callGraph;
        this.prunedCallGraph = prunedCallGraph;
        this.controllableFieldGraph = controllableFieldGraph;
    }
    
    // ========== 方法摘要管理 ==========
    
    /**
     * 获取或创建方法摘要
     * 
     * 🔥 关键修复：readObject方法的this和参数都是污点源
     * 
     * @param method 方法
     * @return 方法摘要
     */
    public MethodTaintSummary getOrCreateSummary(SootMethod method) {
        return summaries.computeIfAbsent(method, m -> {
            MethodTaintSummary summary = new MethodTaintSummary(m);
            
            // 🔥 readObject方法是污点源
            if (isSourceMethod(m)) {
                // 标记this为污点（要反序列化的对象）
                if (!m.isStatic()) {
                summary.setThisTainted(true);
                }
                
                // 🔥 标记所有参数为污点（ObjectInputStream等）
                for (int i = 0; i < m.getParameterCount(); i++) {
                    summary.setParameterTainted(i, true);
                }
            }
            
            return summary;
        });
    }
    
    /**
     * 检查方法是否为Source方法
     * 
     * @param method 方法
     * @return 是否为Source
     */
    private boolean isSourceMethod(SootMethod method) {
        String sig = method.getSignature();
        
        // readObject方法是污点源
        if (sig.contains(": void readObject(java.io.ObjectInputStream)")) {
            return true;
        }
        
        // TODO: 扩展其他Source方法（TiedMapEntry.getValue等）
        // 可以从FlashSourceSinkManager获取
        
        return false;
    }
    
    /**
     * 获取方法摘要（如果存在）
     * 
     * @param method 方法
     * @return 方法摘要，不存在则返回null
     */
    public MethodTaintSummary getSummary(SootMethod method) {
        return summaries.get(method);
    }
    
    /**
     * 检查方法摘要是否存在
     * 
     * @param method 方法
     * @return 是否存在
     */
    public boolean hasSummary(SootMethod method) {
        return summaries.containsKey(method);
    }
    
    // ========== 字段污点管理 ==========
    
    /**
     * 检查字段是否为污点
     * 
     * 注意：这是流不敏感、对象不敏感的简化版本
     * 
     * @param field 字段
     * @return 是否污点
     */
    public boolean isFieldTainted(SootField field) {
        return globalFieldTaints.getOrDefault(field, false);
    }
    
    /**
     * 标记字段为污点
     * 
     * @param field 字段
     * @return 是否发生变化
     */
    public boolean markFieldTainted(SootField field) {
        Boolean oldValue = globalFieldTaints.put(field, true);
        return oldValue == null || !oldValue;
    }
    
    /**
     * 检查字段是否可控（从可控字段图查询）
     * 
     * @param field 字段
     * @return 是否可控
     */
    public boolean isFieldControllable(SootField field) {
        return controllableFieldGraph.isControllableField(field);
    }
    
    // ========== Worklist管理 ==========
    
    /**
     * 添加方法到worklist
     * 
     * 自动去重，避免重复处理
     * 
     * @param method 方法
     */
    public void addToWorklist(SootMethod method) {
        if (worklistSet.add(method)) {
            worklist.offer(method);
        }
    }
    
    /**
     * 从worklist中取出方法
     * 
     * @return 方法，worklist为空时返回null
     */
    public SootMethod pollFromWorklist() {
        SootMethod method = worklist.poll();
        if (method != null) {
            worklistSet.remove(method);
        }
        return method;
    }
    
    /**
     * 检查worklist是否为空
     * 
     * @return 是否为空
     */
    public boolean isWorklistEmpty() {
        return worklist.isEmpty();
    }
    
    /**
     * 获取worklist大小
     * 
     * @return 大小
     */
    public int getWorklistSize() {
        return worklist.size();
    }
    
    // ========== 调用图查询 ==========
    
    /**
     * 获取方法的所有调用者（用于[Return-Side-Effect]规则）
     * 
     * 当callee的摘要变化时，需要将所有caller加入worklist
     * 
     * @param method 方法
     * @return 调用者集合
     */
    public Set<SootMethod> getCallers(SootMethod method) {
        Set<SootMethod> callers = new HashSet<>();
        
        // 如果没有调用图，返回空集合（保守处理）
        if (callGraph == null) {
            return callers;
        }
        
        // 从调用图查询（使用原始调用图，更全面）
        Iterator<Edge> edgeIter = callGraph.edgesInto(method);
        while (edgeIter.hasNext()) {
            Edge edge = edgeIter.next();
            callers.add(edge.src());
        }
        
        return callers;
    }
    
    /**
     * 获取方法的所有被调用者
     * 
     * @param method 方法
     * @return 被调用者集合
     */
    public Set<SootMethod> getCallees(SootMethod method) {
        Set<SootMethod> callees = new HashSet<>();
        
        Iterator<Edge> edgeIter = callGraph.edgesOutOf(method);
        while (edgeIter.hasNext()) {
            Edge edge = edgeIter.next();
            callees.add(edge.tgt());
        }
        
        return callees;
    }
    
    // ========== 统计信息 ==========
    
    /**
     * 获取已分析的方法数量
     * 
     * @return 方法数量
     */
    public int getAnalyzedMethodCount() {
        return summaries.size();
    }
    
    /**
     * 获取污点字段数量
     * 
     * @return 字段数量
     */
    public int getTaintedFieldCount() {
        int count = 0;
        for (Boolean tainted : globalFieldTaints.values()) {
            if (tainted) count++;
        }
        return count;
    }
    
    /**
     * 获取污点this的方法数量
     * 
     * @return 方法数量
     */
    public int getTaintedThisMethodCount() {
        int count = 0;
        for (MethodTaintSummary summary : summaries.values()) {
            if (summary.isThisTainted()) count++;
        }
        return count;
    }
    
    /**
     * 获取污点返回值的方法数量
     * 
     * @return 方法数量
     */
    public int getTaintedReturnMethodCount() {
        int count = 0;
        for (MethodTaintSummary summary : summaries.values()) {
            if (summary.isReturnTainted()) count++;
        }
        return count;
    }
    
    /**
     * 转换为可读字符串（用于调试）
     */
    @Override
    public String toString() {
        return String.format(
            "GlobalTaintState{methods=%d, taintedFields=%d, taintedThis=%d, taintedReturn=%d, worklist=%d}",
            getAnalyzedMethodCount(),
            getTaintedFieldCount(),
            getTaintedThisMethodCount(),
            getTaintedReturnMethodCount(),
            getWorklistSize()
        );
    }
}





