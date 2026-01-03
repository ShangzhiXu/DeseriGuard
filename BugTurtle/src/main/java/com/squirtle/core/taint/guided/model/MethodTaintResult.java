package com.squirtle.core.taint.guided.model;

import soot.Type;
import java.util.*;

/**
 * 方法污点分析结果（支持VSA）
 * 
 * analyzeMethod的返回值，包含：
 * - callSites：方法内的所有调用点
 * - returnTainted：返回值是否被污染
 * - exitState：方法出口时的内部状态
 * - 🆕 returnValueSet：返回值的可能类型集合
 */
public class MethodTaintResult {
    private final List<CallSite> callSites;
    private final boolean returnTainted;
    private final MethodInternalState exitState;
    private final Set<Type> returnValueSet;  // 🆕 返回值类型集合
    
    public MethodTaintResult(List<CallSite> callSites, boolean returnTainted, 
                           MethodInternalState exitState, Set<Type> returnValueSet) {
        this.callSites = new ArrayList<>(callSites);
        this.returnTainted = returnTainted;
        this.exitState = exitState;
        this.returnValueSet = returnValueSet != null ? new HashSet<>(returnValueSet) : new HashSet<>();
    }
    
    // Getters
    public List<CallSite> getCallSites() {
        return callSites;
    }
    
    public boolean isReturnTainted() {
        return returnTainted;
    }
    
    public MethodInternalState getExitState() {
        return exitState;
    }
    
    /**
     * 🆕 获取返回值的类型集合
     */
    public Set<Type> getReturnValueSet() {
        return returnValueSet != null ? new HashSet<>(returnValueSet) : new HashSet<>();
    }
    
    @Override
    public String toString() {
        return String.format("MethodTaintResult{callSites=%d, returnTainted=%s, returnTypes=%d}",
                callSites.size(), returnTainted, returnValueSet != null ? returnValueSet.size() : 0);
    }
}









