package com.squirtle.core.taint.guided.model;

import soot.Type;
import java.util.*;

/**
 * 方法污点摘要（增强版：支持值集分析）
 * 
 * 缓存方法的分析结果，支持上下文敏感：
 * 不同的entryTaint对应不同的分析结果
 * 
 * VSA支持：除了污点信息，还保存返回值的类型集合
 */
public class MethodTaintSummary {
    // 上下文敏感：不同的entryTaint对应不同的结果
    private final Map<MethodLevelTaint, SummaryResult> contextResults;
    
    public MethodTaintSummary() {
        this.contextResults = new HashMap<>();
    }
    
    public void addResult(MethodLevelTaint entryTaint, SummaryResult result) {
        contextResults.put(entryTaint, result);
    }
    
    public SummaryResult getResult(MethodLevelTaint entryTaint) {
        return contextResults.get(entryTaint);
    }
    
    public Map<MethodLevelTaint, SummaryResult> getContextResults() {
        return contextResults;
    }
    
    /**
     * 检查是否有任何上下文下返回值被污染
     */
    public boolean isAnyReturnTainted() {
        return contextResults.values().stream()
                .anyMatch(sr -> sr.returnTainted);
    }
    
    /**
     * Summary结果（增强版：支持VSA）
     */
    public static class SummaryResult {
        public final boolean returnTainted;
        public final MethodLevelTaint exitTaint;  // 预留（当前未使用）
        public final Set<Type> returnValueSet;  // 🆕 返回值的可能类型集合
        
        public SummaryResult(boolean returnTainted, MethodLevelTaint exitTaint) {
            this.returnTainted = returnTainted;
            this.exitTaint = exitTaint;
            this.returnValueSet = new HashSet<>();
        }
        
        /**
         * 🆕 带值集的构造函数
         */
        public SummaryResult(boolean returnTainted, MethodLevelTaint exitTaint, Set<Type> returnValueSet) {
            this.returnTainted = returnTainted;
            this.exitTaint = exitTaint;
            this.returnValueSet = returnValueSet != null ? new HashSet<>(returnValueSet) : new HashSet<>();
        }
        
        /**
         * 🆕 获取返回值类型集合
         */
        public Set<Type> getReturnValueSet() {
            return returnValueSet != null ? new HashSet<>(returnValueSet) : new HashSet<>();
        }
    }
}









