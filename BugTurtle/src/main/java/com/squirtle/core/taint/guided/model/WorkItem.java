package com.squirtle.core.taint.guided.model;

import soot.SootMethod;

/**
 * Worklist元素
 * 
 * 表示待分析的方法及其入口污点状态
 */
public class WorkItem implements Comparable<WorkItem> {
    private final SootMethod method;
    private final MethodLevelTaint entryTaint;
    private final int depth;
    
    public WorkItem(SootMethod method, MethodLevelTaint entryTaint, int depth) {
        this.method = method;
        this.entryTaint = entryTaint;
        this.depth = depth;
    }
    
    @Override
    public int compareTo(WorkItem other) {
        // 深度优先：深度小的优先（越早调用的越先处理）
        return Integer.compare(this.depth, other.depth);
    }
    
    // Getters
    public SootMethod getMethod() {
        return method;
    }
    
    public MethodLevelTaint getEntryTaint() {
        return entryTaint;
    }
    
    public int getDepth() {
        return depth;
    }
    
    @Override
    public String toString() {
        return String.format("WorkItem{method=%s, depth=%d, taint=%s}",
                method.getSignature(), depth, entryTaint);
    }
}









