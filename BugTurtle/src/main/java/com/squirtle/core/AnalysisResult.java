package com.squirtle.core;

import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.dataflow.DataFlowAnalysis;
import com.squirtle.core.fields.FieldAccessGraph;
import com.squirtle.core.fields.ControllableFieldGraph;
import com.squirtle.core.pruning.CallEdgeControllabilityAnalyzer.Controllability;
import soot.SootMethod;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

/**
 * 完整的分析结果
 * 
 * 整合所有分析组件的结果：
 * 1. 自定义调用图分析结果
 * 2. 字段访问图分析结果
 * 3. 数据流分析结果
 * 4. 污点分析结果
 * 
 * @author BugTurtle
 * @version 1.0
 */
public class AnalysisResult {
    
    private final LocalDateTime analysisTime;
    private String targetDescription;
    private boolean success = false;
    private String errorMessage;
    
    // 各组件分析结果
    private CallGraph callGraph;                        // 原始调用图
    private CallGraph prunedCallGraph;                 // 🆕 剪枝后的调用图
    private FieldAccessGraph fieldGraph;
    private ControllableFieldGraph controllableFieldGraph;
    private DataFlowAnalysis.DataFlowResult dataFlowResult;
    private Map<CallGraph.CallEdge, Controllability> edgeControllability;  // 🆕 边的可控性
    
    // Demand-Driven 分析结果
    private Set<SootMethod> sourceMethods;              // Source方法集合
    private Set<SootMethod> sinkMethods;                // Sink方法集合
    
    // 性能统计
    private long analysisStartTime;
    private long analysisEndTime;
    
    public AnalysisResult() {
        this.analysisTime = LocalDateTime.now();
        this.analysisStartTime = System.currentTimeMillis();
    }
    
    /**
     * 完成分析，记录结束时间
     */
    public void finish() {
        this.analysisEndTime = System.currentTimeMillis();
        this.success = (errorMessage == null);
    }
    
    /**
     * 获取分析耗时（毫秒）
     */
    public long getAnalysisDuration() {
        return analysisEndTime - analysisStartTime;
    }
    
    /**
     * 获取综合统计信息
     */
    public String getSummary() {
        if (!success) {
            return String.format("分析失败: %s", errorMessage);
        }
        
        StringBuilder summary = new StringBuilder();
        summary.append("自主分析结果摘要:\n");
        summary.append(String.format("  分析时间: %s\n", analysisTime));
        summary.append(String.format("  分析耗时: %d ms\n", getAnalysisDuration()));
        
        if (callGraph != null) {
            CallGraph.CallGraphStats cgStats = callGraph.getStats();
            summary.append(String.format("  调用图: %d 方法, %d 调用边\n", 
                                        cgStats.getMethodCount(), cgStats.getEdgeCount()));
        }
        
        if (fieldGraph != null) {
            FieldAccessGraph.Statistics faStats = fieldGraph.getStatistics();
            summary.append(String.format("  字段访问: %d 字段, %d 访问\n", 
                                        faStats.getFieldCount(), faStats.getTotalAccesses()));
        }
        
        if (controllableFieldGraph != null) {
            ControllableFieldGraph.Statistics cfStats = controllableFieldGraph.getStatistics();
            summary.append(String.format("  可控字段: %d 字段, %d 类\n", 
                                        cfStats.getFieldCount(), 
                                        cfStats.getClassCount()));
        }
        
        if (dataFlowResult != null) {
            DataFlowAnalysis.DataFlowStatistics dfStats = dataFlowResult.getStatistics();
            summary.append(String.format("  数据流: %d 定义, %d 使用, %d 链\n", 
                                        dfStats.getTotalDefinitions(), 
                                        dfStats.getTotalUses(), 
                                        dfStats.getTotalDefUseChains()));
        }
        
        
        return summary.toString();
    }
    
    /**
     * 打印详细报告
     */
    public void printDetailedReport() {
        System.out.println("========================================");
        System.out.println("        自主程序分析详细报告");
        System.out.println("========================================");
        System.out.println(getSummary());
        
        if (callGraph != null) {
            System.out.println("\n--- 调用图分析 ---");
            CallGraph.CallGraphStats cgStats = callGraph.getStats();
            System.out.println("调用类型分布: " + cgStats.getEdgeCountByType());
        }
        
        if (fieldGraph != null) {
            System.out.println("\n--- 字段访问分析 ---");
            FieldAccessGraph.Statistics faStats = fieldGraph.getStatistics();
            System.out.println("访问类型分布: " + faStats.getAccessCountByType());
        }
        
        if (dataFlowResult != null) {
            System.out.println("\n--- 数据流分析 ---");
            DataFlowAnalysis.DataFlowStatistics dfStats = dataFlowResult.getStatistics();
            System.out.println("分析了 " + dfStats.getMethodCount() + " 个方法");
        }
        

        
        System.out.println("========================================");
    }
    
    // Getters and Setters
    
    public LocalDateTime getAnalysisTime() { return analysisTime; }
    
    public String getTargetDescription() { return targetDescription; }
    public void setTargetDescription(String targetDescription) { this.targetDescription = targetDescription; }
    
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    
    public String getErrorMessage() { return errorMessage; }
    public void setError(String errorMessage) { 
        this.errorMessage = errorMessage; 
        this.success = false;
    }
    
    public CallGraph getCallGraph() { return callGraph; }
    public void setCallGraph(CallGraph callGraph) { this.callGraph = callGraph; }
    
    public CallGraph getPrunedCallGraph() { return prunedCallGraph; }
    public void setPrunedCallGraph(CallGraph prunedCallGraph) { this.prunedCallGraph = prunedCallGraph; }
    
    public FieldAccessGraph getFieldGraph() { return fieldGraph; }
    public void setFieldGraph(FieldAccessGraph fieldGraph) { this.fieldGraph = fieldGraph; }
    public void setFieldAccessGraph(FieldAccessGraph fieldGraph) { this.fieldGraph = fieldGraph; }
    
    public ControllableFieldGraph getControllableFieldGraph() { return controllableFieldGraph; }
    public void setControllableFieldGraph(ControllableFieldGraph controllableFieldGraph) { 
        this.controllableFieldGraph = controllableFieldGraph; 
    }
    
    public DataFlowAnalysis.DataFlowResult getDataFlowResult() { return dataFlowResult; }
    public void setDataFlowResult(DataFlowAnalysis.DataFlowResult dataFlowResult) {
        this.dataFlowResult = dataFlowResult; 
    }
    
    public Map<CallGraph.CallEdge, Controllability> getEdgeControllability() { return edgeControllability; }
    public void setEdgeControllability(Map<CallGraph.CallEdge, Controllability> edgeControllability) {
        this.edgeControllability = edgeControllability;
    }
    
    public Set<SootMethod> getSourceMethods() { return sourceMethods; }
    public void setSourceMethods(Set<SootMethod> sourceMethods) { this.sourceMethods = sourceMethods; }
    
    public Set<SootMethod> getSinkMethods() { return sinkMethods; }
    public void setSinkMethods(Set<SootMethod> sinkMethods) { this.sinkMethods = sinkMethods; }
} 