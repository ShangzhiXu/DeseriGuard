package com.squirtle.core.taint.summary;

import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import com.squirtle.core.fields.ControllableFieldGraph;
import com.squirtle.core.pruning.PrunedCallGraph;

import java.util.Collection;

/**
 * Full Taint Propagation分析器（主分析引擎）
 * 
 * 实现Flash的完整污点传播算法，包括：
 * - Field-sensitive + Parameter-sensitive 污点分析
 * - Summary-based 过程间分析
 * - Worklist 迭代算法
 * - 15条污点传播规则
 * 
 * **使用方式**：
 * ```java
 * FullTaintPropagationAnalyzer analyzer = new FullTaintPropagationAnalyzer();
 * GlobalTaintState result = analyzer.analyze(methods, callGraph, ...);
 * 
 * // 查询污点信息
 * MethodTaintSummary summary = result.getSummary(method);
 * boolean tainted = summary.isParameterTainted(0);
 * ```
 * 
 * **分析流程**：
 * 1. 初始化GlobalTaintState
 * 2. 运行InterProceduralTaintAnalyzer（Worklist算法）
 * 3. 返回分析结果
 * 
 * @see docs/减少UNKNOWN边的方案.md
 * @author BugTurtle
 * @version 2.0 - Summary-based Taint Analysis
 */
public class FullTaintPropagationAnalyzer {
    
    /**
     * 构造函数
     */
    public FullTaintPropagationAnalyzer() {
        // 简单构造函数，无需特殊初始化
    }
    
    /**
     * 分析方法集合的完整污点传播
     * 
     * @param methods 待分析方法集合
     * @param callGraph 调用图
     * @param prunedCallGraph 剪枝后的调用图
     * @param controllableFieldGraph 可控字段图
     * @return 全局污点状态（包含所有方法的summary）
     */
    public GlobalTaintState analyze(Collection<SootMethod> methods,
                                   CallGraph callGraph,
                                   PrunedCallGraph prunedCallGraph,
                                   ControllableFieldGraph controllableFieldGraph) {
        
        System.out.println("\n╔════════════════════════════════════════════════════════════╗");
        System.out.println("║       Full Taint Propagation分析器 v2.0                  ║");
        System.out.println("║       Based on Flash's Summary-based Taint Analysis      ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");
        
        // 1. 初始化全局状态
        System.out.println("[初始化] 创建GlobalTaintState...");
        GlobalTaintState globalState = new GlobalTaintState(
            callGraph,
            prunedCallGraph,
            controllableFieldGraph
        );
        
        // 2. 创建过程间分析器
        System.out.println("[初始化] 创建InterProceduralTaintAnalyzer...");
        InterProceduralTaintAnalyzer interAnalyzer = new InterProceduralTaintAnalyzer();
        
        // 3. 运行分析
        long startTime = System.currentTimeMillis();
        interAnalyzer.analyze(methods, globalState);
        long totalTime = System.currentTimeMillis() - startTime;
        
        // 4. 输出最终统计
        printFinalStatistics(globalState, totalTime);
        
        // 5. 返回结果
        return globalState;
    }
    
    /**
     * 输出最终统计信息
     * 
     * @param globalState 全局状态
     * @param totalTime 总耗时（毫秒）
     */
    private void printFinalStatistics(GlobalTaintState globalState, long totalTime) {
        System.out.println("\n╔════════════════════════════════════════════════════════════╗");
        System.out.println("║                  分析完成 - 最终统计                      ║");
        System.out.println("╠════════════════════════════════════════════════════════════╣");
        
        int analyzedMethods = globalState.getAnalyzedMethodCount();
        int taintedFields = globalState.getTaintedFieldCount();
        int taintedThisMethods = globalState.getTaintedThisMethodCount();
        int taintedReturnMethods = globalState.getTaintedReturnMethodCount();
        
        System.out.println(String.format("║ 总耗时:          %10.2f 秒                         ║", 
            totalTime / 1000.0));
        System.out.println(String.format("║ 分析方法数:      %10d                              ║", 
            analyzedMethods));
        System.out.println(String.format("║ 污点this方法:    %10d (%.1f%%)                     ║", 
            taintedThisMethods, 
            analyzedMethods > 0 ? 100.0 * taintedThisMethods / analyzedMethods : 0));
        System.out.println(String.format("║ 污点return方法:  %10d (%.1f%%)                     ║", 
            taintedReturnMethods,
            analyzedMethods > 0 ? 100.0 * taintedReturnMethods / analyzedMethods : 0));
        System.out.println(String.format("║ 污点字段数:      %10d                              ║", 
            taintedFields));
        
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");
    }
    
    /**
     * 便捷方法：查询方法的污点摘要
     * 
     * @param globalState 全局状态
     * @param method 方法
     * @return 污点摘要，不存在则返回null
     */
    public static MethodTaintSummary getSummary(GlobalTaintState globalState, SootMethod method) {
        return globalState.getSummary(method);
    }
    
    /**
     * 便捷方法：检查方法参数是否污点
     * 
     * @param globalState 全局状态
     * @param method 方法
     * @param paramIndex 参数索引
     * @return 是否污点
     */
    public static boolean isParameterTainted(GlobalTaintState globalState, 
                                            SootMethod method, 
                                            int paramIndex) {
        MethodTaintSummary summary = globalState.getSummary(method);
        return summary != null && summary.isParameterTainted(paramIndex);
    }
    
    /**
     * 便捷方法：检查方法this是否污点
     * 
     * @param globalState 全局状态
     * @param method 方法
     * @return 是否污点
     */
    public static boolean isThisTainted(GlobalTaintState globalState, SootMethod method) {
        MethodTaintSummary summary = globalState.getSummary(method);
        return summary != null && summary.isThisTainted();
    }
    
    /**
     * 便捷方法：检查方法返回值是否污点
     * 
     * @param globalState 全局状态
     * @param method 方法
     * @return 是否污点
     */
    public static boolean isReturnTainted(GlobalTaintState globalState, SootMethod method) {
        MethodTaintSummary summary = globalState.getSummary(method);
        return summary != null && summary.isReturnTainted();
    }
}






