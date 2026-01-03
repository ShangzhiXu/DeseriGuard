package com.squirtle.core.taint.summary;

import soot.SootMethod;
import java.util.Collection;

/**
 * 过程间污点分析器（Inter-procedural Taint Analyzer）
 * 
 * 负责协调多个方法的污点分析，实现Worklist算法。
 * 
 * **Worklist算法流程**：
 * 1. 初始化：将所有方法加入worklist
 * 2. 迭代：不断从worklist中取出方法进行分析
 * 3. 传播：summary变化时，将相关方法加入worklist
 * 4. 终止：worklist为空或达到最大迭代次数
 * 
 * **收敛性保证**：
 * - 单调性：污点只能增加不能减少（τ(x) = τ(x) ∨ ...）
 * - 有限性：每个summary最多有O(参数数量)个状态位
 * - 不动点：summary不再变化时停止
 * 
 * @see docs/减少UNKNOWN边的方案.md
 * @author BugTurtle
 * @version 2.0 - Summary-based Taint Analysis
 */
public class InterProceduralTaintAnalyzer {
    
    /** 最大迭代次数（防止无限循环） */
    private static final int MAX_ITERATIONS = 100000;
    
    /** 进度报告间隔（每处理N个方法输出一次进度） */
    private static final int PROGRESS_INTERVAL = 1000;
    
    /** 过程内分析器 */
    private final IntraProceduralTaintAnalyzer intraAnalyzer;
    
    /**
     * 构造函数
     */
    public InterProceduralTaintAnalyzer() {
        this.intraAnalyzer = new IntraProceduralTaintAnalyzer();
    }
    
    /**
     * 分析所有方法的污点传播（主入口）
     * 
     * @param methods 待分析方法集合
     * @param globalState 全局污点状态
     */
    public void analyze(Collection<SootMethod> methods, GlobalTaintState globalState) {
        System.out.println("\n========== 开始Full Taint Propagation分析 ==========");
        System.out.println("方法总数: " + methods.size());
        
        // 1. 初始化worklist：添加所有方法
        initializeWorklist(methods, globalState);
        
        // 2. Worklist迭代
        runWorklistAlgorithm(globalState);
        
        // 3. 输出统计信息
        printStatistics(globalState);
        
        System.out.println("========== Full Taint Propagation分析完成 ==========\n");
    }
    
    /**
     * 初始化worklist
     * 
     * 策略：添加所有方法（保证完整性）
     * 
     * @param methods 方法集合
     * @param globalState 全局状态
     */
    private void initializeWorklist(Collection<SootMethod> methods, GlobalTaintState globalState) {
        System.out.println("[初始化] 添加所有方法到worklist...");
        
        int addedCount = 0;
        for (SootMethod method : methods) {
            // 跳过无方法体的方法（phantom、native、abstract）
            if (!method.hasActiveBody()) {
                continue;
            }
            
            globalState.addToWorklist(method);
            addedCount++;
        }
        
        System.out.println("[初始化] Worklist大小: " + addedCount);
    }
    
    /**
     * 运行Worklist算法
     * 
     * @param globalState 全局状态
     */
    private void runWorklistAlgorithm(GlobalTaintState globalState) {
        System.out.println("[Worklist] 开始迭代...");
        
        int processedCount = 0;
        int iteration = 0;
        long startTime = System.currentTimeMillis();
        
        while (!globalState.isWorklistEmpty() && iteration < MAX_ITERATIONS) {
            // 从worklist中取出方法
            SootMethod method = globalState.pollFromWorklist();
            
            // 分析方法（调用过程内分析器）
            try {
                intraAnalyzer.analyzeMethod(method, globalState);
                processedCount++;
            } catch (Exception e) {
                System.err.println("[ERROR] 分析方法失败: " + method.getSignature());
                e.printStackTrace();
            }
            
            // 定期输出进度
            if (processedCount % PROGRESS_INTERVAL == 0) {
                printProgress(processedCount, globalState, startTime);
            }
            
            iteration++;
        }
        
        // 最终进度
        long totalTime = System.currentTimeMillis() - startTime;
        System.out.println(String.format(
            "[Worklist] 完成！总迭代次数: %d，处理方法数: %d，耗时: %.2f 秒",
            iteration, processedCount, totalTime / 1000.0
        ));
        
        // 检查是否超过最大迭代次数
        if (iteration >= MAX_ITERATIONS) {
            System.err.println("[WARNING] 达到最大迭代次数限制！可能未收敛。");
        }
    }
    
    /**
     * 输出进度信息
     * 
     * @param processedCount 已处理方法数
     * @param globalState 全局状态
     * @param startTime 开始时间
     */
    private void printProgress(int processedCount, GlobalTaintState globalState, long startTime) {
        long elapsed = System.currentTimeMillis() - startTime;
        double speed = processedCount / (elapsed / 1000.0);
        
        System.out.println(String.format(
            "[进度] 已处理: %d 方法，worklist剩余: %d，速度: %.1f 方法/秒，" +
            "污点this: %d，污点return: %d，污点字段: %d",
            processedCount,
            globalState.getWorklistSize(),
            speed,
            globalState.getTaintedThisMethodCount(),
            globalState.getTaintedReturnMethodCount(),
            globalState.getTaintedFieldCount()
        ));
    }
    
    /**
     * 输出最终统计信息
     * 
     * @param globalState 全局状态
     */
    private void printStatistics(GlobalTaintState globalState) {
        System.out.println("\n========== 污点分析统计 ==========");
        System.out.println(globalState.toString());
        System.out.println("================================\n");
    }
}






