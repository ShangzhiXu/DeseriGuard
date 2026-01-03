package com.squirtle.test;

import com.squirtle.config.SootJarAnalysisConfig;
import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.taint.guided.TaintGuidedCallGraphBuilder;
import org.junit.AfterClass;
import org.junit.Test;
import soot.G;
import soot.SootClass;

import java.util.*;

/**
 * 基准测试：分析调用图构建时间
 * * 修改点：
 * 1. 移除了 Gadget 搜索过程，专注于测试构建性能。
 * 2. 汇总表改为展示 [构建耗时] vs [图节点/边数]。
 */
public class BenchmarkCallGraphBuildTime {
    
    // --- 仅存储构建时间和图规模 ---
    private static class BenchmarkResult {
        String name;
        long buildTimeMs;
        int nodes;
        int edges;

        public BenchmarkResult(String name, long buildTimeMs, int nodes, int edges) {
            this.name = name;
            this.buildTimeMs = buildTimeMs;
            this.nodes = nodes;
            this.edges = edges;
        }
    }

    // 静态列表，收集所有测试方法的运行结果
    private static final List<BenchmarkResult> allResults = new ArrayList<>();

    /**
     * 执行测试：仅构建图并计时
     */
    private void runBenchmark(String testName, String libDir) {
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║  基准测试: " + testName + " (仅构建调用图)");
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");
        
        // 1. 初始化Soot
        // >>>>> 计时开始 <<<<<
        long startTime = System.currentTimeMillis();
        G.reset();
        System.out.println("【步骤1】初始化Soot...");
        SootJarAnalysisConfig.initializeSootForLibraryAnalysis(libDir);
        
        // 2. 构建调用图（带计时）
        System.out.println("\n【步骤2】构建污点驱动的调用图...");
        Set<SootClass> targetClasses = new HashSet<>(SootJarAnalysisConfig.getAllLoadedClasses());
        
        TaintGuidedCallGraphBuilder builder = new TaintGuidedCallGraphBuilder();
        

        
        CallGraph callGraph = builder.buildTaintGuidedCallGraph(targetClasses);
        
        long endTime = System.currentTimeMillis();
        long durationMs = endTime - startTime;
        // >>>>> 计时结束 <<<<<
        
        int nodeCount = callGraph.getAllMethods().size();
        int edgeCount = callGraph.getEdgeCount();

        System.out.println("-----------------------------------------------------");
        System.out.println("★ 构建完成！");
        System.out.println("★ 耗时: " + durationMs + " ms");
        System.out.println("★ 规模: " + nodeCount + " 节点, " + edgeCount + " 边");
        System.out.println("-----------------------------------------------------");
        
        // 收集结果
        synchronized (allResults) {
            allResults.add(new BenchmarkResult(
                testName, 
                durationMs, 
                nodeCount,
                edgeCount
            ));
        }
    }

    // --- 所有测试结束后的汇总输出 ---
    @AfterClass
    public static void printGlobalSummary() {
        System.out.println("\n\n");
        System.out.println("################################################################################");
        System.out.println("#                            调用图构建效率汇总                                #");
        System.out.println("################################################################################");
        
        // 打印表头：Library | Time | Nodes | Edges
        String format = "| %-15s | %-12s | %-12s | %-12s |%n";
        System.out.format("+-----------------+--------------+--------------+--------------+%n");
        System.out.format(format, "Library", "BuildTime(ms)", "Nodes", "Edges");
        System.out.format("+-----------------+--------------+--------------+--------------+%n");
        
        long totalBuildTime = 0;
        long totalNodes = 0;
        long totalEdges = 0;

        // 打印每行数据
        for (BenchmarkResult r : allResults) {
            System.out.format(format, 
                r.name, 
                r.buildTimeMs, 
                r.nodes, 
                r.edges
            );
            totalBuildTime += r.buildTimeMs;
            totalNodes += r.nodes;
            totalEdges += r.edges;
        }
        
        System.out.format("+-----------------+--------------+--------------+--------------+%n");
        System.out.format(format, 
            "TOTAL", 
            totalBuildTime, 
            totalNodes, 
            totalEdges
        );
        System.out.format("+-----------------+--------------+--------------+--------------+%n");
    }
    
    // ================== 测试用例 ==================
    // 注意：去掉了 outputPath 参数，因为不再输出 gadget 链文件

    @Test
    public void benchmarkWicket() {
        runBenchmark("Wicket", "libs/target/Wicket/");
    }

    @Test
    public void benchmarkCC3() {
        runBenchmark("CC3", "libs/target/CC3/");
    }

    @Test
    public void benchmarkFileUpload() {
        runBenchmark("FileUpload", "libs/target/FileUpload/");
    }

    @Test
    public void benchmarkWildFly() {
        runBenchmark("WildFly", "libs/target/WildFly/");
    }

    @Test
    public void benchmarkC3P0() {
        runBenchmark("C3P0", "libs/target/C3P0/");
    }

    @Test
    public void benchmarkClojure() {
        runBenchmark("Clojure", "libs/target/Clojure/");
    }
    
    @Test
    public void benchmarkAspectJweaver() {
        runBenchmark("AspectJweaver", "libs/target/AspectJweaver/");
    }
    
    @Test
    public void benchmarkBeanShell() {
        runBenchmark("BeanShell", "libs/target/BeanShell/");
    }
    
    @Test
    public void benchmarkCB() {
        runBenchmark("CB", "libs/target/CB/");
    }
    
    @Test
    public void benchmarkClick() {
        runBenchmark("Click", "libs/target/Click/");
    }
    
    @Test
    public void benchmarkJBoss() {
        runBenchmark("JBoss", "libs/target/JBoss/");
    }
    
    @Test
    public void benchmarkJavassistWeld() {
        runBenchmark("JavassistWeld", "libs/target/JavassistWeld/");
    }
    
    @Test
    public void benchmarkMozillaRhino() {
        runBenchmark("MozillaRhino", "libs/target/MozillaRhino/");
    }
    
    @Test
    public void benchmarkMyFace() {
        runBenchmark("MyFace", "libs/target/MyFace/");
    }
    
    @Test
    public void benchmarkRome() {
        runBenchmark("Rome", "libs/target/Rome/");
    }
    
    @Test
    public void benchmarkSnakeYaml() {
        runBenchmark("SnakeYaml", "libs/target/SnakeYaml/");
    }
    
    @Test
    public void benchmarkVaadin() {
        runBenchmark("Vaadin", "libs/target/Vaadin/");
    }
}