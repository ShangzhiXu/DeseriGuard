package com.squirtle.test;

import com.squirtle.config.SootJarAnalysisConfig;
import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.pruning.CallEdgeControllabilityAnalyzer;
import com.squirtle.core.taint.guided.TaintGuidedCallGraphBuilder;
import com.squirtle.gadget.GadgetChainSearcherFlashStyleV2;
import com.squirtle.gadget.SourceSinkManager;
import org.junit.Test;
import soot.G;
import soot.SootClass;
import soot.SootMethod;

import java.util.*;

/**
 * 验证动态污点剪枝效果
 * 
 * 对比：
 * - 修复前：所有边视为可控，不剪枝 → 路径爆炸
 * - 修复后：动态检查路径污点，有效剪枝 → 结果接近Flash
 */
public class VerifyDynamicPruning {
    
    /**
     * 执行 Gadget 链搜索的通用方法
     */
    private void runGadgetSearch(String testName, String libDir, String outputPath) {
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║  测试 " + testName + " 动态污点剪枝");
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");
        
        // 1. 初始化Soot
        G.reset();
        System.out.println("【步骤1】初始化Soot...");
        SootJarAnalysisConfig.initializeSootForLibraryAnalysis(libDir);
        
        // 2. 构建调用图
        System.out.println("\n【步骤2】构建污点驱动的调用图（带可控性）...");
        Set<SootClass> targetClasses = new HashSet<>(SootJarAnalysisConfig.getAllLoadedClasses());
        
        // 统计类和方法数量
        int classCount = targetClasses.size();
        int methodCount = 0;
        for (SootClass sc : targetClasses) {
            methodCount += sc.getMethodCount();
        }
        
        TaintGuidedCallGraphBuilder builder = new TaintGuidedCallGraphBuilder();
        CallGraph callGraph = builder.buildTaintGuidedCallGraph(targetClasses);
        
        System.out.println("调用图构建完成:");
        System.out.println("  分析类数: " + classCount);
        System.out.println("  分析方法数: " + methodCount);
        System.out.println("  调用图节点数: " + callGraph.getAllMethods().size());
        System.out.println("  调用图边数: " + callGraph.getEdgeCount());
        System.out.println();
        
        // 3. 准备搜索器
        System.out.println("【步骤3】初始化搜索器...");
        Map<CallGraph.CallEdge, CallEdgeControllabilityAnalyzer.Controllability> edgeControllability =
            new HashMap<>();
        
        SourceSinkManager sourceSinkManager = new SourceSinkManager(true);
        System.out.println("  Sources: " + sourceSinkManager.getSourceMethods().size());
        System.out.println("  Sinks: " + sourceSinkManager.getSinkMethods().size());
        System.out.println();
        
        // 4. 执行搜索
        System.out.println("【步骤4】执行gadget链搜索...\n");
        
        GadgetChainSearcherFlashStyleV2 searcher = new GadgetChainSearcherFlashStyleV2(
            callGraph,
            sourceSinkManager,
            edgeControllability
        );
        
        // 传入统计信息
        searcher.search(outputPath, classCount, methodCount);
        
        // 5. 输出结果
        System.out.println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("  搜索结果");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        System.out.println(searcher.getStatistics());
        System.out.println("\n结果已输出到: " + outputPath);
        
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║  测试完成                                                     ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");
    }
    
    @Test
    public void testWicketWithDynamicPruning() {
        runGadgetSearch("Wicket", "libs/target/Wicket/", "gadget_chains_wicket_dynamic_pruning.txt");
    }

    @Test
    public void testCC3WithDynamicPruning() {
        runGadgetSearch("CC3", "libs/target/CC3/", "gadget_chains_cc3_dynamic_pruning.txt");
    }

    @Test
    public void testFileUploadWithDynamicPruning() {
        runGadgetSearch("FileUpload", "libs/target/FileUpload/", "gadget_chains_fileupload_dynamic_pruning.txt");
    }

    @Test
    public void testWildFlyWithDynamicPruning() {
        runGadgetSearch("WildFly", "libs/target/WildFly/", "gadget_chains_wildfly_dynamic_pruning.txt");
    }

    @Test
    public void testC3P0WithDynamicPruning() {
        runGadgetSearch("C3P0", "libs/target/C3P0/", "gadget_chains_c3p0_dynamic_pruning.txt");
    }

    @Test
    public void testClojureWithDynamicPruning() {
        runGadgetSearch("Clojure", "libs/target/Clojure/", "gadget_chains_clojure_dynamic_pruning.txt");
    }
    
    @Test
    public void testAspectJweaverWithDynamicPruning() {
        runGadgetSearch("AspectJweaver", "libs/target/AspectJweaver/", "gadget_chains_aspectjweaver_dynamic_pruning.txt");
    }
    
    @Test
    public void testBeanShellWithDynamicPruning() {
        runGadgetSearch("BeanShell", "libs/target/BeanShell/", "gadget_chains_beanshell_dynamic_pruning.txt");
    }
    
    @Test
    public void testCBWithDynamicPruning() {
        runGadgetSearch("CB", "libs/target/CB/", "gadget_chains_cb_dynamic_pruning.txt");
    }
    
//    @Test
//    public void testCC4WithDynamicPruning() {
//        runGadgetSearch("CC4", "libs/target/CC4/", "gadget_chains_cc4_dynamic_pruning.txt");
//    }
    
    @Test
    public void testClickWithDynamicPruning() {
        runGadgetSearch("Click", "libs/target/Click/", "gadget_chains_click_dynamic_pruning.txt");
    }
    
    @Test
    public void testJBossWithDynamicPruning() {
        runGadgetSearch("JBoss", "libs/target/JBoss/", "gadget_chains_jboss_dynamic_pruning.txt");
    }
    
    @Test
    public void testJavassistWeldWithDynamicPruning() {
        runGadgetSearch("JavassistWeld", "libs/target/JavassistWeld/", "gadget_chains_javassistweld_dynamic_pruning.txt");
    }
    
    @Test
    public void testMozillaRhinoWithDynamicPruning() {
        runGadgetSearch("MozillaRhino", "libs/target/MozillaRhino/", "gadget_chains_mozillarhino_dynamic_pruning.txt");
    }
    
    @Test
    public void testMyFaceWithDynamicPruning() {
        runGadgetSearch("MyFace", "libs/target/MyFace/", "gadget_chains_myface_dynamic_pruning.txt");
    }
    
    @Test
    public void testRomeWithDynamicPruning() {
        runGadgetSearch("Rome", "libs/target/Rome/", "gadget_chains_rome_dynamic_pruning.txt");
    }
    
    @Test
    public void testSnakeYamlWithDynamicPruning() {
        runGadgetSearch("SnakeYaml", "libs/target/SnakeYaml/", "gadget_chains_snakeyaml_dynamic_pruning.txt");
    }
    
    @Test
    public void testVaadinWithDynamicPruning() {
        runGadgetSearch("Vaadin", "libs/target/Vaadin/", "gadget_chains_vaadin_dynamic_pruning.txt");
    }
}
