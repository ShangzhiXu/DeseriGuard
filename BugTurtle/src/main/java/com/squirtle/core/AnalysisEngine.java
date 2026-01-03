package com.squirtle.core;

import com.squirtle.core.builder.CallGraphBuilder;
import com.squirtle.core.dataflow.DataFlowAnalysis;

// 新的组件
import com.squirtle.core.resolver.CHAResolver;
import com.squirtle.core.resolver.TypeInferenceEngine;
import com.squirtle.core.processor.MethodBodyProcessor;
import com.squirtle.core.analyzer.FieldAccessAnalyzer;
import com.squirtle.core.analyzer.ControllableFieldAnalyzer;
import com.squirtle.core.proxy.ProxyInterfaceRegistry;

// 🆕 字段敏感污点分析组件
import com.squirtle.core.taint.FieldSensitiveTaintAnalysis;
import com.squirtle.core.pruning.CallEdgeControllabilityAnalyzer;
import com.squirtle.core.pruning.PrunedCallGraph;

import soot.*;

import java.util.*;
import java.util.logging.Logger;

/**
 * 自主分析引擎 - 模块化组件架构
 * 
 * 核心设计理念：
 * 1. 只使用Soot做字节码到Jimple IR的转换
 * 2. 所有分析算法完全自主实现
 * 3. 构建自己的调用图、字段图、数据流图
 * 4. 实现可插拔的分析组件架构
 * 5. 模块化设计，职责分离，便于维护和扩展
 * 
 * @author BugTurtle
 * @version 4.0 - 模块化重构版本
 */
public class AnalysisEngine {
    
    private static final Logger logger = Logger.getLogger(AnalysisEngine.class.getName());
    
    // 新的模块化组件
    private CHAResolver chaResolver;
    private final TypeInferenceEngine typeInference;
    private final MethodBodyProcessor methodBodyProcessor;
    private final FieldAccessAnalyzer fieldAccessAnalyzer;
    private final ControllableFieldAnalyzer controllableFieldAnalyzer;
    private CallGraphBuilder callGraphBuilder;
    
    // 🆕 动态代理分析组件
    private ProxyInterfaceRegistry proxyRegistry;
    
    // 🆕 字段敏感污点分析组件
    private final FieldSensitiveTaintAnalysis fieldSensitiveTaintAnalysis;
    private final CallEdgeControllabilityAnalyzer controllabilityAnalyzer;
    
    // 仍保留的数据流分析（暂时禁用但保留接口）
    private final DataFlowAnalysis dataFlowAnalysis;
    
    // 程序表示
    private Set<SootClass> analysisClasses;
    private Map<SootMethod, List<Unit>> methodBodies;
    
    // 反序列化检测缓存（保留在主类中）
    private final Set<SootClass> serializableClasses;
    private final Map<SootClass, SootMethod> readObjectMethods;

    
    public AnalysisEngine() {
        // 初始化数据结构
        this.analysisClasses = new HashSet<>();
        this.serializableClasses = new HashSet<>();
        this.readObjectMethods = new HashMap<>();
        
        // 初始化组件
        this.typeInference = new TypeInferenceEngine();
        this.methodBodyProcessor = new MethodBodyProcessor();
        this.fieldAccessAnalyzer = new FieldAccessAnalyzer();
        this.controllableFieldAnalyzer = new ControllableFieldAnalyzer();
        
        // 初始化字段敏感污点分析组件
        this.fieldSensitiveTaintAnalysis = new FieldSensitiveTaintAnalysis();
        this.controllabilityAnalyzer = new CallEdgeControllabilityAnalyzer();
        
        // 初始化暂时禁用的组件
        this.dataFlowAnalysis = new DataFlowAnalysis();
    }
    
    /**
     * 执行完整的自主分析流程 - 对外接口保持不变
     */
    public AnalysisResult performCompleteAnalysis(Collection<SootClass> targetClasses) {
        logger.info("开始执行完全自主的程序分析（模块化版本 + 动态代理）");
        
        AnalysisResult result = new AnalysisResult();
        
        try {
            // 🆕 阶段 0.5: Proxy 接口注册表初始化
            initializeProxyRegistry(targetClasses);
            
            // 第一阶段：收集和预处理所有方法体
            collectAndPreprocessMethods(targetClasses);
            
            // 第二阶段：构建自定义调用图（现在包含 Proxy 桥接）
            buildCustomCallGraph();
            
            // 第三阶段：构建字段访问图
            buildFieldAccessGraph();
            
            // 第四阶段：构建可控字段图
            buildControllableFieldGraph();
            
            // 🆕 第五阶段：执行字段敏感污点分析
            performFieldSensitiveTaintAnalysis();
            
            // 🆕 第六阶段：执行调用边可控性分析
            performControllabilityAnalysis();
            
            // 🆕 第七阶段：构建剪枝后的调用图
            PrunedCallGraph prunedCallGraph = buildPrunedCallGraph();
            
            // 第八阶段：生成分析结果
            result = generateAnalysisResult(prunedCallGraph);
            
        } catch (Exception e) {
            logger.severe("自主分析失败: " + e.getMessage());
            e.printStackTrace();
            result.setError(e.getMessage());
        } finally {
            result.finish(); // 确保总是记录结束时间
            logger.info("自主分析完成: " + result.getSummary());
        }
        
        return result;
    }
    
    /**
     * 🆕 阶段 0.5: 初始化 Proxy 接口注册表
     */
    private void initializeProxyRegistry(Collection<SootClass> targetClasses) {
        logger.info("阶段 0.5: 初始化 Proxy 接口注册表");
        
        // 创建注册表
        proxyRegistry = new ProxyInterfaceRegistry();
        
        // 扫描 InvocationHandler 实现类
        proxyRegistry.scanInvocationHandlers(targetClasses);
        
        // 应用启发式规则
        proxyRegistry.applyHeuristicRules(targetClasses);
        
        // 打印详细信息（调试用）
        proxyRegistry.printDetails();
        
        // 打印统计
        ProxyInterfaceRegistry.RegistryStatistics stats = proxyRegistry.getStatistics();
        logger.info("✅ Proxy 注册表初始化完成: " + stats);
    }
    
    /**
     * 第一阶段：收集和预处理方法体 - 使用MethodBodyProcessor
     */
    private void collectAndPreprocessMethods(Collection<SootClass> targetClasses) {
        logger.info("第一阶段：收集和预处理方法体");
        
        // 设置分析类集合
        this.analysisClasses = new HashSet<>(targetClasses);
        
        // 初始化CHAResolver（现在有了analysisClasses）
        this.chaResolver = new CHAResolver(analysisClasses);
        this.callGraphBuilder = new CallGraphBuilder(chaResolver, typeInference);
        
        // 🆕 注入 ProxyInterfaceRegistry
        if (proxyRegistry != null) {
            callGraphBuilder.setProxyInterfaceRegistry(proxyRegistry);
        }
        
        // 使用MethodBodyProcessor收集方法体
        this.methodBodies = methodBodyProcessor.collectMethodBodies(targetClasses);
        
        logger.info("方法体收集完成，共收集 " + methodBodies.size() + " 个方法");
    }
    
    /**
     * 第二阶段：构建自定义调用图 - 使用CallGraphBuilder
     */
    private void buildCustomCallGraph() {
        logger.info("第二阶段：构建自定义调用图（工作列表驱动）");
        
        // 收集所有序列化类的readObject方法
        Set<SootMethod> readObjectMethods = getAllSerializableReadObjectMethods(analysisClasses);
        
        // 使用CallGraphBuilder构建调用图
        callGraphBuilder.buildCallGraph(analysisClasses, methodBodies, readObjectMethods);
        
        logger.info("调用图构建完成");
    }
    
    /**
     * 第三阶段：构建字段访问图 - 使用FieldAccessAnalyzer
     */
    private void buildFieldAccessGraph() {
        logger.info("第三阶段：构建字段访问图");
        
        // 使用FieldAccessAnalyzer构建字段访问图
        fieldAccessAnalyzer.buildFieldAccessGraph(methodBodies);
        
        logger.info("字段访问图构建完成");
    }
    
    /**
     * 第四阶段：构建可控字段图 - 使用ControllableFieldAnalyzer
     */
    private void buildControllableFieldGraph() {
        logger.info("第四阶段：构建可控字段图");
        
        // 使用ControllableFieldAnalyzer构建可控字段图（只需要序列化类）
        controllableFieldAnalyzer.buildControllableFieldGraph(serializableClasses);
        
        logger.info("可控字段图构建完成");
    }
    
    /**
     * 🆕 第五阶段：执行字段敏感污点分析
     */
    private void performFieldSensitiveTaintAnalysis() {
        logger.info("第五阶段：执行字段敏感污点分析");
        
        fieldSensitiveTaintAnalysis.performAnalysis(
            callGraphBuilder.getCallGraph(),
            controllableFieldAnalyzer.getControllableFieldGraph(),
            fieldAccessAnalyzer.getFieldAccessGraph(),
            methodBodies
        );
        
        logger.info("字段敏感污点分析完成");
    }
    
    /**
     * 🆕 第六阶段：执行调用边可控性分析
     */
    private void performControllabilityAnalysis() {
        logger.info("第六阶段：执行调用边可控性分析");
        
        controllabilityAnalyzer.analyzeControllability(
            callGraphBuilder.getCallGraph(),
            fieldSensitiveTaintAnalysis.performAnalysis(
                callGraphBuilder.getCallGraph(),
                controllableFieldAnalyzer.getControllableFieldGraph(),
                fieldAccessAnalyzer.getFieldAccessGraph(),
                methodBodies
            )
        );
        
        logger.info("调用边可控性分析完成");
    }
    
    /**
     * 🆕 第七阶段：构建剪枝后的调用图
     */
    private PrunedCallGraph buildPrunedCallGraph() {
        logger.info("第七阶段：构建剪枝后的调用图");
        
        // 重新执行污点分析以获取结果
        FieldSensitiveTaintAnalysis.TaintAnalysisResult taintResult = 
            fieldSensitiveTaintAnalysis.performAnalysis(
                callGraphBuilder.getCallGraph(),
                controllableFieldAnalyzer.getControllableFieldGraph(),
                fieldAccessAnalyzer.getFieldAccessGraph(),
                methodBodies
            );
        
        // 执行可控性分析
        Map<com.squirtle.core.callgraph.CallGraph.CallEdge, CallEdgeControllabilityAnalyzer.Controllability> edgeControllability =
            controllabilityAnalyzer.analyzeControllability(
                callGraphBuilder.getCallGraph(),
                taintResult
            );
        
        // 构建剪枝后的调用图（Sound模式）
        PrunedCallGraph prunedCallGraph = new PrunedCallGraph(
            callGraphBuilder.getCallGraph(),
            edgeControllability,
            true  // Sound模式
        );
        
        // 打印统计信息
        PrunedCallGraph.PruningStatistics stats = prunedCallGraph.getStatistics();
        logger.info("剪枝统计: " + stats);
        
        return prunedCallGraph;
    }
    
    
    /**
     * 收集所有序列化类的readObject方法（保留在主类中）
     */
    private Set<SootMethod> getAllSerializableReadObjectMethods(Collection<SootClass> targetClasses) {
        Set<SootMethod> readObjectMethodsSet = new HashSet<>();
        
        // 🎯 扫描所有已加载的类（包括JDK类），而不仅仅是targetClasses
        // 这样可以自动找到 Throwable.readObject, HashMap.readObject 等 JDK gadget 入口点
        Collection<SootClass> allClasses = Scene.v().getClasses();
        
        logger.info("开始扫描所有已加载的类查找readObject方法...");
        logger.info("  目标分析类: " + targetClasses.size() + " 个");
        logger.info("  所有加载类: " + allClasses.size() + " 个");
        
        for (SootClass sootClass : allClasses) {
            if (!methodBodyProcessor.shouldAnalyzeClass(sootClass)) continue;
            
            // 检查是否是序列化类
            if (isSerializableClass(sootClass)) {
                serializableClasses.add(sootClass);
                
                // 查找readObject方法
                SootMethod readObjectMethod = findReadObjectMethod(sootClass);
                if (readObjectMethod != null && readObjectMethod.hasActiveBody()) {
                    readObjectMethods.put(sootClass, readObjectMethod);
                    readObjectMethodsSet.add(readObjectMethod);
                    
                    // 只打印关键的JDK gadget类或用户类
                    if (methodBodyProcessor.isUserClass(sootClass) || isKeyGadgetClass(sootClass)) {
                        logger.info("✅ readObject入口: " + readObjectMethod.getSignature());
                    }
                }
            }
        }
        
        logger.info("扫描完成: " + allClasses.size() + " 个类中有 " + serializableClasses.size() + " 个序列化类");
        logger.info("✅ 收集到 " + readObjectMethodsSet.size() + " 个readObject方法作为入口点");
        
        return readObjectMethodsSet;
    }
    
    /**
     * 判断是否是关键的 Gadget 类
     */
    private boolean isKeyGadgetClass(SootClass sootClass) {
        String className = sootClass.getName();
        return className.equals("java.lang.Throwable") ||
               className.equals("java.util.HashMap") ||
               className.equals("java.util.concurrent.ConcurrentHashMap") ||
               className.contains("TemplatesImpl") ||
               className.contains("AnnotationInvocationHandler");
    }
    
    /**
     * 检查类是否实现了Serializable接口（递归检查）
     */
    private boolean isSerializableClass(SootClass sootClass) {
        try {
            // 检查直接实现的接口
            for (SootClass interfaceClass : sootClass.getInterfaces()) {
                if ("java.io.Serializable".equals(interfaceClass.getName())) {
                    return true;
                }
                // 递归检查接口继承
                if (isSerializableClass(interfaceClass)) {
                    return true;
                }
            }
            
            // 检查父类
            if (sootClass.hasSuperclass()) {
                return isSerializableClass(sootClass.getSuperclass());
            }
        } catch (Exception e) {
            // 忽略类层次分析异常
        }
        
        return false;
    }
    
    /**
     * 查找类中的readObject方法
     */
    private SootMethod findReadObjectMethod(SootClass sootClass) {
        try {
            String readObjectSignature = "void readObject(java.io.ObjectInputStream)";
            if (sootClass.declaresMethod(readObjectSignature)) {
                return sootClass.getMethod(readObjectSignature);
            }
        } catch (Exception e) {
            // 忽略方法查找异常
        }
        return null;
    }
    
    /**
     * 生成分析结果
     */
    private AnalysisResult generateAnalysisResult(PrunedCallGraph prunedCallGraph) {
        AnalysisResult result = new AnalysisResult();
        
        result.setTargetDescription("自主分析: " + analysisClasses.size() + " 个类");
        
        // 设置各组件的分析结果
        result.setCallGraph(callGraphBuilder.getCallGraph());  // 原始调用图
        result.setPrunedCallGraph(prunedCallGraph.toCallGraph());  // 剪枝后的调用图
        result.setControllableFieldGraph(controllableFieldAnalyzer.getControllableFieldGraph());
        result.setFieldAccessGraph(fieldAccessAnalyzer.getFieldAccessGraph());
        
        // 暂时禁用的组件返回null或空结果
        result.setDataFlowResult(null); // dataFlowAnalysis.getResult()
        
        return result;
    }
}
