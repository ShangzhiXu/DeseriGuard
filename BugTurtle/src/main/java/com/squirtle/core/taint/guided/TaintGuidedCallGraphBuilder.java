package com.squirtle.core.taint.guided;

import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.callgraph.CallGraph.CallType;
import com.squirtle.core.callgraph.CallGraphPruner;
import com.squirtle.core.callgraph.PureFunctionFilter;
import com.squirtle.core.reflection.controllability.ReflectionControllabilityAnalyzer;
import com.squirtle.core.reflection.controllability.ReflectionControllabilityAnalyzer.AnalysisResult;
import com.squirtle.core.reflection.controllability.ReflectionControllabilityAnalyzer.Controllability;
import com.squirtle.core.sink.FlashAlignedSinkRegistry;
import com.squirtle.core.sink.SinkDefinition;
import com.squirtle.core.taint.guided.model.*;
import com.squirtle.core.taint.guided.analyzer.MethodTaintAnalyzer;
import com.squirtle.core.taint.guided.resolver.CallTargetResolver;
import soot.*;
import soot.jimple.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * 污点驱动的调用图构建器
 * 
 * 实现算法：
 * 1. 从readObject等入口开始
 * 2. 追踪可控性传播（this、参数、返回值）
 * 3. 只记录可控对象的方法调用
 * 4. 使用Worklist算法迭代分析
 * 5. 支持多轮固定点迭代（处理返回值污点时序依赖）
 * 6. 检测到达Flash定义的30个sink（带可控性约束）
 */
public class TaintGuidedCallGraphBuilder {
    private static final Logger logger = LoggerFactory.getLogger(TaintGuidedCallGraphBuilder.class);
    
    private static final int MAX_GLOBAL_ITERATIONS = 3;
    private static final int MAX_DEPTH = 20;
    
    /** Flash对齐的Sink注册表 */
    private final FlashAlignedSinkRegistry sinkRegistry;
    
    /** 发现的Gadget列表（sink到达路径） */
    private final List<GadgetInfo> discoveredGadgets;
    
    /** 字段读取分析缓存（性能优化） */
    private final Map<SootMethod, Boolean> fieldReadCache;
    
    /** 纯函数过滤器（通用设计，不依赖gadget知识） */
    private final PureFunctionFilter pureFunctionFilter;
    
    /** 反射目标可控性分析器 */
    private final ReflectionControllabilityAnalyzer reflectionAnalyzer;
    
    /**
     * 构造函数
     */
    public TaintGuidedCallGraphBuilder() {
        this.sinkRegistry = FlashAlignedSinkRegistry.v(); // 再次改回使用单例，解决根本问题
        this.discoveredGadgets = new ArrayList<>();
        this.fieldReadCache = new HashMap<>();
        this.pureFunctionFilter = new PureFunctionFilter();
        this.reflectionAnalyzer = new ReflectionControllabilityAnalyzer();
    }
    
    /**
     * 构建污点驱动的调用图
     */
    public CallGraph buildTaintGuidedCallGraph(Set<SootClass> targetClasses) {
        logger.info("开始构建污点驱动的调用图，目标类数量：{}", targetClasses.size());
        
        // 1. 初始化
        discoveredGadgets.clear();  // 清空之前的gadget列表
        MethodInternalState.clearStaticFieldTaints();
        Map<SootMethod, MethodTaintSummary> summaryCache = new HashMap<>();
        CallGraph callGraph = new CallGraph();
        Set<SootMethod> entryPoints = collectReadObjectMethods(targetClasses);
        
        logger.info("收集到入口点数量：{}", entryPoints.size());
        
        // 2. 多轮固定点迭代
        boolean globalChanged = true;
        int globalIteration = 0;
        
        while (globalChanged && globalIteration < MAX_GLOBAL_ITERATIONS) {
            globalChanged = false;
            globalIteration++;
            
            logger.info("开始第{}轮全局迭代", globalIteration);
            
            Map<SootMethod, MethodLevelTaint> visited = new HashMap<>();
            PriorityQueue<WorkItem> worklist = new PriorityQueue<>();
            
            // 3. 初始化Worklist（入口点）
            for (SootMethod method : entryPoints) {
                MethodLevelTaint initial = new MethodLevelTaint();
                initial.setThisTainted(true);
                if (method.getParameterCount() > 0) {
                    initial.setParamTaint(0, true);  // ObjectInputStream参数
                }
                worklist.add(new WorkItem(method, initial, 0));
            }
            
            // 4. Worklist循环
            int processedMethods = 0;
            int totalCallSites = 0;
            int totalTargets = 0;
            int skippedNoBody = 0;
            int skippedDepth = 0;
            int skippedDuplicate = 0;
            int bodyLoadedCount = 0;
            
            MethodTaintAnalyzer analyzer = new MethodTaintAnalyzer();
            CallTargetResolver resolver = new CallTargetResolver(sinkRegistry);
            
            while (!worklist.isEmpty()) {
                WorkItem item = worklist.poll();
                
                // 调试：检查是否是反射方法
            boolean isReflection = isReflectionMethod(item.getMethod());
            
            // 深度限制（反射方法豁免深度限制）
            if (item.getDepth() > MAX_DEPTH && !isReflection) {
                skippedDepth++;
                continue;
            }
                
                // 尝试加载方法Body（如果还没有的话）
                SootMethod currentMethod = item.getMethod();
                if (!currentMethod.hasActiveBody()) {
                    if (tryLoadBody(currentMethod)) {
                        bodyLoadedCount++;
                    }
                }
                
                // 如果仍然没有Body，跳过（反射方法通过CallTargetResolver处理）
                if (!currentMethod.hasActiveBody()) {
                    skippedNoBody++;
                    continue;
                }
                
                // 去重检查
                MethodLevelTaint existing = visited.get(item.getMethod());
                if (existing != null && !item.getEntryTaint().isStricterThan(existing)) {
                    skippedDuplicate++;
                    continue;  // 已有更严格的污点，跳过
                }
                visited.put(item.getMethod(), item.getEntryTaint());
                
                // 5. 分析方法
                try {
                    MethodTaintResult result = analyzer.analyzeMethod(
                        item.getMethod(), item.getEntryTaint(), summaryCache
                    );
                    
                    processedMethods++;
                    totalCallSites += result.getCallSites().size();
                    
                    // 6. 处理CallSites
                    for (CallSite cs : result.getCallSites()) {
                        // 计算目标污点（对所有目标统一计算）
                        MethodLevelTaint targetTaint = computeTargetTaint(cs);
                        
                        // ⚠️ 污点驱动的核心：只有污点能传播到目标时，才添加边和Worklist
                        if (!targetTaint.isThisTainted() && targetTaint.getParamTaints().isEmpty()) {
                            // 无污点输入 → 跳过所有目标
                            continue;
                        }
                        
                        // 根据base来源决定是否展开CHA
                        Set<SootMethod> targets = resolveTargetsBasedOnOrigin(cs, resolver);
                        totalTargets += targets.size();
                        
                        // 🔥 关键修复：反射调用需要两层边
                        SootMethod declaredMethod = cs.getInvoke().getMethod();
                        boolean isReflectionCall = isReflectionMethod(declaredMethod);
                        
                        // 🔍 调试：输出判断信息
                        if (item.getMethod().getSignature().contains("InstantiateTransformer")) {
                            logger.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                            logger.info("🔍 处理InstantiateTransformer中的调用");
                            logger.info("    declaredMethod: {}", declaredMethod.getSignature());
                            logger.info("    isReflectionCall: {}", isReflectionCall);
                            logger.info("    targets.size: {}", targets.size());
                            logger.info("    targets列表（前3个）:");
                            targets.stream().limit(3).forEach(t -> 
                                logger.info("      - {}", t.getSignature()));
                        }
                        
                        if (isReflectionCall && targets.size() > 1) {
                            // 🆕 反射可控性分析：检查反射目标方法名是否硬编码
                            // 如果是硬编码（如 PrototypeCloneFactory 只调用 "clone"），则跳过推断的目标
                            AnalysisResult controllabilityResult = reflectionAnalyzer.analyzeControllability(item.getMethod());
                            if (controllabilityResult.getControllability() == Controllability.NOT_CONTROLLABLE) {
                                logger.debug("🚫 跳过不可控反射调用: {} (方法名硬编码为: {})", 
                                    item.getMethod().getSignature(), controllabilityResult.getMethodNameValue());
                                // 不添加到推断目标的边，但仍然添加到反射方法本身的边（用于链路完整性）
                                CallType callType = determineCallType(cs.getInvoke());
                                boolean callerIsAppClass = isApplicationClass(item.getMethod());
                                boolean callerIsSource = isSerializationEntry(item.getMethod());
                                boolean callerIsControllable = callerIsAppClass || callerIsSource;
                                Map<Integer, Boolean> edgeParamControllability = 
                                    computeEdgeParamControllability(item.getMethod(), declaredMethod, targetTaint);
                                boolean callerReadsFields = callerReadsControllableFields(item.getMethod());
                                boolean thisControllable = callerIsControllable && (targetTaint.isThisTainted() || callerReadsFields);
                                Map<Integer, Boolean> paramControllable = callerIsControllable ? edgeParamControllability : new HashMap<>();
                                callGraph.addCall(item.getMethod(), declaredMethod, cs.getUnit(), callType,
                                    thisControllable, paramControllable);
                                // 不继续添加到推断目标的边，直接跳到下一个调用点
                                continue;
                            }
                            
                            logger.info("✅ 使用两层边策略: {} -> {}", item.getMethod().getName(), declaredMethod.getName());
                            logger.info("   将添加 {} → {}", item.getMethod().getSignature(), declaredMethod.getSignature());
                            logger.info("   以及 {} 条从反射方法到推断目标的边", targets.size());
                            logger.info("   反射可控性: {}", controllabilityResult);
                            
                            // 反射调用 且 有多个推断目标
                            // 策略：只添加到反射方法的边，让反射方法去连接推断的目标
                            CallType callType = determineCallType(cs.getInvoke());
                            
                            // 🔥 关键修复：如果 caller 是 JDK 内部方法，边标记为不可控
                            // 🆕 但反序列化入口（source）是例外，即使是 JDK 类也应该可控！
                            boolean callerIsAppClass = isApplicationClass(item.getMethod());
                            boolean callerIsSource = isSerializationEntry(item.getMethod());
                            boolean callerIsControllable = callerIsAppClass || callerIsSource;
                            
                            // 🔥 关键修复：计算边的可控性（考虑字段污点传播）
                            Map<Integer, Boolean> edgeParamControllability = 
                                computeEdgeParamControllability(item.getMethod(), declaredMethod, targetTaint);
                            
                            // 如果 caller 是 JDK 方法（且不是 source），清空可控性
                            // 🔥 修复：thisControllable 应该检查 caller 是否读取可控字段
                            boolean callerReadsFields = callerReadsControllableFields(item.getMethod());
                            boolean thisControllable = callerIsControllable && (targetTaint.isThisTainted() || callerReadsFields);
                            Map<Integer, Boolean> paramControllable = callerIsControllable ? edgeParamControllability : new HashMap<>();
                            
                            // 🆕 传入可控性信息
                            callGraph.addCall(item.getMethod(), declaredMethod, cs.getUnit(), callType,
                                thisControllable, paramControllable);
                            
                            // 反射方法作为新的WorkItem继续分析
                            if (tryLoadBody(declaredMethod)) {
                                bodyLoadedCount++;
                            }
                            worklist.add(new WorkItem(declaredMethod, targetTaint, item.getDepth() + 1));
                            
                            // 🚀 特殊处理：为反射方法添加到推断目标的边
                            // 这些边的caller是反射方法本身（declaredMethod）
                            
                            for (SootMethod target : targets) {
                                // 🔥 关键修复：跳过反射方法自己，防止自环
                                if (target.equals(declaredMethod)) {
                                    logger.debug("跳过反射方法自环: {} -> {}", declaredMethod.getSignature(), target.getSignature());
                                    continue;
                                }
                                
                                // 🔥 核心修复：为目标方法重新计算污点需求
                                // targetTaint 是为反射方法（Method.invoke）计算的
                                // 但我们需要目标方法（如 Runtime.exec）的污点需求
                                MethodLevelTaint targetSpecificTaint = computeTargetTaint(cs, target);
                                
                                // 🔥 先增强反射方法的污点（必须在 canReflectionPropagateTaint 之前）
                                // 补充字段污点传播：如果调用反射方法的caller读取了可控字段，标记参数可控
                                MethodLevelTaint enhancedTargetTaint = new MethodLevelTaint();
                                enhancedTargetTaint.setThisTainted(targetTaint.isThisTainted());
                                enhancedTargetTaint.getParamTaints().putAll(targetTaint.getParamTaints());
                                
                                if (callerReadsControllableFields(item.getMethod())) {
                                    if (isMethodInvokeCall(declaredMethod)) {
                                        // Method.invoke(obj, args): 标记参数0（obj/this）和参数1（args）可控
                                        // 在Rhino/CC等链中，攻击者可以控制obj（通过序列化字段）
                                        enhancedTargetTaint.setParamTaint(0, true);
                                        enhancedTargetTaint.setParamTaint(1, true);
                                    } else if (isConstructorNewInstanceCall(declaredMethod)) {
                                        // Constructor.newInstance: 标记参数0（args）可控
                                        enhancedTargetTaint.setParamTaint(0, true);
                                    }
                                }
                                
                                // 🔥 反射污点传播：使用增强后的污点检查
                                boolean reflectionCanPropagate = canReflectionPropagateTaint(
                                    declaredMethod, enhancedTargetTaint, target, targetSpecificTaint);
                                
                                // 🔥 修复：反射方法（Method.invoke等）本身是JDK类，不是application class
                                // 应该检查调用反射方法的 caller 是否是 application class
                                // 或者只要 caller 能读取可控字段，就认为边可控
                                boolean callerIsAppClassOrHasFields = isApplicationClass(item.getMethod()) 
                                    || callerReadsControllableFields(item.getMethod());
                                boolean edgeControllable = callerIsAppClassOrHasFields && reflectionCanPropagate;
                                
                                // 🆕 传入可控性信息（使用增强后的反射方法污点）
                                boolean targetThisControllable = edgeControllable && enhancedTargetTaint.isThisTainted();
                                Map<Integer, Boolean> targetParamControllable = edgeControllable ? enhancedTargetTaint.getParamTaints() : new HashMap<>();
                                
                                callGraph.addCall(declaredMethod, target, cs.getUnit(), CallType.REFLECTION,
                                    targetThisControllable, targetParamControllable);
                                
                                // 检测sink（使用目标方法的污点）
                                if (edgeControllable && sinkRegistry.isSinkWithTaint(target, targetSpecificTaint)) {
                                    reportGadget(declaredMethod, target, cs.getUnit(), targetSpecificTaint);
                                }
                                
                                // 继续传播（使用目标方法的污点）
                                if (edgeControllable) {
                                    worklist.add(new WorkItem(target, targetSpecificTaint, item.getDepth() + 2));
                                }
                            }
                        } else {
                            // 非反射调用 或 只有单个目标 → 正常处理
                            if (item.getMethod().getSignature().contains("InstantiateTransformer")) {
                                logger.info("❌ 使用正常边策略（不符合两层边条件）");
                                logger.info("   isReflectionCall={}, targets.size={}", isReflectionCall, targets.size());
                            }
                            
                            for (SootMethod target : targets) {
                                // 🚀 工具类过滤：只过滤明显无害的JDK内部调用
                                if (shouldFilterUtilityCall(item.getMethod(), target)) {
                                    continue; // 跳过工具类调用
                                }
                                
                                // 🔥 新增：纯函数过滤（通用设计，不依赖gadget知识）
                                if (pureFunctionFilter.canSafelyFilter(target)) {
                                    continue; // 跳过纯函数
                                }
                                
                                // 有污点输入 → 添加到调用图
                                CallType callType = determineCallType(cs.getInvoke());
                                
                                // 🔥 关键修复：如果 caller 是 JDK 内部方法，边标记为不可控
                                // 避免 Class.getEnumConstantsShared 等 JDK 方法触发误报
                                // 🆕 但反序列化入口（source）是例外，即使是 JDK 类也应该可控！
                                boolean callerIsAppClass = isApplicationClass(item.getMethod());
                                boolean callerIsSource = isSerializationEntry(item.getMethod());
                                boolean callerIsControllable = callerIsAppClass || callerIsSource;
                                
                                // 🔥 关键修复：计算边的可控性（考虑字段污点传播）
                                Map<Integer, Boolean> edgeParamControllability = 
                                    computeEdgeParamControllability(item.getMethod(), target, targetTaint);
                                
                                // 如果 caller 是 JDK 方法（且不是 source），清空可控性
                                // 🔥 修复：thisControllable 应该检查 caller 是否读取可控字段
                                // 如果 caller 读取可控字段并用它调用方法，callee 的 this 就是可控的
                                boolean callerReadsFields = callerReadsControllableFields(item.getMethod());
                                boolean thisControllable = callerIsControllable && (targetTaint.isThisTainted() || callerReadsFields);
                                Map<Integer, Boolean> paramControllable = callerIsControllable ? edgeParamControllability : new HashMap<>();
                                
                                // 🆕 Class.newInstance 误报过滤：检查 this.getClass() 模式
                                // 如果调用者使用 this.getClass().newInstance()，Class 对象不可控
                                if (isClassNewInstanceCall(target) && usesThisGetClassPattern(item.getMethod())) {
                                    thisControllable = false;
                                    logger.debug("🔥 [Class.newInstance过滤] {} 使用 this.getClass() 模式 → this不可控", 
                                        item.getMethod().getName());
                                }
                                
                                // 🆕 传入可控性信息
                                callGraph.addCall(item.getMethod(), target, cs.getUnit(), callType,
                                    thisControllable, paramControllable);
                                
                                // ✅ 检测是否到达Sink（带可控性约束）
                                if (sinkRegistry.isSinkWithTaint(target, targetTaint)) {
                                    // 找到gadget：到达sink且参数可控
                                    reportGadget(item.getMethod(), target, cs.getUnit(), targetTaint);
                                }
                                
                                // 强制加载目标方法的Body（如果可能）
                                if (tryLoadBody(target)) {
                                    bodyLoadedCount++;
                                }
                                
                                // 添加到Worklist（继续传播污点）
                                // 注意：即使到达sink也继续传播，可能有链式调用
                                worklist.add(new WorkItem(target, targetTaint, item.getDepth() + 1));
                            }
                        }
                    }
                    
                    // 7. 更新Summary并检测变化（支持VSA）
                    MethodTaintSummary summary = summaryCache.computeIfAbsent(
                        item.getMethod(), k -> new MethodTaintSummary()
                    );
                    
                    MethodTaintSummary.SummaryResult oldResult = summary.getResult(item.getEntryTaint());
                    MethodTaintSummary.SummaryResult newResult = new MethodTaintSummary.SummaryResult(
                        result.isReturnTainted(), null, result.getReturnValueSet()
                    );
                    
                    // 检测变化：污点或值集有变化都触发重新迭代
                    if (oldResult == null || 
                        oldResult.returnTainted != newResult.returnTainted ||
                        !oldResult.getReturnValueSet().equals(newResult.getReturnValueSet())) {
                        globalChanged = true;
                    }
                    
                    summary.addResult(item.getEntryTaint(), newResult);
                    
                } catch (Exception e) {
                    logger.debug("分析方法失败：{} - {}", item.getMethod().getSignature(), e.getMessage());
                }
            }
            
            logger.info("第{}轮迭代完成，处理方法数：{}，调用图边数：{}",
                    globalIteration, processedMethods, callGraph.getAllEdges().size());
            
        }
        
        logger.info("调用图构建完成，总边数：{}，总方法数：{}",
                callGraph.getAllEdges().size(), summaryCache.size());
        
        // 🔥 新增：剪枝反射方法的不可达边（必须在添加关键边之前，否则关键边会被剪掉）
        pruneReflectionMethods(callGraph);
        
        // 🔥 新增：添加 JDK 关键调用边（JDK 类的方法体无法分析，需手动添加）
        // 注意：必须在剪枝之后添加，否则这些边会被误剪
        addCriticalJDKEdges(callGraph);
        
        // 🔥 新增：清理死节点（孤岛消除）
        removeDeadNodes(callGraph, entryPoints);
        
        // 打印发现的Gadget（测试时关闭）
        // printGadgetStatistics();
        
        return callGraph;
    }
    
    /**
     * 报告发现的Gadget
     */
    private void reportGadget(SootMethod caller, SootMethod sink, Unit callSite, MethodLevelTaint taint) {
        SinkDefinition sinkDef = sinkRegistry.getSinkDefinition(sink.getSignature());
        if (sinkDef == null) {
            return;  // 不应该发生
        }
        
        GadgetInfo gadget = new GadgetInfo(caller, sink, callSite, taint, sinkDef);
        discoveredGadgets.add(gadget);
        
        logger.info("✅ 发现Gadget: {} -> {} ({})",
                caller.getSignature(), sink.getSignature(), sinkDef.getCategory());
    }
    
    /**
     * 添加 JDK 关键调用边
     * 
     * JDK 类的方法体无法通过 Soot 分析（retrieveActiveBody 会失败），
     * 但这些调用模式是已知的 gadget 链关键路径，需要手动添加。
     * 
     * 参考 Flash 的 priori-knowledge.yml edges 配置
     */
    private void addCriticalJDKEdges(CallGraph callGraph) {
        logger.info("添加 JDK 关键调用边...");
        int addedEdges = 0;
        
        // JDK 关键调用边定义（source签名 -> target签名）
        // 格式：{caller方法签名, callee方法签名, 调用类型}
        String[][] criticalEdges = {
            // PriorityQueue.readObject -> Comparator.compare (BeanShell1, CC2, CC4)
            {"<java.util.PriorityQueue: void readObject(java.io.ObjectInputStream)>",
             "<java.util.Comparator: int compare(java.lang.Object,java.lang.Object)>", "VIRTUAL"},
            
            // HashMap.readObject -> HashMap.hash -> Object.hashCode (URLDNS, CC6, CC7)
            {"<java.util.HashMap: void readObject(java.io.ObjectInputStream)>",
             "<java.lang.Object: int hashCode()>", "VIRTUAL"},
            
            // Hashtable.readObject -> reconstitutionPut -> Object.hashCode (CC7)
            {"<java.util.Hashtable: void readObject(java.io.ObjectInputStream)>",
             "<java.lang.Object: int hashCode()>", "VIRTUAL"},
            
            // HashSet.readObject -> HashMap.put (CC6)
            {"<java.util.HashSet: void readObject(java.io.ObjectInputStream)>",
             "<java.util.HashMap: java.lang.Object put(java.lang.Object,java.lang.Object)>", "VIRTUAL"},
            
            // TreeMap.readObject -> Comparator.compare
            {"<java.util.TreeMap: void readObject(java.io.ObjectInputStream)>",
             "<java.util.Comparator: int compare(java.lang.Object,java.lang.Object)>", "VIRTUAL"},
            
            // TreeSet.readObject -> TreeMap.put -> Comparator.compare
            {"<java.util.TreeSet: void readObject(java.io.ObjectInputStream)>",
             "<java.util.Comparator: int compare(java.lang.Object,java.lang.Object)>", "VIRTUAL"},
            
            // BadAttributeValueExpException.readObject -> Object.toString (CC5)
            {"<javax.management.BadAttributeValueExpException: void readObject(java.io.ObjectInputStream)>",
             "<java.lang.Object: java.lang.String toString()>", "VIRTUAL"},
            
            // Object.hashCode -> 各种 hashCode 实现（多态）
            {"<java.lang.Object: int hashCode()>",
             "<java.net.URL: int hashCode()>", "VIRTUAL"},
            
            // URL.hashCode -> URLStreamHandler.hashCode (URLDNS)
            {"<java.net.URL: int hashCode()>",
             "<java.net.URLStreamHandler: int hashCode(java.net.URL)>", "VIRTUAL"},
            
            // URLStreamHandler.hashCode -> getHostAddress -> InetAddress.getByName
            {"<java.net.URLStreamHandler: int hashCode(java.net.URL)>",
             "<java.net.URLStreamHandler: java.net.InetAddress getHostAddress(java.net.URL)>", "VIRTUAL"},
            {"<java.net.URLStreamHandler: java.net.InetAddress getHostAddress(java.net.URL)>",
             "<java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>", "STATIC"},
            
            // InvocationHandler.invoke（动态代理）
            {"<java.util.Comparator: int compare(java.lang.Object,java.lang.Object)>",
             "<java.lang.reflect.InvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>", "INTERFACE"},
            {"<java.lang.Object: int hashCode()>",
             "<java.lang.reflect.InvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>", "INTERFACE"},
            {"<java.lang.Object: java.lang.String toString()>",
             "<java.lang.reflect.InvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>", "INTERFACE"},
            
            // AnnotationInvocationHandler.invoke -> memberValues.get (CC1, CC3)
            {"<sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>",
             "<java.util.Map: java.lang.Object get(java.lang.Object)>", "INTERFACE"},
            
            // 注：Rhino 链的边（Method.invoke -> JavaAdapter.readAdapterObject）
            // 已改为通用方法处理：inferMethodInvokeTargets 自动添加目标库的静态方法
        };
        
        for (String[] edge : criticalEdges) {
            String callerSig = edge[0];
            String calleeSig = edge[1];
            String callTypeStr = edge[2];
            
            try {
                SootMethod caller = findMethodBySignature(callerSig);
                SootMethod callee = findMethodBySignature(calleeSig);
                
                if (caller != null && callee != null) {
                    CallType callType = CallType.valueOf(callTypeStr);
                    
                    // 添加边，标记为可控（JDK source 的边通常是可控的）
                    Map<Integer, Boolean> paramControllable = new HashMap<>();
                    for (int i = 0; i < callee.getParameterCount(); i++) {
                        paramControllable.put(i, true);
                    }
                    
                    callGraph.addCall(caller, callee, null, callType, true, paramControllable);
                    addedEdges++;
                    logger.debug("添加 JDK 边: {} -> {}", callerSig, calleeSig);
                }
            } catch (Exception e) {
                logger.debug("添加 JDK 边失败: {} -> {} : {}", callerSig, calleeSig, e.getMessage());
            }
        }
        
        logger.info("添加了 {} 条 JDK 关键调用边", addedEdges);
    }
    
    /**
     * 根据签名查找方法
     */
    private SootMethod findMethodBySignature(String signature) {
        try {
            // 提取类名
            int colonPos = signature.indexOf(':');
            if (colonPos < 0) return null;
            
            String className = signature.substring(1, colonPos); // 去掉开头的 <
            
            // 尝试获取类
            if (!Scene.v().containsClass(className)) {
                // 尝试加载
                Scene.v().addBasicClass(className, SootClass.SIGNATURES);
                Scene.v().loadClassAndSupport(className);
            }
            
            if (Scene.v().containsClass(className)) {
                SootClass sc = Scene.v().getSootClass(className);
                
                // 遍历方法找到匹配的签名
                for (SootMethod method : sc.getMethods()) {
                    if (method.getSignature().equals(signature)) {
                        return method;
                    }
                }
            }
        } catch (Exception e) {
            logger.trace("无法找到方法: {}", signature);
        }
        return null;
    }
    
    /**
     * 打印Gadget统计信息
     */
    private void printGadgetStatistics() {
        System.out.println("\n========================================");
        System.out.println("✅ Gadget检测结果（Flash对齐）");
        System.out.println("========================================");
        System.out.println("发现Gadget总数: " + discoveredGadgets.size());
        
        if (discoveredGadgets.isEmpty()) {
            System.out.println("⚠️ 未发现任何到达sink的gadget路径");
            System.out.println("可能原因：");
            System.out.println("  1. 目标库确实不包含反序列化gadget");
            System.out.println("  2. Sink定义不完整（当前使用Flash的30个sink）");
            System.out.println("  3. 可控性约束太严格");
            return;
        }
        
        // 按类别统计
        Map<SinkDefinition.SinkCategory, Integer> countByCategory = new EnumMap<>(SinkDefinition.SinkCategory.class);
        for (GadgetInfo gadget : discoveredGadgets) {
            countByCategory.merge(gadget.getSinkCategory(), 1, Integer::sum);
        }
        
        System.out.println("\n按Sink类别统计:");
        for (Map.Entry<SinkDefinition.SinkCategory, Integer> entry : countByCategory.entrySet()) {
            System.out.println(String.format("  %s: %d", entry.getKey().getDisplayName(), entry.getValue()));
        }
        
        // 打印前10个gadget详情
        System.out.println("\nGadget详情（前10个）:");
        int count = 0;
        for (GadgetInfo gadget : discoveredGadgets) {
            if (count >= 10) break;
            count++;
            
            System.out.println(String.format("\n[%d] %s", count, gadget.getSinkCategory().getDisplayName()));
            System.out.println("  调用者: " + gadget.getCaller().getSignature());
            System.out.println("  Sink: " + gadget.getSink().getSignature());
            System.out.println("  污点: " + describeTaint(gadget.getTaint()));
            System.out.println("  调用位置: " + gadget.getCallSite());
        }
        
        if (discoveredGadgets.size() > 10) {
            System.out.println("\n... 还有 " + (discoveredGadgets.size() - 10) + " 个gadget（省略）");
        }
        
        System.out.println("========================================\n");
    }
    
    /**
     * 描述污点状态（用于输出）
     */
    private String describeTaint(MethodLevelTaint taint) {
        List<String> parts = new ArrayList<>();
        
        if (taint.isThisTainted()) {
            parts.add("this=可控");
        }
        
        for (Map.Entry<Integer, Boolean> entry : taint.getParamTaints().entrySet()) {
            if (entry.getValue()) {
                parts.add("param" + entry.getKey() + "=可控");
            }
        }
        
        return parts.isEmpty() ? "无污点" : String.join(", ", parts);
    }
    
    /**
     * 获取发现的Gadget列表
     */
    public List<GadgetInfo> getDiscoveredGadgets() {
        return Collections.unmodifiableList(discoveredGadgets);
    }
    
    /**
     * 收集反序列化入口点
     */
    private Set<SootMethod> collectReadObjectMethods(Set<SootClass> targetClasses) {
        Set<SootMethod> entryPoints = new HashSet<>();
        
        for (SootClass cls : targetClasses) {
            try {
                // 1. readObject(ObjectInputStream)
                if (cls.declaresMethodByName("readObject")) {
                    for (SootMethod m : cls.getMethods()) {
                        if (m.getName().equals("readObject") &&
                            m.getParameterCount() == 1 &&
                            m.getParameterType(0).toString().equals("java.io.ObjectInputStream")) {
                            entryPoints.add(m);
                        }
                    }
                }
                
                // 2. readExternal(ObjectInput)
                if (cls.declaresMethodByName("readExternal")) {
                    for (SootMethod m : cls.getMethods()) {
                        if (m.getName().equals("readExternal") &&
                            m.getParameterCount() == 1 &&
                            m.getParameterType(0).toString().equals("java.io.ObjectInput")) {
                            entryPoints.add(m);
                        }
                    }
                }
                
                // 3. readResolve()
                if (cls.declaresMethodByName("readResolve")) {
                    for (SootMethod m : cls.getMethods()) {
                        if (m.getName().equals("readResolve") &&
                            m.getParameterCount() == 0) {
                            entryPoints.add(m);
                        }
                    }
                }
                
                // 4. <clinit>静态初始化器（对Serializable类）
                try {
                    if (isSerializable(cls) && cls.declaresMethodByName("<clinit>")) {
                        SootMethod clinit = cls.getMethodByName("<clinit>");
                        if (clinit.hasActiveBody()) {
                            entryPoints.add(clinit);
                        }
                    }
                } catch (Exception e) {
                    // 忽略
                }
                
            } catch (Exception e) {
                logger.debug("收集入口点失败：{} - {}", cls.getName(), e.getMessage());
            }
        }
        
        return entryPoints;
    }
    
    /**
     * 判断类是否实现Serializable
     */
    private boolean isSerializable(SootClass cls) {
        try {
            SootClass serializableClass = Scene.v().getSootClass("java.io.Serializable");
            Hierarchy hierarchy = Scene.v().getActiveHierarchy();
            return hierarchy.isClassSubclassOfIncluding(cls, serializableClass);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 根据base来源决定如何解析目标
     * 
     * 这是控制调用图大小的关键：
     * - FIELD：必须展开CHA（攻击者可控）
     * - THIS：精确派发（只解析当前类，不展开子类）
     * - PARAMETER/UNKNOWN：使用类型推导
     * - LOCAL_NEW/LOCAL_CONST：不展开（只返回声明方法）
     * - STATIC_CALL：直接返回声明方法
     */
    private Set<SootMethod> resolveTargetsBasedOnOrigin(CallSite cs, CallTargetResolver resolver) {
        BaseOrigin origin = cs.getBaseOrigin();
        InvokeExpr invoke = cs.getInvoke();
        SootMethod declaredMethod = invoke.getMethod();
        
        switch (origin) {
            case FIELD:
                // 字段引用 → 必须展开CHA（攻击者可以控制字段指向任意子类）
                return resolver.resolveTargets(cs);
                
            case THIS:
                // this调用 → 精确派发（不展开子类）
                return resolveThisCall(invoke, cs.getCaller());
                
            case PARAMETER:
                // 参数 → 检查是否需要展开CHA
                return resolveParameterCall(invoke, resolver, cs);
                
            case UNKNOWN:
                // 未知来源 → 检查是否需要展开
                return resolveUnknownCall(invoke, resolver, cs);
                
            case LOCAL_NEW:
            case LOCAL_CONST:
                // 局部new或常量 → 类型固定，不展开
                return Collections.singleton(declaredMethod);
                
            case STATIC_CALL:
                // 静态调用 → 直接返回声明的方法
                return Collections.singleton(declaredMethod);
                
            default:
                // 默认：保守展开
                return resolver.resolveTargets(cs);
        }
    }
    
    /**
     * 解析参数调用的目标
     * 
     * 对于 param.method() 调用：
     * - 如果方法是final → 不展开
     * - 如果声明类是final → 不展开
     * - 如果声明类无子类 → 不展开
     * - 否则使用refinedCHA
     */
    private Set<SootMethod> resolveParameterCall(InvokeExpr invoke, CallTargetResolver resolver, CallSite cs) {
        SootMethod declaredMethod = invoke.getMethod();
        
        // 特殊处理：反射方法（Method.invoke, Constructor.newInstance等）
        // 即使它们是final，也需要调用resolver进行目标推断
        if (isReflectionMethod(declaredMethod)) {
            return resolver.resolveTargets(cs);
        }
        
        // 1. 如果方法是final → 不需要CHA
        if (declaredMethod.isFinal()) {
            return Collections.singleton(declaredMethod);
        }
        
        // 2. 如果声明类是final → 不需要CHA
        SootClass declaredClass = declaredMethod.getDeclaringClass();
        if (declaredClass.isFinal()) {
            return Collections.singleton(declaredMethod);
        }
        
        // 3. 如果声明类没有子类 → 不需要CHA
        if (!hasSubclasses(declaredClass)) {
            return Collections.singleton(declaredMethod);
        }
        
        // 4. 否则使用refinedCHA
        return resolver.resolveTargets(cs);
    }
    
    /**
     * 解析UNKNOWN来源的调用
     * 
     * 对于来源未知的调用：
     * - 如果方法是final → 不展开
     * - 如果声明类是final → 不展开
     * - 如果声明类无子类 → 不展开
     * - 否则保守展开CHA
     */
    private Set<SootMethod> resolveUnknownCall(InvokeExpr invoke, CallTargetResolver resolver, CallSite cs) {
        SootMethod declaredMethod = invoke.getMethod();
        
        // 特殊处理：反射方法（Method.invoke, Constructor.newInstance等）
        // 即使它们是final，也需要调用resolver进行目标推断
        if (isReflectionMethod(declaredMethod)) {
            return resolver.resolveTargets(cs);
        }
        
        // 1. 如果方法是final → 不需要CHA
        if (declaredMethod.isFinal()) {
            return Collections.singleton(declaredMethod);
        }
        
        // 2. 如果声明类是final → 不需要CHA
        SootClass declaredClass = declaredMethod.getDeclaringClass();
        if (declaredClass.isFinal()) {
            return Collections.singleton(declaredMethod);
        }
        
        // 3. 如果声明类没有子类 → 不需要CHA
        if (!hasSubclasses(declaredClass)) {
            return Collections.singleton(declaredMethod);
        }
        
        // 4. 否则保守展开CHA
        return resolver.resolveTargets(cs);
    }
    
    /**
     * 检查一个类在当前Scene中是否有子类
     */
    private boolean hasSubclasses(SootClass cls) {
        try {
            Hierarchy hierarchy = Scene.v().getActiveHierarchy();
            
            // 如果是接口，检查是否有实现者
            if (cls.isInterface()) {
                List<SootClass> implementers = hierarchy.getImplementersOf(cls);
                return !implementers.isEmpty();
            }
            
            // 如果是类，检查是否有子类
            List<SootClass> subclasses = hierarchy.getSubclassesOf(cls);
            return !subclasses.isEmpty();
            
        } catch (Exception e) {
            // 出错时保守返回true
            return true;
        }
    }
    
    /**
     * 解析this调用的目标
     * 
     * 对于 this.method() 调用：
     * - 不展开所有子类（避免调用图爆炸）
     * - 只解析当前类的实现（精确派发）
     */
    private Set<SootMethod> resolveThisCall(InvokeExpr invoke, SootMethod caller) {
        SootMethod declaredMethod = invoke.getMethod();
        
        // 静态调用、特殊调用、构造函数调用 → 直接返回
        if (invoke instanceof StaticInvokeExpr || 
            invoke instanceof SpecialInvokeExpr) {
            return Collections.singleton(declaredMethod);
        }
        
        // 虚方法/接口调用 → 使用caller的声明类来精确派发
        if (invoke instanceof VirtualInvokeExpr || 
            invoke instanceof InterfaceInvokeExpr) {
            
            SootClass callerClass = caller.getDeclaringClass();
            
            try {
                // 在caller的类中查找方法的具体实现
                Hierarchy hierarchy = Scene.v().getActiveHierarchy();
                
                // 如果caller的类有该方法的实现，使用它
                if (callerClass.declaresMethod(declaredMethod.getSubSignature())) {
                    SootMethod resolved = callerClass.getMethod(declaredMethod.getSubSignature());
                    return Collections.singleton(resolved);
                }
                
                // 否则，查找父类中的实现（向上查找，不向下）
                for (SootClass superClass : hierarchy.getSuperclassesOfIncluding(callerClass)) {
                    if (superClass.declaresMethod(declaredMethod.getSubSignature())) {
                        SootMethod resolved = superClass.getMethod(declaredMethod.getSubSignature());
                        if (!resolved.isAbstract()) {
                            return Collections.singleton(resolved);
                        }
                    }
                }
            } catch (Exception e) {
                // 查找失败，回退到声明方法
            }
        }
        
        // 回退：返回声明的方法
        return Collections.singleton(declaredMethod);
    }
    
    /**
     * 计算调用目标的入口污点（支持VSA值集传播）
     */
    private MethodLevelTaint computeTargetTaint(CallSite cs) {
        MethodLevelTaint targetTaint = new MethodLevelTaint();
        
        InvokeExpr invoke = cs.getInvoke();
        SootMethod targetMethod = invoke.getMethod();
        SootMethod caller = cs.getCaller();
        
        // 🆕 VSA: 从CallSite提取值集并设置到目标污点
        Set<Type> baseValueSet = cs.getBaseValueSet();
        Map<Integer, Set<Type>> argsValueSets = cs.getArgsValueSets();
        
        // 实例方法调用（虚方法/接口/特殊调用）
        if (invoke instanceof VirtualInvokeExpr || 
            invoke instanceof InterfaceInvokeExpr ||
            invoke instanceof SpecialInvokeExpr) {
            
            // 🆕 VSA: 传播base值集（this的类型）
            if (baseValueSet != null && !baseValueSet.isEmpty()) {
                targetTaint.setThisPossibleTypes(baseValueSet);
            }
            
            // 传播this污点（保守策略：只要base是污点就传播）
            if (cs.isBaseTainted()) {
                targetTaint.setThisTainted(true);
            }
        }
        
        // 传播参数污点和值集
        List<Boolean> argsTainted = cs.getArgsTainted();
        if (argsTainted != null) {
            for (int i = 0; i < argsTainted.size(); i++) {
                if (argsTainted.get(i)) {
                    targetTaint.setParamTaint(i, true);
                }
                
                // 🆕 VSA: 传播参数值集
                Set<Type> paramValueSet = argsValueSets != null ? argsValueSets.get(i) : null;
                
                // 🔍 调试日志
                if (targetMethod.getSignature().contains("InstantiateTransformer") &&
                    targetMethod.getName().equals("transform")) {
                    logger.info("🔍 [VSA诊断] 调用InstantiateTransformer.transform");
                    logger.info("    调用者: {}", cs.getCaller().getSignature());
                    logger.info("    参数{}值集: {}", i, paramValueSet);
                }
                
                if (paramValueSet != null && !paramValueSet.isEmpty()) {
                    targetTaint.setParamPossibleTypes(i, paramValueSet);
                }
            }
        }
        
        // 🔥 关键修复：Method.invoke 的字段污点传播
        // 
        // 问题：InvokerTransformer.transform 读取字段 iArgs 并传给 Method.invoke
        //      但字段读取不传播污点（Field-Insensitive策略）
        //      导致 Method.invoke 的 param[1] 被认为不可控
        // 
        // 🔥 新增问题：NativeJavaObject.readObject 读取字段 adapter_readAdapterObject 作为 Method 对象
        //      但 cs.isBaseTainted() 可能返回 false，导致整个调用被跳过
        // 
        // 解决：如果调用 Method.invoke 且 caller 读取了可控字段
        //      → 保守地标记 this 和 param[1] (args数组) 可控
        if (isMethodInvokeCall(targetMethod)) {
            if (callerReadsControllableFields(caller)) {
                // 🔥 关键修复：标记 this 可控（Method 对象来自字段）
                targetTaint.setThisTainted(true);
                // caller读取了可控字段，保守地标记 param[0](obj) 和 param[1](args) 可控
                // Method.invoke(obj, args): obj 是传给目标方法的 this，args 是参数
                targetTaint.setParamTaint(0, true);
                targetTaint.setParamTaint(1, true);
                logger.debug("🔥 [字段污点传播] {} 调用 Method.invoke 且读取可控字段 → this+param[0]+param[1]可控", 
                    caller.getName());
            }
        }
        
        // 🔥 同样处理：Constructor.newInstance 的字段污点传播
        if (isConstructorNewInstanceCall(targetMethod)) {
            if (callerReadsControllableFields(caller)) {
                // caller读取了可控字段，保守地标记args数组可控
                targetTaint.setParamTaint(0, true);
                logger.debug("🔥 [字段污点传播] {} 调用 Constructor.newInstance 且读取可控字段 → param[0]可控", 
                    caller.getName());
            }
        }
        
        // 🆕 Class.newInstance 可控性修正
        // 问题：Class.newInstance 的 sink 约束是 this 可控
        //       但很多链中的 Class 对象是硬编码的（如 Delegator.class, this.getClass()）
        //       这些不应该被认为是可控的
        // 解决：检查 baseOrigin，如果是 LOCAL_NEW/LOCAL_CONST/THIS → this 不可控
        if (isClassNewInstanceCall(targetMethod)) {
            BaseOrigin origin = cs.getBaseOrigin();
            if (origin == BaseOrigin.LOCAL_NEW || origin == BaseOrigin.LOCAL_CONST || origin == BaseOrigin.THIS) {
                // Class 对象来自硬编码，不可控
                targetTaint.setThisTainted(false);
                logger.debug("🔥 [Class.newInstance过滤] Class来源={} → this不可控", origin);
            }
            // FIELD/PARAMETER/UNKNOWN 保持原有污点状态
        }
        
        return targetTaint;
    }
    
    /**
     * 计算边的参数可控性（考虑字段污点传播）
     * 
     * <p>关键用途：处理反射方法的字段污点传播
     * 
     * <p>例如：InvokerTransformer.transform → Method.invoke
     * - param[0] (input) → 来自caller的参数 → 可控
     * - param[1] (args数组) → 来自caller的字段 iArgs → 也应该可控！
     * 
     * @param caller 调用者方法
     * @param callee 被调用方法
     * @param targetTaint 目标方法的入口污点
     * @return 边的参数可控性Map
     */
    private Map<Integer, Boolean> computeEdgeParamControllability(
            SootMethod caller,
            SootMethod callee,
            MethodLevelTaint targetTaint) {
        
        // 1. 从 targetTaint 提取基础的参数可控性
        Map<Integer, Boolean> edgeControllability = new HashMap<>(targetTaint.getParamTaints());
        
        // 2. 特殊处理：Method.invoke 的字段污点传播
        if (isMethodInvokeCall(callee)) {
            if (callerReadsControllableFields(caller)) {
                edgeControllability.put(1, true);
            }
        }
        
        // 3. 特殊处理：Constructor.newInstance 的字段污点传播
        if (isConstructorNewInstanceCall(callee)) {
            if (callerReadsControllableFields(caller)) {
                edgeControllability.put(0, true);
            }
        }
        
        return edgeControllability;
    }
    
    /**
     * 检查是否是 Method.invoke 调用
     */
    private boolean isMethodInvokeCall(SootMethod method) {
        return method.getSignature().contains("<java.lang.reflect.Method: java.lang.Object invoke(");
    }
    
    /**
     * 检查是否是 Constructor.newInstance 调用
     */
    private boolean isConstructorNewInstanceCall(SootMethod method) {
        return method.getSignature().contains("<java.lang.reflect.Constructor: java.lang.Object newInstance(");
    }
    
    /**
     * 检查是否是 Class.newInstance 调用
     */
    private boolean isClassNewInstanceCall(SootMethod method) {
        return method.getSignature().equals("<java.lang.Class: java.lang.Object newInstance()>");
    }
    
    /**
     * 检查调用者方法是否使用 this.getClass().newInstance() 模式
     * 
     * <p>这种模式下，Class 对象来自 this.getClass()，攻击者无法控制实例化的类。
     * 例如：Delegator.newInstance() 内部就是 return this.getClass().newInstance();
     * 
     * @param caller 调用 Class.newInstance() 的方法
     * @return true 如果使用了 this.getClass() 模式
     */
    private boolean usesThisGetClassPattern(SootMethod caller) {
        if (caller == null || caller.isPhantom() || !caller.hasActiveBody()) {
            return false;
        }
        
        try {
            Body body = caller.getActiveBody();
            for (Unit unit : body.getUnits()) {
                if (unit instanceof Stmt) {
                    Stmt stmt = (Stmt) unit;
                    if (stmt.containsInvokeExpr()) {
                        InvokeExpr invoke = stmt.getInvokeExpr();
                        String sig = invoke.getMethod().getSignature();
                        
                        // 检查是否调用了 Object.getClass() 或其变体
                        if (sig.contains("java.lang.Class getClass()")) {
                            // 检查 base 是否是 this
                            if (invoke instanceof VirtualInvokeExpr) {
                                Value base = ((VirtualInvokeExpr) invoke).getBase();
                                if (base instanceof Local) {
                                    Local local = (Local) base;
                                    // this 通常是第一个 local 且名称为 "this" 或 "r0"
                                    if (local.getName().equals("this") || 
                                        (local.getName().startsWith("r") && local.getName().equals("r0"))) {
                                        logger.debug("🔥 [this.getClass()模式] 方法 {} 使用了 this.getClass()", caller.getName());
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("检查 this.getClass() 模式时出错: {}", e.getMessage());
        }
        
        return false;
    }
    
    /**
     * 检查方法是否读取了可控字段
     * 
     * <p>关键用途：判断字段污点是否应该传播到反射调用
     * 
     * <p>例如：
     * <pre>
     * class InvokerTransformer implements Serializable {
     *     private Object[] iArgs;  // 可控字段（来自反序列化）
     *     
     *     public Object transform(Object input) {
     *         Method method = ...;
     *         return method.invoke(input, iArgs);  // ← 读取了可控字段！
     *     }
     * }
     * </pre>
     * 
     * <p>判断逻辑：
     * 1. 方法所属类是Serializable → 字段可控
     * 2. 方法读取了实例字段 → 字段可能被使用
     * 
     * @param method 目标方法
     * @return true 如果方法读取了可控字段
     */
    private boolean callerReadsControllableFields(SootMethod method) {
        if (method == null || method.isPhantom()) {
            return false;  // Phantom方法：保守返回false
        }
        
        // 1. 检查方法所属类是否可控（Serializable）
        SootClass declaringClass = method.getDeclaringClass();
        if (!isControllableClass(declaringClass)) {
            return false;  // 非可控类，字段不可控
        }
        
        // 2. 检查方法是否读取了实例字段
        return methodReadsInstanceFields(method);
    }
    
    /**
     * 检查类是否可控（即是否实现Serializable）
     * 
     * @param clazz 目标类
     * @return true 如果类是可控的
     */
    private boolean isControllableClass(SootClass clazz) {
        if (clazz == null) {
            return false;
        }
        
        // 检查是否实现Serializable
        try {
            if (clazz.implementsInterface("java.io.Serializable") ||
                clazz.implementsInterface("java.io.Externalizable")) {
                return true;
            }
        } catch (Exception e) {
            // 忽略异常，保守返回false
        }
        
        return false;
    }
    
    /**
     * 检查方法是否读取了实例字段
     * 
     * <p>这是判断是否需要传播this污点的关键：
     * 如果方法读取了实例字段（InstanceFieldRef），则this的污点状态会影响方法行为，
     * 需要保守地传播this污点。
     * 
     * <p>例如：
     * <pre>
     * class InstantiateTransformer {
     *     Object[] iArgs;  // 实例字段
     *     
     *     Object transform(Object input) {
     *         Constructor con = ((Class) input).getConstructor(...);
     *         return con.newInstance(iArgs);  // ← 读取了实例字段！
     *     }
     * }
     * </pre>
     * 
     * @param method 目标方法
     * @return true 如果方法读取了实例字段
     */
    private boolean methodReadsInstanceFields(SootMethod method) {
        if (method == null || method.isPhantom()) {
            // Phantom方法：保守返回true
            return true;
        }
        
        // 🔥 性能优化：检查缓存
        Boolean cached = fieldReadCache.get(method);
        if (cached != null) {
            return cached;
        }
        
        // 尝试加载Body（如果还没有）
        if (!method.hasActiveBody()) {
            try {
                method.retrieveActiveBody();
            } catch (Exception e) {
                // 无法加载Body：保守返回true
                fieldReadCache.put(method, true);
                return true;
            }
        }
        
        if (!method.hasActiveBody()) {
            // 仍然没有Body：保守返回true
            fieldReadCache.put(method, true);
            return true;
        }
        
        // 遍历方法Body，查找实例字段引用
        try {
            Body body = method.getActiveBody();
            for (Unit unit : body.getUnits()) {
                // 检查语句中是否包含InstanceFieldRef
                if (containsInstanceFieldRef(unit)) {
                    fieldReadCache.put(method, true);
                    return true;
                }
            }
        } catch (Exception e) {
            // 分析出错：保守返回true
            fieldReadCache.put(method, true);
            return true;
        }
        
        // 没有读取实例字段
        fieldReadCache.put(method, false);
        return false;
    }
    
    /**
     * 检查语句是否包含实例字段引用
     */
    private boolean containsInstanceFieldRef(Unit unit) {
        // 使用Soot的Value访问器来检查
        for (ValueBox vb : unit.getUseBoxes()) {
            Value v = vb.getValue();
            if (v instanceof soot.jimple.InstanceFieldRef) {
                return true;
            }
            
            // 递归检查嵌套的Value（如InvokeExpr中的参数）
            if (v instanceof InvokeExpr) {
                InvokeExpr invokeExpr = (InvokeExpr) v;
                // 检查方法调用的参数
                for (Value arg : invokeExpr.getArgs()) {
                    if (arg instanceof soot.jimple.InstanceFieldRef) {
                        return true;
                    }
                }
                // 检查base（如果是实例方法调用）
                if (invokeExpr instanceof soot.jimple.InstanceInvokeExpr) {
                    Value base = ((soot.jimple.InstanceInvokeExpr) invokeExpr).getBase();
                    // base本身不算字段引用，但如果base是字段就算
                    if (base instanceof soot.jimple.InstanceFieldRef) {
                        return true;
                    }
                }
            }
        }
        
        // 检查定义的值（赋值语句的左侧）
        for (ValueBox vb : unit.getDefBoxes()) {
            Value v = vb.getValue();
            if (v instanceof soot.jimple.InstanceFieldRef) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 尝试加载方法Body
     * 返回true如果成功加载了Body
     */
    protected boolean tryLoadBody(SootMethod method) {
        if (method == null) return false;
        
        try {
            // 如果方法已经有Body，返回true
            if (method.hasActiveBody()) {
                return true;
            }
            
            // 如果方法是抽象的、native的或phantom的，无法加载Body
            if (method.isAbstract() || method.isNative() || method.isPhantom()) {
                return false;
            }
            
            // 如果方法的类是phantom类，无法加载
            if (method.getDeclaringClass().isPhantom()) {
                return false;
            }
            
            // 尝试检索Body
            if (method.isConcrete()) {
                try {
                    method.retrieveActiveBody();
                    return method.hasActiveBody();
                } catch (Exception e) {
                    // 检索失败，可能是JDK方法或library方法
                    return false;
                }
            }
        } catch (Exception e) {
            // 加载失败
        }
        return false;
    }
    
    /**
     * 检查是否是反射方法
     */
    private boolean isReflectionMethod(SootMethod method) {
        String sig = method.getSignature();
        return sig.contains("<java.lang.reflect.Method: java.lang.Object invoke(") ||
               sig.contains("<java.lang.reflect.Constructor: java.lang.Object newInstance(") ||
               sig.equals("<java.lang.Class: java.lang.Object newInstance()>");
    }
    
    /**
     * 对反射方法应用sink兜底策略（带污点传播检查）
     * 
     * <p>反射方法（Method.invoke, Constructor.newInstance, Class.newInstance）
     * 可能有Body也可能没有，但即使有Body，其实现也是JDK的通用逻辑，
     * 无法看到具体的目标调用。因此，我们直接连接到所有可能的sinks。
     * 
     * <p><b>策略</b>：为反射方法添加到所有Flash sink的边（带污点传播过滤）
     * 
     * @param reflectionMethod 反射方法
     * @param entryTaint 入口污点
     * @param depth 当前深度
     * @param callGraph 调用图
     * @param worklist 工作列表
     */
    private void applyReflectionSinkFallback(
            SootMethod reflectionMethod,
            MethodLevelTaint entryTaint,
            int depth,
            CallGraph callGraph,
            PriorityQueue<WorkItem> worklist) {
        
        // 🔥 关键修复：补充字段污点传播
        // 问题：entryTaint 来自 WorkItem，可能没有考虑字段污点传播
        // 解决：手动检查调用 reflectionMethod 的方法是否读取可控字段
        
        // 从调用图中找到调用 reflectionMethod 的方法
        Set<CallGraph.CallEdge> incomingEdges = new HashSet<>();
        for (CallGraph.CallEdge edge : callGraph.getAllEdges()) {
            if (edge.getCallee().equals(reflectionMethod)) {
                incomingEdges.add(edge);
            }
        }
        
        // 检查是否有任何 caller 读取了可控字段
        boolean anyCallerReadsFields = false;
        for (CallGraph.CallEdge edge : incomingEdges) {
            SootMethod caller = edge.getCaller();
            if (callerReadsControllableFields(caller)) {
                anyCallerReadsFields = true;
                break;
            }
        }
        
        // 如果有 caller 读取了可控字段，补充字段污点传播
        MethodLevelTaint enhancedTaint = new MethodLevelTaint();
        enhancedTaint.setThisTainted(entryTaint.isThisTainted());
        enhancedTaint.getParamTaints().putAll(entryTaint.getParamTaints());
        
        if (anyCallerReadsFields) {
            if (isMethodInvokeCall(reflectionMethod)) {
                // Method.invoke: 标记参数1（args）可控
                enhancedTaint.setParamTaint(1, true);
                logger.debug("🔥 [反射兜底] {} 的caller读取可控字段 → param[1]可控", 
                    reflectionMethod.getName());
            } else if (isConstructorNewInstanceCall(reflectionMethod)) {
                // Constructor.newInstance: 标记参数0（args）可控
                enhancedTaint.setParamTaint(0, true);
                logger.debug("🔥 [反射兜底] {} 的caller读取可控字段 → param[0]可控", 
                    reflectionMethod.getName());
            }
        }
        
        // 使用增强后的污点
        entryTaint = enhancedTaint;
        
        // 获取所有sink方法（包括构造函数）
        Set<SootMethod> sinks = sinkRegistry.getAllSinkMethods();
        
        int connectedCount = 0;
        int skippedCount = 0;
        int constructorSinkCount = 0;
        int constructorConnected = 0;
        
        // 检查反射方法类型
        boolean isConstructor = reflectionMethod.getSignature().contains("Constructor: java.lang.Object newInstance(");
        
        // 为每个sink添加边（带污点传播检查）
        for (SootMethod sink : sinks) {
            
            boolean isSinkConstructor = sink.getName().equals("<init>");
            if (isConstructor && isSinkConstructor) {
                constructorSinkCount++;
            }
            
            // 获取sink的定义
            SinkDefinition sinkDefinition = sinkRegistry.getSinkDefinition(sink.getSignature());

            // 1️⃣ 计算目标污点（从反射方法到sink的污点传播）
            MethodLevelTaint targetTaint = computeTargetTaintForReflection(
                reflectionMethod, entryTaint, sink
            );
            
            
            // 2️⃣ 检查是否有污点传播并满足sink约束
            if (!targetTaint.isThisTainted() && targetTaint.getParamTaints().isEmpty()) {
                skippedCount++;
                continue;  // 无污点传播 → 跳过此sink
            }
            
            // 获取sink定义并检查可控性约束
            if (sinkDefinition == null || !sinkDefinition.isTaintSatisfied(targetTaint)) {
                skippedCount++;
                continue; // 污点未满足sink定义的可控性约束 → 跳过此sink
            }
            
            // 3️⃣ 有污点传播且满束 → 添加边
            // 检查sink是否有效
            if (sink == null || sink.isPhantom()) {
                skippedCount++;
                continue;
            }
            
            try {
                // 🔥 修复：边的可控性应该基于调用者（Method.invoke）的entryTaint
                // 而不是被调用者（sink）的targetTaint
                // entryTaint 表示 Method.invoke 的哪些参数可控
                // 这才是边能提供的可控性
                callGraph.addCall(reflectionMethod, sink, null, CallType.REFLECTION,
                    entryTaint.isThisTainted(), entryTaint.getParamTaints());
                connectedCount++;
            } catch (Exception e) {
                // 忽略addCall异常
                skippedCount++;
                continue;
            }
            if (isSinkConstructor) {
                constructorConnected++;
            }
            
            // 4️⃣ 检查是否满足sink的可控性约束
            // 注意：反射兜底场景没有具体的callSite，跳过reportGadget
            // reportGadget要求callSite非null，但反射场景下callSite就是null
            // if (sinkRegistry.isSinkWithTaint(sink, targetTaint)) {
            //     reportGadget(reflectionMethod, sink, null, targetTaint);
            // }
            
            // 5️⃣ 将sink添加到worklist（传播正确的污点）
            if (depth + 1 <= MAX_DEPTH) {
                worklist.add(new WorkItem(sink, targetTaint, depth + 1));
            }
        }
        
        logger.debug("反射兜底: {} → 连接{}个sink, 跳过{}个",
                reflectionMethod.getName(), connectedCount, skippedCount);
    }
    
    /**
     * 计算反射调用的目标污点
     * 
     * <p>将反射方法的入口污点转换为目标sink的污点。
     * 
     * @param reflectionMethod 反射方法
     * @param entryTaint 反射方法的入口污点
     * @param targetSink 目标sink方法
     * @return 目标sink的入口污点
     */
    private MethodLevelTaint computeTargetTaintForReflection(
            SootMethod reflectionMethod,
            MethodLevelTaint entryTaint,
            SootMethod targetSink) {
        
        // 1. 获取Method.invoke的参数：base (param0) 和 args (param1)
        SootMethod actualReflectionMethod = reflectionMethod;
        
        String sig = reflectionMethod.getSignature();
        
        if (sig.contains("<java.lang.reflect.Method: java.lang.Object invoke(")) {
            // Method.invoke(Object obj, Object... args)
            return computeTargetTaintForMethodInvoke(entryTaint, targetSink);
            
        } else if (sig.contains("<java.lang.reflect.Constructor: java.lang.Object newInstance(")) {
            // Constructor.newInstance(Object... args)
            return computeTargetTaintForConstructorNewInstance(entryTaint, targetSink);
            
        } else if (sig.equals("<java.lang.Class: java.lang.Object newInstance()>")) {
            // Class.newInstance() - 无参构造
            return new MethodLevelTaint();  // 无参数，无污点传播
        }
        
        // 未知反射方法，保守返回空污点
        return new MethodLevelTaint();
    }
    
    /**
     * 计算Method.invoke的目标污点
     * 
     * <p>Method.invoke(Object obj, Object... args)
     * <ul>
     *   <li>param0 (obj) → 目标方法的 this</li>
     *   <li>param1 (args) → 目标方法的所有参数（保守策略）</li>
     * </ul>
     * 
     * @param entryTaint Method.invoke的入口污点
     * @param targetSink 目标sink方法
     * @return 目标sink的入口污点
     */
    private MethodLevelTaint computeTargetTaintForMethodInvoke(
            MethodLevelTaint entryTaint,
            SootMethod targetSink) {
        
        MethodLevelTaint targetTaint = new MethodLevelTaint();
        
        // 规则1: Method.invoke的param0 → 目标的this（如果目标不是静态方法）
        // 🔧 修复：同时传播到第一个参数（保守策略）
        // 原因：攻击者通过控制Method对象（param0），可以选择任意方法并控制其参数
        if (!targetSink.isStatic() && entryTaint.isParamTainted(0)) {
            targetTaint.setThisTainted(true);
            // 🔥 新增：保守地传播到第一个参数
            // 这样Runtime.exec(String cmd)的cmd参数就能被标记为可控
            if (targetSink.getParameterCount() > 0) {
                targetTaint.setParamTaint(0, true);
            }
        }
        
        // 规则2: Method.invoke的param1（args数组）→ 目标的所有参数
        // 保守策略：如果args可控，则目标的所有参数都视为可控
        // 原因：污点分析无法知道args[0], args[1]...哪个具体可控
        if (entryTaint.isParamTainted(1)) {
            for (int i = 0; i < targetSink.getParameterCount(); i++) {
                targetTaint.setParamTaint(i, true);
            }
        }
        
        // 规则3: 对于静态方法，如果param0可控但param1不可控，
        // 保守地传播污点到所有参数（对齐Flash的保守策略）
        if (targetSink.isStatic() && entryTaint.isParamTainted(0) && !entryTaint.isParamTainted(1)) {
            for (int i = 0; i < targetSink.getParameterCount(); i++) {
                targetTaint.setParamTaint(i, true);
            }
        }
        
        return targetTaint;
    }
    
    /**
     * 计算Constructor.newInstance的目标污点
     * 
     * <p>Constructor.newInstance(Object... args)
     * <ul>
     *   <li>param0 (args) → 目标构造函数的所有参数（保守策略）</li>
     *   <li>构造函数没有this（对象还未创建）</li>
     * </ul>
     * 
     * @param entryTaint Constructor.newInstance的入口污点
     * @param targetConstructor 目标构造函数
     * @return 目标构造函数的入口污点
     */
    private MethodLevelTaint computeTargetTaintForConstructorNewInstance(
            MethodLevelTaint entryTaint,
            SootMethod targetConstructor) {
        
        MethodLevelTaint targetTaint = new MethodLevelTaint();
        
        // 构造函数没有this（对象还未创建）
        // 只考虑参数污点
        
        // 规则: Constructor.newInstance的param0（args数组）→ 目标构造函数的所有参数
        if (entryTaint.isParamTainted(0)) {
            for (int i = 0; i < targetConstructor.getParameterCount(); i++) {
                targetTaint.setParamTaint(i, true);
            }
        }
        
        return targetTaint;
    }
    
    private String simplifyMethodName(SootMethod method) {
        return method.getDeclaringClass().getShortName() + "." + method.getName();
    }
    
    /**
     * 确定调用类型
     */
    private CallType determineCallType(InvokeExpr invoke) {
        if (invoke instanceof StaticInvokeExpr) {
            return CallType.STATIC;
        } else if (invoke instanceof VirtualInvokeExpr) {
            return CallType.VIRTUAL;
        } else if (invoke instanceof InterfaceInvokeExpr) {
            return CallType.INTERFACE;
        } else if (invoke instanceof SpecialInvokeExpr) {
            return CallType.SPECIAL;
        } else if (invoke instanceof DynamicInvokeExpr) {
            return CallType.DYNAMIC;
        } else {
            return CallType.VIRTUAL;  // 默认
        }
    }
    
    /**
     * 判断是否应该过滤工具类调用
     * 
     * 策略：基于方法特征的更激进过滤，但仍保持普适性
     * 重点过滤明显无害的JDK工具方法调用
     */
    private boolean shouldFilterUtilityCall(SootMethod caller, SootMethod target) {
        String callerClass = caller.getDeclaringClass().getName();
        String targetClass = target.getDeclaringClass().getName();
        String targetMethod = target.getName();
        
        // 🚀 优先检查：通用的冗余方法（不限于JDK）
        
        // 1. Iterator相关方法（包括Apache Commons）
        if (isIteratorMethod(target)) {
            return true;
        }
        
        // 2. 容器的只读方法（包括Apache Commons）
        if (isContainerReadOnlyMethod(target)) {
            return true;
        }
        
        // 3. 检查Apache Commons容器的equals/hashCode（部分可以过滤）
        if (targetClass.startsWith("org.apache.commons.collections.")) {
            if (targetMethod.equals("equals") || targetMethod.equals("hashCode")) {
                // 过滤明显安全的容器类的equals/hashCode
                if (targetClass.contains("StaticBucketMap") ||
                    targetClass.contains("SynchronizedCollection")) {
                    return true;
                }
            }
        }
        
        // 4. 如果目标不是JDK类，检查完通用规则后保留
        if (!isJDKClass(targetClass)) {
            return false;  // 其他应用类：保留
        }
        
        // ====== 以下是JDK特定的过滤规则 ======
        
        // 5. 过滤明显的工具方法调用
        if (isObviousUtilityMethod(target)) {
            return true;
        }
        
        // 6. 过滤JDK内部的equals/hashCode/toString调用
        if (isJDKClass(callerClass) && isJDKClass(targetClass)) {
            if (targetMethod.equals("toString")) {
                return true;
            }
            if (targetMethod.equals("hashCode") && isSafeHashCodeCall(targetClass)) {
                return true;
            }
            if (targetMethod.equals("equals") && isSafeEqualsCall(targetClass)) {
                return true;
            }
        }
        
        // 7. 过滤StringBuilder/StringBuffer相关调用
        if (isStringProcessingCall(target)) {
            return true;
        }
        
        // 8. 过滤数组复制操作
        if (isArrayCopyOperation(target)) {
            return true;
        }
        
        // 9. 过滤数学计算
        if (isMathOperation(target)) {
            return true;
        }
        
        // 10. 过滤时间/日期相关操作
        if (isTimeRelatedOperation(target)) {
            return true;
        }
        
        // 11. 过滤Object.getClass()（除非可能用于反射）
        if (targetMethod.equals("getClass") && !mightBeUsedForReflection(caller)) {
            return true;
        }
        
        // 12. 保守策略：其他情况都保留
        return false;
    }
    
    /**
     * 判断是否是JDK类
     */
    private boolean isJDKClass(String className) {
        return className.startsWith("java.") || 
               className.startsWith("javax.") || 
               className.startsWith("sun.") || 
               className.startsWith("com.sun.");
    }
    
    /**
     * 🆕 判断是否是安全的equals调用（可以过滤）
     */
    private boolean isSafeEqualsCall(String targetClass) {
        // 基础类型
        if (targetClass.equals("java.lang.String") ||
            targetClass.equals("java.lang.Integer") ||
            targetClass.equals("java.lang.Long") ||
            targetClass.equals("java.lang.Double") ||
            targetClass.equals("java.lang.Boolean") ||
            targetClass.startsWith("java.lang.Number")) {
            return true;
        }
        
        // 🆕 XML/域名相关类（统计发现的冗余调用）
        if (targetClass.startsWith("javax.xml.namespace.QName") ||
            targetClass.startsWith("java.net.URI") ||
            targetClass.startsWith("javax.xml.") ||
            targetClass.startsWith("com.sun.org.apache.xerces.") ||
            targetClass.startsWith("sun.security.x509.") ||
            targetClass.startsWith("java.security.cert.") ||
            targetClass.startsWith("javax.security.")) {
            return true;
        }
        
        // 🆕 MIME类型、LDAP等
        if (targetClass.startsWith("java.awt.datatransfer.MimeType") ||
            targetClass.startsWith("javax.naming.ldap.LdapName") ||
            targetClass.startsWith("java.lang.reflect.WildcardType") ||
            targetClass.startsWith("com.sun.org.apache.xerces.internal.impl.dv.xs.")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 🆕 判断是否是安全的hashCode调用（可以过滤）
     */
    private boolean isSafeHashCodeCall(String targetClass) {
        // 只过滤明确安全的基础类型的hashCode
        // ❌ 不过滤URL.hashCode - 它会调用URLStreamHandler.hashCode（gadget链）
        // ❌ 不过滤集合类的hashCode - 可能触发元素的hashCode/equals
        
        // 基础类型
        if (targetClass.equals("java.lang.String") ||
            targetClass.equals("java.lang.Integer") ||
            targetClass.equals("java.lang.Long") ||
            targetClass.equals("java.lang.Double") ||
            targetClass.equals("java.lang.Boolean") ||
            targetClass.equals("java.lang.Character") ||
            targetClass.equals("java.lang.Byte") ||
            targetClass.equals("java.lang.Short")) {
            return true;
        }
        
        // 🆕 XML/域名相关类（统计发现的冗余调用）
        if (targetClass.startsWith("javax.xml.namespace.QName") ||
            targetClass.startsWith("java.net.URI") ||
            targetClass.startsWith("javax.xml.") ||
            targetClass.startsWith("com.sun.org.apache.xerces.") ||
            targetClass.startsWith("sun.security.x509.") ||
            targetClass.startsWith("java.security.cert.") ||
            targetClass.startsWith("javax.security.")) {
            return true;
        }
        
        // 🆕 MIME类型、LDAP等
        if (targetClass.startsWith("java.awt.datatransfer.MimeType") ||
            targetClass.startsWith("javax.naming.ldap.LdapName") ||
            targetClass.startsWith("java.lang.reflect.WildcardType")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 🆕 判断是否是Iterator相关方法（改进版：直接类名匹配）
     */
    private boolean isIteratorMethod(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        
        // Iterator接口的方法
        if (methodName.equals("hasNext") || 
            methodName.equals("next") || 
            methodName.equals("remove")) {
            
            // 🚀 直接匹配：包含Iterator的类名
            if (className.contains("Iterator") || 
                className.contains("Itr")) {
                return true;
            }
            
            // 常见的Iterator实现类
            if (className.endsWith("$ListIter") ||
                className.endsWith("$SubListIter") ||
                className.endsWith("$Cursor") ||
                className.endsWith("$SubCursor")) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 🆕 判断是否是容器的只读方法（不修改状态）
     */
    private boolean isContainerReadOnlyMethod(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        
        // 容器类（JDK + Apache Commons）
        if (className.startsWith("java.util.") || 
            className.startsWith("java.util.concurrent.") ||
            className.startsWith("org.apache.commons.collections."))  {
            
            // 只读方法
            if (methodName.equals("size") ||
                methodName.equals("isEmpty") ||
                methodName.equals("contains") ||
                methodName.equals("containsKey") ||
                methodName.equals("containsValue")) {
                return true;
            }
            
            // 🆕 get方法智能过滤：保留可能触发gadget的，过滤纯读取的
            if (methodName.equals("get")) {
                // ❌ 绝对不能过滤的：LazyMap（会触发transform）
                if (className.contains("LazyMap")) {
                    return false;  // 保留！
                }
                
                // ✅ 可以过滤的：JDK标准容器的get（纯读取）
                if (className.equals("java.util.HashMap") ||
                    className.equals("java.util.Hashtable") ||
                    className.equals("java.util.TreeMap") ||
                    className.equals("java.util.LinkedHashMap") ||
                    className.equals("java.util.concurrent.ConcurrentHashMap")) {
                    return true;
                }
                
                // 🆕 Apache Commons的一些安全Map
                if (className.startsWith("org.apache.commons.collections.map.") &&
                    (className.contains("StaticBucketMap") ||
                     className.contains("LRUMap") ||
                     className.contains("ReferenceMap"))) {
                    // 这些Map的get一般不会触发复杂逻辑
                    // 但ReferenceMap可能有问题，保守起见先保留
                    if (!className.contains("ReferenceMap")) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    /**
     * 🆕 判断是否是时间/日期相关操作
     */
    private boolean isTimeRelatedOperation(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        
        return className.startsWith("java.time.") ||
               className.startsWith("java.util.Date") ||
               className.startsWith("java.util.Calendar") ||
               className.startsWith("java.sql.Timestamp") ||
               className.startsWith("java.sql.Date");
    }
    
    /**
     * 🆕 判断方法是否可能使用反射
     */
    private boolean mightBeUsedForReflection(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        
        // 如果调用者在反射相关的包中，可能使用getClass
        return className.startsWith("java.lang.reflect.") ||
               className.startsWith("sun.reflect.") ||
               // 或者是Transformer类（gadget相关）
               className.contains("Transformer") ||
               className.contains("Invoker");
    }
    
    /**
     * 判断类是否实现了指定接口
     */
    private boolean implementsInterface(SootClass cls, String interfaceName) {
        try {
            for (SootClass iface : cls.getInterfaces()) {
                if (iface.getName().equals(interfaceName)) {
                    return true;
                }
                // 递归检查父接口
                if (implementsInterface(iface, interfaceName)) {
                    return true;
                }
            }
            // 检查父类
            if (cls.hasSuperclass()) {
                return implementsInterface(cls.getSuperclass(), interfaceName);
            }
        } catch (Exception e) {
            // 忽略错误
        }
        return false;
    }
    
    /**
     * 判断是否是明显的工具方法（基于方法名和类名特征）
     */
    private boolean isObviousUtilityMethod(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        
        // StringBuilder/StringBuffer的所有方法（除了构造函数）
        if ((className.equals("java.lang.StringBuilder") || className.equals("java.lang.StringBuffer")) &&
            !methodName.equals("<init>")) {
            return true;
        }
        
        // Math类的所有静态方法
        if (className.equals("java.lang.Math")) {
            return true;
        }
        
        // Arrays工具类
        if (className.equals("java.util.Arrays")) {
            return true;
        }
        
        // 格式化类
        if (className.startsWith("java.text.") || className.startsWith("java.time.format.")) {
            return true;
        }
        
        // 数学计算类
        if (className.startsWith("java.math.")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 判断是否是Object基本方法调用
     */
    private boolean isObjectBasicMethod(String methodName) {
        return methodName.equals("toString") ||
               methodName.equals("hashCode") ||
               methodName.equals("equals");
    }
    
    /**
     * 判断是否是字符串处理调用
     */
    private boolean isStringProcessingCall(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        
        // String的基本操作方法
        if (className.equals("java.lang.String")) {
            return methodName.equals("length") ||
                   methodName.equals("charAt") ||
                   methodName.equals("substring") ||
                   methodName.equals("indexOf") ||
                   methodName.equals("toLowerCase") ||
                   methodName.equals("toUpperCase") ||
                   methodName.equals("trim") ||
                   methodName.equals("replace");
        }
        
        return false;
    }
    
    /**
     * 判断是否是数组复制操作（更保守的过滤）
     */
    private boolean isArrayCopyOperation(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        
        // System.arraycopy - 纯数组复制，对gadget检测无价值
        if (className.equals("java.lang.System") && methodName.equals("arraycopy")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 判断是否是数学运算
     */
    private boolean isMathOperation(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        
        // Math类
        if (className.equals("java.lang.Math")) {
            return true;
        }
        
        // StrictMath类
        if (className.equals("java.lang.StrictMath")) {
            return true;
        }
        
        // 数学计算类
        if (className.startsWith("java.math.")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 剪枝反射方法的不可达边，减少误报
     */
    private void pruneReflectionMethods(CallGraph callGraph) {
        logger.info("================================================================================");
        logger.info("开始剪枝反射方法的不可达边");
        logger.info("================================================================================");
        
        CallGraphPruner pruner = new CallGraphPruner(callGraph, sinkRegistry);
        
        // 剪枝关键反射方法
        String[] reflectionMethods = {
            "<java.lang.reflect.Constructor: java.lang.Object newInstance(java.lang.Object[])>",
            "<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>",
            "<java.lang.Class: java.lang.Object newInstance()>"
        };
        
        int totalOriginal = 0;
        int totalRemaining = 0;
        int totalRemoved = 0;
        
        for (String signature : reflectionMethods) {
            if (!Scene.v().containsMethod(signature)) {
                continue;
            }
            
            SootMethod method = Scene.v().getMethod(signature);
            int beforeEdges = callGraph.getOutgoingEdges(method).size();
            
            if (beforeEdges == 0) {
                continue;
            }
            
            System.out.println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            System.out.println("剪枝: " + method.getName());
            System.out.println("  剪枝前出边数: " + beforeEdges);
            
            CallGraphPruner.PruneResult result = pruner.pruneReflectionMethod(method);
            
            int afterEdges = callGraph.getOutgoingEdges(method).size();
            System.out.println("  剪枝后出边数（预期）: " + result.remainingEdges);
            System.out.println("  剪枝后出边数（实际）: " + afterEdges);
            System.out.println("  删除边数: " + result.removedEdges);
            System.out.println("  剪枝率: " + String.format("%.2f%%", result.getPruneRate()));
            
            if (afterEdges != result.remainingEdges) {
                System.out.println("  ⚠️ 警告：实际边数与预期不符！");
            }
            
            logger.info("\n剪枝: {}", method.getName());
            logger.info("  剪枝前出边数: {}", beforeEdges);
            logger.info("  剪枝后出边数: {}", result.remainingEdges);
            logger.info("  删除边数: {}", result.removedEdges);
            logger.info("  剪枝率: {:.2f}%", result.getPruneRate());
            
            totalOriginal += result.originalEdges;
            totalRemaining += result.remainingEdges;
            totalRemoved += result.removedEdges;
        }
        
        System.out.println("\n================================================================================");
        System.out.println("剪枝完成统计:");
        System.out.println("  原始总边数: " + totalOriginal);
        System.out.println("  保留边数: " + totalRemaining);
        System.out.println("  删除边数: " + totalRemoved);
        System.out.println("  总剪枝率: " + String.format("%.2f%%", (totalRemoved * 100.0 / totalOriginal)));
        System.out.println("  保守策略保留数: " + pruner.getConservativeCount() + 
                " (" + String.format("%.2f%%", (pruner.getConservativeCount() * 100.0 / totalRemaining)) + ")");
        System.out.println("  调用图总边数（剪枝后）: " + callGraph.getEdgeCount());
        System.out.println("================================================================================");
        
        logger.info("剪枝完成统计:");
        logger.info("  原始总边数: {}", totalOriginal);
        logger.info("  保留边数: {}", totalRemaining);
        logger.info("  删除边数: {}", totalRemoved);
        logger.info("  总剪枝率: {:.2f}%", (totalRemoved * 100.0 / totalOriginal));
        logger.info("  保守策略保留数: {} ({:.2f}%)", 
                pruner.getConservativeCount(),
                (pruner.getConservativeCount() * 100.0 / totalRemaining));
        logger.info("  调用图总边数（剪枝后）: {}", callGraph.getEdgeCount());
    }
    
    /**
     * 清理死节点（Dead Code Elimination）
     */
    private void removeDeadNodes(CallGraph callGraph, Set<SootMethod> entryPoints) {
        logger.info("\n================================================================================");
        logger.info("开始清理死节点（Dead Code Elimination）");
        logger.info("================================================================================");
        
        int beforeEdges = callGraph.getEdgeCount();
        Set<SootMethod> beforeNodes = callGraph.getAllMethods();
        int beforeNodeCount = beforeNodes.size();
        
        CallGraphPruner pruner = new CallGraphPruner(callGraph, sinkRegistry);
        CallGraphPruner.DeadNodeResult result = pruner.removeDeadNodes(entryPoints);
        
        int afterEdges = callGraph.getEdgeCount();
        int afterNodeCount = callGraph.getAllMethods().size();
        
        System.out.println("\n════════════════════════════════════════════════════════════");
        System.out.println("死节点清理完成:");
        System.out.println("  原始节点数: " + beforeNodeCount);
        System.out.println("  原始边数: " + beforeEdges);
        System.out.println("  删除节点数: " + result.removedNodes + 
                " (" + String.format("%.2f%%", result.getNodeRemovalRate()) + ")");
        System.out.println("  删除边数: " + result.removedEdges);
        System.out.println("  剩余节点数: " + afterNodeCount);
        System.out.println("  剩余边数: " + afterEdges);
        System.out.println("════════════════════════════════════════════════════════════");
        
        logger.info("死节点清理完成:");
        logger.info("  原始节点数: {}", beforeNodeCount);
        logger.info("  原始边数: {}", beforeEdges);
        logger.info("  删除节点数: {} ({:.2f}%)", result.removedNodes, result.getNodeRemovalRate());
        logger.info("  删除边数: {}", result.removedEdges);
        logger.info("  剩余节点数: {}", afterNodeCount);
        logger.info("  剩余边数: {}", afterEdges);
        
        // 🔥 新增：输出边类型统计
        printEdgeTypeStatistics(callGraph);
    }
    
    /**
     * 输出边类型统计（用于分析优化空间）
     */
    private void printEdgeTypeStatistics(CallGraph callGraph) {
        System.out.println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("  调用图边类型统计");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        
        CallGraph.CallGraphStats stats = callGraph.getStats();
        Map<CallGraph.CallType, Integer> edgesByType = stats.getEdgeCountByType();
        
        System.out.println("\n【按调用类型统计】");
        int total = stats.getEdgeCount();
        edgesByType.entrySet().stream()
                .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
                .forEach(e -> {
                    System.out.println(String.format("  %s: %d (%.2f%%)",
                            e.getKey(), e.getValue(), (e.getValue() * 100.0 / total)));
                });
        
        System.out.println("\n总边数: " + total);
        System.out.println("总节点数: " + stats.getMethodCount());
        System.out.println("平均出度: " + String.format("%.2f", (total * 1.0 / stats.getMethodCount())));
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        
        logger.info("边类型统计: {}", edgesByType);
        
        // 记录纯函数过滤统计到日志
        PureFunctionFilter.FilterStatistics pureStats = pureFunctionFilter.getStatistics();
        logger.info("纯函数过滤统计: {}", pureStats);
    }
    
    /**
     * 判断方法是否属于应用程序类（非JDK、非第三方库的核心类）
     * 
     * @param method 方法
     * @return true=应用程序类，false=JDK/核心库类
     */
    private boolean isApplicationClass(SootMethod method) {
        if (method == null) {
            return false;
        }
        
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        
        // ✅ 方法级白名单：只允许特定的危险 JDK 方法
        // URLDNS 链：URL.hashCode → URLStreamHandler.hashCode → getHostAddress → InetAddress.getByName
        if (className.equals("java.net.URL") && methodName.equals("hashCode")) {
            return true;
        }
        
        if (className.equals("java.net.URLStreamHandler") && 
            (methodName.equals("hashCode") || methodName.equals("getHostAddress"))) {
            return true;
        }
        
        if (className.startsWith("java.net.InetAddress") && methodName.equals("getByName")) {
            return true;
        }
        
        // 反射链相关（CC3等）
        if (className.equals("java.lang.reflect.Method") ||
            className.equals("java.lang.reflect.Constructor") ||
            className.equals("java.lang.Class")) {
            return true;
        }
        
        // 其他已知 gadget 链类（可按需扩展）
        if (className.equals("java.beans.beancontext.BeanContextSupport")) {
            return true;
        }
        
        // ❌ 其他 JDK 核心类（包括 URL.equals、URL.sameFile 等）
        if (className.startsWith("java.") || 
            className.startsWith("javax.") ||
            className.startsWith("sun.") ||
            className.startsWith("com.sun.") ||
            className.startsWith("jdk.")) {
            return false;
        }
        
        // ✅ 应用程序类（包括 gadget 库，如 commons-collections）
        return true;
    }
    
    /**
     * 🆕 检查方法是否是反序列化入口（source）
     * 
     * 反序列化入口即使是 JDK 类也应该被视为可控，因为：
     * 1. readObject/readExternal 是反序列化的起点
     * 2. 攻击者可以控制反序列化的数据
     * 3. 典型例子：AnnotationInvocationHandler.readObject
     */
    private boolean isSerializationEntry(SootMethod method) {
        if (method == null) {
            return false;
        }
        
        String methodName = method.getName();
        
        // readObject(ObjectInputStream)
        if (methodName.equals("readObject") && 
            method.getParameterCount() == 1 &&
            method.getParameterType(0).toString().equals("java.io.ObjectInputStream")) {
            return true;
        }
        
        // readExternal(ObjectInput)
        if (methodName.equals("readExternal") && 
            method.getParameterCount() == 1 &&
            method.getParameterType(0).toString().equals("java.io.ObjectInput")) {
            return true;
        }
        
        // readResolve()
        if (methodName.equals("readResolve") && method.getParameterCount() == 0) {
            return true;
        }
        
        // readObjectNoData()
        if (methodName.equals("readObjectNoData") && method.getParameterCount() == 0) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 🔥 检查反射方法能否将污点传播给目标方法
     * 
     * 反射调用的污点传播规则：
     * - Method.invoke(obj, args[]) → target.method(param1, param2, ...)
     *   - 如果 invoke 的 args 参数（param[1]）可控 → target 的所有参数可控
     *   - 如果 invoke 的 obj 参数（param[0]）可控 → target 的 this 可控
     * 
     * @param reflectionMethod 反射方法（如 Method.invoke）
     * @param reflectionTaint 反射方法的污点
     * @param target 目标方法（如 Runtime.exec）
     * @param targetTaint 目标方法需要的污点
     * @return true=可以传播，false=不能传播
     */
    private boolean canReflectionPropagateTaint(
            SootMethod reflectionMethod, 
            MethodLevelTaint reflectionTaint,
            SootMethod target, 
            MethodLevelTaint targetTaint) {
        
        String reflectionSig = reflectionMethod.getSignature();
        
        // Method.invoke(Object obj, Object[] args)
        if (reflectionSig.contains("<java.lang.reflect.Method: java.lang.Object invoke(")) {
            // 检查 obj 参数（param[0]）是否可控
            boolean objControllable = reflectionTaint.getParamTaints().getOrDefault(0, false);
            
            // 检查 args 参数（param[1]）是否可控
            boolean argsControllable = reflectionTaint.getParamTaints().getOrDefault(1, false);
            
            // 如果目标需要 this 可控，检查 obj 是否可控
            if (targetTaint.isThisTainted() && !objControllable) {
                return false;
            }
            
            // 如果目标需要参数可控，检查 args 是否可控
            if (!targetTaint.getParamTaints().isEmpty() && !argsControllable) {
                return false;
            }
            
            return true;
        }
        
        // Constructor.newInstance(Object[] args)
        if (reflectionSig.contains("<java.lang.reflect.Constructor: java.lang.Object newInstance(")) {
            // 检查 args 参数（param[0]）是否可控
            boolean argsControllable = reflectionTaint.getParamTaints().getOrDefault(0, false);
            
            // 构造函数不需要 this 可控（新对象）
            // 如果目标需要参数可控，检查 args 是否可控
            if (!targetTaint.getParamTaints().isEmpty() && !argsControllable) {
                return false;
            }
            
            return true;
        }
        
        // Class.newInstance() - 无参构造
        if (reflectionSig.equals("<java.lang.Class: java.lang.Object newInstance()>")) {
            // 无参构造函数，只要反射方法的 this 可控即可
            return reflectionTaint.isThisTainted();
        }
        
        // 其他反射方法：保守地要求反射方法有污点
        return reflectionTaint.isThisTainted() || !reflectionTaint.getParamTaints().isEmpty();
    }
    
    /**
     * 🔥 为反射目标方法计算污点需求
     * 
     * 根据目标方法的语义，决定它需要哪些参数/this可控
     * 
     * @param cs 调用点
     * @param target 目标方法（反射调用的实际目标）
     * @return 目标方法需要的污点
     */
    private MethodLevelTaint computeTargetTaint(CallSite cs, SootMethod target) {
        MethodLevelTaint taint = new MethodLevelTaint();
        
        // 先创建一个临时的全污点，用于检查是否是 sink
        MethodLevelTaint tempTaint = new MethodLevelTaint();
        tempTaint.setThisTainted(true);
        for (int i = 0; i < target.getParameterCount(); i++) {
            tempTaint.setParamTaint(i, true);
        }
        
        boolean isSink = sinkRegistry.isSinkWithTaint(target, tempTaint);
        
        if (isSink) {
            // 如果是 sink，根据 sink 的语义设置污点需求
            String targetName = target.getName();
            
            // exec/loadClass/forName 等：需要参数可控
            if (targetName.equals("exec") || targetName.equals("loadClass") || 
                targetName.equals("forName") || targetName.equals("getMethod") ||
                targetName.equals("getDeclaredMethod")) {
                
                // 需要第一个参数可控
                if (target.getParameterCount() > 0) {
                    taint.setParamTaint(0, true);
                }
            }
            // newInstance：需要 this 或参数可控
            else if (targetName.equals("newInstance")) {
                if (!target.isStatic() && target.getParameterCount() == 0) {
                    // Class.newInstance() - 需要 this 可控
                    taint.setThisTainted(true);
                } else if (target.getParameterCount() > 0) {
                    // Constructor.newInstance(args) - 需要参数可控
                    taint.setParamTaint(0, true);
                }
            }
            // 其他 sink：保守地要求所有参数可控
            else if (target.getParameterCount() > 0) {
                for (int i = 0; i < target.getParameterCount(); i++) {
                    taint.setParamTaint(i, true);
                }
            } else if (!target.isStatic()) {
                // 无参非静态方法，需要 this 可控
                taint.setThisTainted(true);
            }
        } else {
            // 不是 sink，保守地传播所有污点
            if (!target.isStatic()) {
                taint.setThisTainted(true);
            }
            for (int i = 0; i < target.getParameterCount(); i++) {
                taint.setParamTaint(i, true);
            }
        }
        
        return taint;
    }
}

