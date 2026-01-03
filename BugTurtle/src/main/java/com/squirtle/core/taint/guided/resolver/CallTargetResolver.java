package com.squirtle.core.taint.guided.resolver;

import com.squirtle.core.callgraph.PureFunctionFilter;
import com.squirtle.core.sink.FlashAlignedSinkRegistry;
import com.squirtle.core.taint.guided.model.*;
import soot.*;
import soot.jimple.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * 调用目标解析器
 * 
 * 实现可控性驱动的调用目标解析，包括：
 * - CHA精化（基于类型约束）
 * - 动态代理处理
 * - 反射调用处理（带sink兜底）
 * - Lambda/invokedynamic处理
 */
public class CallTargetResolver {
    private static final Logger logger = LoggerFactory.getLogger(CallTargetResolver.class);
    
    /** Flash对齐的Sink注册表（用于反射兜底） */
    private final FlashAlignedSinkRegistry sinkRegistry;
    
    /** 纯函数过滤器（在CHA阶段过滤） */
    private final PureFunctionFilter pureFunctionFilter;
    
    // CHA缓存
    private final Map<String, Set<SootMethod>> chaCache = new HashMap<>();
    private final Map<SootClass, List<SootClass>> subtypeCache = new HashMap<>();
    private final Map<SootClass, List<SootClass>> implCache = new HashMap<>();
    
    private static final int MAX_CHA_TARGETS = 100;
    
    /**
     * 构造函数
     * 
     * @param sinkRegistry Sink注册表（用于反射调用的保守兜底）
     */
    public CallTargetResolver(FlashAlignedSinkRegistry sinkRegistry) {
        this.sinkRegistry = Objects.requireNonNull(sinkRegistry, "sinkRegistry cannot be null");
        this.pureFunctionFilter = new PureFunctionFilter();
    }
    
    /**
     * 解析调用目标
     */
    public Set<SootMethod> resolveTargets(CallSite cs) {
        InvokeExpr invoke = cs.getInvoke();
        SootMethod declaredMethod = invoke.getMethod();
        
        // 1. 静态/特殊调用
        if (invoke instanceof StaticInvokeExpr || invoke instanceof SpecialInvokeExpr) {
            return Collections.singleton(declaredMethod);
        }
        
        // 2. 反射调用（带sink兜底的保守处理）
        if (isReflectionCall(declaredMethod)) {
            return resolveReflectionWithFallback(cs, declaredMethod);
        }
        
        // 3. Lambda/invokedynamic
        if (invoke instanceof DynamicInvokeExpr) {
            return resolveLambda((DynamicInvokeExpr) invoke, cs);
        }
        
        // 4. 精化CHA（基础解析）
        Set<SootMethod> chaTargets = refinedCHA(invoke, cs.getTypeInfo());
        Set<SootMethod> targets = new HashSet<>(chaTargets);
        
        // 5. 动态代理（额外添加InvocationHandler.invoke）
        if (isDynamicProxyCall(cs)) {
            Set<SootMethod> proxyTargets = resolveDynamicProxy();
            targets.addAll(proxyTargets);
        }
        
        // 🔥 6. 纯函数过滤（在CHA阶段过滤，效果最好）
        int beforeFilter = targets.size();
        targets.removeIf(method -> pureFunctionFilter.canSafelyFilter(method));
        int afterFilter = targets.size();
        
        if (beforeFilter != afterFilter) {
            logger.debug("CHA纯函数过滤: {} → {} (过滤{}个)",
                    beforeFilter, afterFilter, beforeFilter - afterFilter);
        }
        
        return targets;
    }
    
    /**
     * 精化CHA（基于类型约束）
     */
    private Set<SootMethod> refinedCHA(InvokeExpr invoke, TypeConstraints typeInfo) {
        Set<SootMethod> targets = new HashSet<>();
        SootMethod declaredMethod = invoke.getMethod();
        Hierarchy hierarchy = Scene.v().getActiveHierarchy();
        
        // 防御：如果类型信息为空，使用声明类型
        if (typeInfo.getPossibleTypes() == null || typeInfo.getPossibleTypes().isEmpty()) {
            Type declaredType = declaredMethod.getDeclaringClass().getType();
            typeInfo = new TypeConstraints(
                Collections.singleton(declaredType),
                TypePrecision.DECLARED_TYPE
            );
        }
        
        if (typeInfo.getPrecision() == TypePrecision.EXACT || 
            typeInfo.getPrecision() == TypePrecision.FIELD_TYPE) {
            // 精确类型：只在约束的类型中查找
            boolean hasInterface = false;
            
            for (Type type : typeInfo.getPossibleTypes()) {
                if (!(type instanceof RefType)) continue;
                
                SootClass cls = ((RefType) type).getSootClass();
                if (cls.isPhantom()) continue;
                
                // 如果是接口，需要遍历所有实现类（不能直接resolveConcreteDispatch）
                if (cls.isInterface()) {
                    hasInterface = true;
                    
                    // 🔥 对低价值接口方法限制实现类数量
                    int maxImpl = isLowValueInterfaceMethod(declaredMethod) ? 10 : MAX_CHA_TARGETS;
                    int count = 0;
                    
                    for (SootClass impl : getCachedImplementers(cls)) {
                        if (impl.isPhantom() || impl.isAbstract()) continue;
                        if (count >= maxImpl) break;
                        
                        try {
                            SootMethod resolved = hierarchy.resolveConcreteDispatch(impl, declaredMethod);
                            if (resolved != null && !resolved.isAbstract()) {
                                targets.add(resolved);
                                count++;
                            }
                        } catch (Exception e) {
                            // 忽略解析失败
                        }
                    }
                } else {
                    // 具体类或抽象类：直接dispatch
                    try {
                        SootMethod resolved = hierarchy.resolveConcreteDispatch(cls, declaredMethod);
                        if (resolved != null && !resolved.isAbstract()) {
                            targets.add(resolved);
                        }
                    } catch (Exception e) {
                        // 忽略解析失败
                    }
                }
            }
            
            // 如果有接口且目标过多，需要截断
            if (hasInterface && targets.size() > MAX_CHA_TARGETS) {
                logger.warn("FIELD_TYPE interface targets overflow: {}, truncating to {}",
                        targets.size(), MAX_CHA_TARGETS);
                targets = truncateTargets(targets);
            }
        } else {
            // 保守：声明类型的所有子类
            SootClass declaredClass = declaredMethod.getDeclaringClass();
            
            if (declaredClass.isInterface()) {
                // 🔥 优化：对低价值接口方法，限制实现类数量
                int maxImpl = MAX_CHA_TARGETS;
                if (isLowValueInterfaceMethod(declaredMethod)) {
                    maxImpl = 10;  // 大幅减少低价值方法的目标数
                }
                
                int count = 0;
                for (SootClass impl : getCachedImplementers(declaredClass)) {
                    if (impl.isPhantom() || impl.isAbstract()) continue;
                    if (count >= maxImpl) break;  // 提前截断
                    
                    try {
                        SootMethod resolved = hierarchy.resolveConcreteDispatch(impl, declaredMethod);
                        if (resolved != null && !resolved.isAbstract()) {
                            targets.add(resolved);
                            count++;
                        }
                    } catch (Exception e) {
                        // 忽略解析失败
                    }
                }
            } else {
                List<SootClass> classesToCheck = new ArrayList<>();
                classesToCheck.add(declaredClass);
                classesToCheck.addAll(getCachedSubclasses(declaredClass));
                
                for (SootClass cls : classesToCheck) {
                    if (cls.isPhantom() || cls.isAbstract()) continue;
                    
                    try {
                        SootMethod resolved = hierarchy.resolveConcreteDispatch(cls, declaredMethod);
                        if (resolved != null && !resolved.isAbstract()) {
                            targets.add(resolved);
                        }
                    } catch (Exception e) {
                        // 忽略解析失败
                    }
                }
            }
        }
        
        // 截断（智能排序）
        // 对于泛型基类（Object、Serializable等），不截断，保留所有目标
        SootClass declaredClass = invoke.getMethod().getDeclaringClass();
        boolean isGenericBase = isGenericBaseClass(declaredClass);
        
        if (!isGenericBase && targets.size() > MAX_CHA_TARGETS) {
            logger.warn("CHA targets overflow for {}: {}, truncating to {}",
                    invoke, targets.size(), MAX_CHA_TARGETS);
            targets = truncateTargets(targets);
        } else if (isGenericBase && targets.size() > MAX_CHA_TARGETS) {
            logger.info("Generic base class {}.{} has {} targets, keeping all (no truncation)",
                    declaredClass.getName(), invoke.getMethod().getName(), targets.size());
        }
        
        return targets;
    }
    
    /**
     * 智能截断CHA结果（优先保留非JDK类）
     */
    private Set<SootMethod> truncateTargets(Set<SootMethod> targets) {
        List<SootMethod> sorted = new ArrayList<>(targets);
        
        // 智能排序：非JDK类优先
        sorted.sort((a, b) -> {
            boolean aIsJDK = isJDKClass(a.getDeclaringClass());
            boolean bIsJDK = isJDKClass(b.getDeclaringClass());
            
            if (!aIsJDK && bIsJDK) return -1;  // 应用类优先
            if (aIsJDK && !bIsJDK) return 1;
            
            // 同类型：稳定排序
            return a.getSignature().compareTo(b.getSignature());
        });
        
        return new HashSet<>(sorted.subList(0, MAX_CHA_TARGETS));
    }
    
    /**
     * 判断是否是动态代理调用（完整的三条件检查 + 方法级优化）
     * 
     * 根据论文，必须同时满足：
     * 1. InterfaceCall: 调用点是接口调用
     * 2. Base可控: receiver对象是tainted
     * 3. NoCast: receiver对象没有被cast
     * 4. 高价值方法: 排除明显不可能在gadget中被利用的方法（性能优化）
     */
    private boolean isDynamicProxyCall(CallSite cs) {
        // 条件1: InterfaceCall
        if (!(cs.getInvoke() instanceof InterfaceInvokeExpr)) {
            return false;
        }
        
        // 条件2: Base可控
        if (!cs.isBaseTainted()) {
            return false;
        }
        
        // 条件3: NoCast（论文核心条件）
        if (cs.baseHasCast()) {
            // Proxy对象继承自java.lang.reflect.Proxy，cast会抛ClassCastException
            return false;
        }
        
        // 条件4: 高价值方法（过滤明显无关的方法）
        // ProxyImplementation和NoCast已经严格过滤Handler和调用点
        // 这里进一步过滤掉不太可能在gadget中被利用的方法
        SootMethod method = cs.getInvoke().getMethod();
        if (isLowValueProxyMethod(method)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * 判断是否是高价值的动态代理接口
     * 
     * 包括所有在gadget链中可能被代理的接口
     * 通过ProxyImplementation和NoCast已经做了严格过滤，这里可以适当宽松
     */
    private boolean isHighValueProxyInterface(SootClass cls) {
        if (!cls.isInterface()) return false;
        
        String name = cls.getName();
        
        // 1. 集合接口（最常见的动态代理目标）
        if (name.startsWith("java.util.") && cls.isInterface()) {
            // Map, List, Set, Collection, Queue, Deque, Iterator等
            return true;
        }
        
        // 2. Templates接口（TemplatesImpl代理）
        if (name.equals("javax.xml.transform.Templates")) {
            return true;
        }
        
        // 3. Annotation接口（AnnotationInvocationHandler）
        if (name.startsWith("java.lang.annotation.") || 
            name.startsWith("javax.annotation.")) {
            return true;
        }
        
        // 4. Remote接口（RMI代理）
        if (name.startsWith("java.rmi.") && cls.isInterface()) {
            return true;
        }
        
        // 5. 反射接口
        if (name.startsWith("java.lang.reflect.") && cls.isInterface()) {
            return true;
        }
        
        // 6. Commons Collections接口（gadget链常用）
        if (name.startsWith("org.apache.commons.collections.") && cls.isInterface()) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 解析动态代理调用（ProxyImplementation过滤）
     * 
     * 只连接满足ProxyImplementation条件的Handler：
     * - 实现InvocationHandler
     * - 实现Serializable
     */
    private Set<SootMethod> resolveDynamicProxy() {
        Set<SootMethod> targets = new HashSet<>();
        
        try {
            SootClass handlerInterface = Scene.v().getSootClass(
                "java.lang.reflect.InvocationHandler"
            );
            
            String invokeSubsig = "java.lang.Object invoke(java.lang.Object," +
                                  "java.lang.reflect.Method,java.lang.Object[])";
            
            Hierarchy hierarchy = Scene.v().getActiveHierarchy();
            for (SootClass impl : hierarchy.getImplementersOf(handlerInterface)) {
                if (impl.isAbstract() || impl.isPhantom()) continue;
                
                // 🔥 ProxyImplementation检查（论文条件1）
                if (!isValidProxyHandler(impl)) {
                    continue;
                }
                
                try {
                    SootMethod resolved = hierarchy.resolveConcreteDispatch(
                        impl, 
                        handlerInterface.getMethod(invokeSubsig)
                    );
                    
                    if (resolved != null) {
                        targets.add(resolved);
                    }
                } catch (Exception e) {
                    // 忽略单个实现的解析失败
                }
            }
        } catch (Exception e) {
            // 如果InvocationHandler不存在，返回空集
            logger.debug("Failed to resolve dynamic proxy: {}", e.getMessage());
        }
        
        return targets;
    }
    
    /**
     * 判断是否是反射调用
     */
    private boolean isReflectionCall(SootMethod method) {
        String sig = method.getSignature();
        return sig.contains("java.lang.reflect.Method: java.lang.Object invoke(") ||
               sig.contains("java.lang.reflect.Constructor: java.lang.Object newInstance(") ||
               sig.equals("<java.lang.Class: java.lang.Object newInstance()>");
    }
    
    /**
     * 解析反射调用（带sink兜底）
     * 
     * <p><b>策略</b>：
     * <ol>
     *   <li>保留Method.invoke本身（保持调用图连续性）</li>
     *   <li>尝试推断真实目标（暂未实现，留待后续优化）</li>
     *   <li>如果无法推断 → fallback到所有30个Flash sink</li>
     * </ol>
     * 
     * <p><b>优势</b>：
     * <ul>
     *   <li>边数可控：每个反射调用最多31条边（1个invoke + 30个sink）</li>
     *   <li>不丢失gadget链：即使无法精确推断，也能连接到可能的sink</li>
     *   <li>对齐Flash：sink列表与Flash完全一致</li>
     * </ul>
     * 
     * @param cs 调用点
     * @param reflectionMethod 反射方法（Method.invoke等）
     * @return 可能的目标方法集合
     */
    private Set<SootMethod> resolveReflectionWithFallback(CallSite cs, SootMethod reflectionMethod) {
        Set<SootMethod> targets = new HashSet<>();
        
        // ✅ 关键：只返回反射方法本身，让它进入worklist
        // 不在这里直接连接到sinks，而是在反射方法被处理时应用sink兜底
        targets.add(reflectionMethod);
        
        // 尝试推断真实目标（目前总是空，因为污点分析的局限性）
        Set<SootMethod> inferredTargets = tryInferReflectionTarget(cs);
        if (!inferredTargets.isEmpty()) {
            targets.addAll(inferredTargets);
            logger.debug("反射调用推断成功：{} → {} 个目标",
                    cs.getInvoke(), inferredTargets.size());
        }
        
        logger.debug("反射调用解析：{} → 反射方法本身（将在worklist中处理sink兜底）",
                cs.getInvoke());
        
        return targets;
    }
    
    /**
     * 尝试推断反射调用的真实目标
     * 
     * <p><b>⚠️ 污点分析的固有局限性</b>：
     * <p>在污点分析中，我们只能看到<b>可控性</b>（是否tainted），而<b>看不到具体值</b>：
     * <pre>
     * Method method = cls.getMethod(methodName, ...);  // methodName是tainted
     * method.invoke(target, args);
     * 
     * // 污点分析能知道的：
     * // ✓ methodName是可控的（tainted）
     * // ✗ methodName的具体值是什么（"exec"? "toString"? 不知道！）
     * </pre>
     * 
     * <p><b>为什么精确推断不可行</b>：
     * <ul>
     *   <li>污点分析只追踪可控性，不追踪具体值</li>
     *   <li>精确推断需要符号执行或具体执行</li>
     *   <li>常量传播只适用于字面量（非常罕见）</li>
     * </ul>
     * 
     * <p><b>正确的策略</b>：使用sink兜底（连接到30个Flash sink）
     * 
     * @param cs 调用点
     * @return 推断出的目标方法集合（总是空，因为污点分析无法推断具体值）
     */
    private Set<SootMethod> tryInferReflectionTarget(CallSite cs) {
        InvokeExpr invoke = cs.getInvoke();
        SootMethod reflectionMethod = invoke.getMethod();
        
        String sig = reflectionMethod.getSignature();
        
        // 特殊处理：Constructor.newInstance
        if (sig.contains("java.lang.reflect.Constructor") && sig.contains("newInstance")) {
            return inferConstructorNewInstanceTargets(cs);
        }
        
        // 特殊处理：Method.invoke - 使用保守的sink兜底策略
        if (sig.contains("java.lang.reflect.Method") && sig.contains("invoke")) {
            return inferMethodInvokeTargets(cs);
        }
        
        // 其他反射方法暂不支持精确推断
        return Collections.emptySet();
    }
    
    /**
     * 推断Constructor.newInstance的目标构造函数
     * 
     * <p>策略：
     * <ol>
     *   <li>分析Constructor对象的类型约束（来自base的类型）</li>
     *   <li>如果能推断出具体类，查找匹配的构造函数</li>
     *   <li>否则，应用CHA到所有应用程序类的构造函数（保守但合理）</li>
     * </ol>
     */
    private Set<SootMethod> inferConstructorNewInstanceTargets(CallSite cs) {
        Set<SootMethod> targets = new HashSet<>();
        
        // 🆕 VSA优化：使用值集信息精确化目标
        // 污点驱动筛选策略（Flash对齐，修正版 + VSA增强）：
        // 0. 🆕 如果有值集信息（可能的Class类型），只搜索这些类的构造函数
        // 1. Constructor对象来自攻击载荷（tainted），攻击者控制调用哪个构造函数
        // 2. ❌ 删除：不检查类本身是否Serializable（因为它是运行时创建的，不需要序列化）
        // 3. ✅ 保留：只保留参数类型都是Serializable的构造函数（传播约束）
        // 4. ✅ 保留：对候选构造函数进行污点传播分析，只保留能接收污点的
        // 5. 不设limit（保证soundness，不漏掉任何可能的gadget）
        //
        // 重要：TrAXFilter不是Serializable，但TrAXFilter(TemplatesImpl)的参数是Serializable
        //      这种情况必须保留，因为TemplatesImpl可以通过反序列化传递
        
        // 提前检查：args参数是否tainted？
        List<Boolean> argsTainted = cs.getArgsTainted();
        if (argsTainted == null || argsTainted.isEmpty() || !argsTainted.get(0)) {
            // args不可控 → 无法传递污点到任何构造函数
            logger.debug("Constructor.newInstance: args参数不可控，跳过推断");
            return Collections.emptySet();
        }
        
        // 构造Constructor.newInstance的入口污点
        MethodLevelTaint entryTaint = new MethodLevelTaint();
        entryTaint.setParamTaint(0, true);  // args参数是tainted
        
        int totalConstructors = 0;
        int filteredNonSerializableParams = 0;
        int filteredNoTaint = 0;
        
        // 🆕 VSA：尝试从类型约束中提取可能的Class类型
        Set<Type> possibleClassTypes = extractPossibleClassTypes(cs);
        
        Set<SootClass> candidateClasses = new HashSet<>();
        if (possibleClassTypes != null && !possibleClassTypes.isEmpty()) {
            // 🚀 VSA路径：只搜索可能的类
            logger.info("🎯 VSA优化: 检测到{}个可能的类型，使用精确搜索", possibleClassTypes.size());
            for (Type type : possibleClassTypes) {
                if (type instanceof soot.RefType) {
                    SootClass cls = ((soot.RefType) type).getSootClass();
                    if (!cls.isPhantom() && !cls.isInterface()) {
                        candidateClasses.add(cls);
                    }
                }
            }
        } else {
            // 保守路径：遍历所有类
            logger.debug("未检测到值集信息，使用全局搜索");
            for (SootClass cls : Scene.v().getClasses()) {
                if (!cls.isPhantom() && !cls.isInterface()) {
                    candidateClasses.add(cls);
                }
            }
        }
        
        logger.info("候选类数量: {}", candidateClasses.size());
        
        // 遍历候选类的构造函数
        for (SootClass cls : candidateClasses) {
            
            // 🔥 优化：跳过Object类（无意义的边）
            if (cls.getName().equals("java.lang.Object")) {
                continue;
            }
            
            for (SootMethod method : cls.getMethods()) {
                if (method.getName().equals("<init>") && !method.isPhantom()) {
                    totalConstructors++;
                    
                    // ✅ Flash过滤1：参数类型必须都是Serializable（传播约束）
                    if (!allParametersSerializable(method)) {
                        filteredNonSerializableParams++;
                        continue;
                    }
                    
                    // 关键：真正的污点传播分析
                    // 计算目标构造函数的入口污点
                    MethodLevelTaint targetTaint = computeTargetTaintForConstructorNewInstance(
                        entryTaint, method
                    );
                    
                    // 只保留能接收污点的构造函数
                    // 对于构造函数：检查参数污点（构造函数没有this）
                    if (targetTaint != null && !targetTaint.getParamTaints().isEmpty()) {
                        // 检查是否至少有一个参数是tainted
                        boolean hasParamTaint = false;
                        for (Boolean tainted : targetTaint.getParamTaints().values()) {
                            if (tainted != null && tainted) {
                                hasParamTaint = true;
                                break;
                            }
                        }
                        if (hasParamTaint) {
                            targets.add(method);
                        } else {
                            filteredNoTaint++;
                        }
                    } else {
                        filteredNoTaint++;
                    }
                }
            }
        }
        
        logger.info("Constructor.newInstance过滤统计: 候选类={}, 总构造函数={}, 过滤非Serializable参数={}, 过滤无污点传播={}, 最终保留={}", 
                    candidateClasses.size(), totalConstructors, filteredNonSerializableParams, filteredNoTaint, targets.size());
        
        return targets;
    }
    
    /**
     * 计算Constructor.newInstance的目标污点
     * 
     * <p><b>污点传播规则</b>：
     * <pre>
     * Constructor.newInstance(Object[] args)  // args是tainted
     *     ↓ 污点传播
     * TargetConstructor(param0, param1, ...)
     * 
     * 映射关系：
     * - newInstance的param0（args数组） → 目标构造函数的所有参数（保守策略）
     * </pre>
     * 
     * <p><b>示例</b>：
     * <pre>
     * // 如果args数组是tainted
     * Constructor<TrAXFilter> c = ...;
     * c.newInstance(args);  // args是tainted
     * 
     * // 目标构造函数：TrAXFilter(Templates templates)
     * // targetTaint.paramTaint[0] = true （templates参数接收污点）
     * // targetTaint.hasTaint() = true → 保留此构造函数
     * 
     * // 目标构造函数：Runtime()  // 无参构造
     * // targetTaint中没有参数
     * // targetTaint.hasTaint() = false → 过滤掉
     * </pre>
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
        // 保守策略：如果args数组是tainted，则目标构造函数的所有参数都可能是tainted
        if (entryTaint.isParamTainted(0)) {
            for (int i = 0; i < targetConstructor.getParameterCount(); i++) {
                targetTaint.setParamTaint(i, true);
            }
        }
        
        return targetTaint;
    }
    
    /**
     * 解析Lambda/invokedynamic调用
     */
    private Set<SootMethod> resolveLambda(DynamicInvokeExpr dynInvoke, CallSite cs) {
        Set<SootMethod> targets = new HashSet<>();
        
        SootMethod callerMethod = cs.getCaller();
        if (callerMethod != null) {
            SootClass containingClass = callerMethod.getDeclaringClass();
            
            // 查找所有lambda方法
            for (SootMethod m : containingClass.getMethods()) {
                if (m.getName().startsWith("lambda$") || 
                    m.getName().contains("$lambda$")) {
                    targets.add(m);
                }
            }
        }
        
        return targets;
    }
    
    /**
     * 缓存子类查询
     */
    private List<SootClass> getCachedSubclasses(SootClass cls) {
        return subtypeCache.computeIfAbsent(cls, k -> {
            try {
                Hierarchy hierarchy = Scene.v().getActiveHierarchy();
                return new ArrayList<>(hierarchy.getSubclassesOf(k));
            } catch (Exception e) {
                return Collections.emptyList();
            }
        });
    }
    
    /**
     * 缓存实现类查询
     */
    private List<SootClass> getCachedImplementers(SootClass iface) {
        return implCache.computeIfAbsent(iface, k -> {
            try {
                Hierarchy hierarchy = Scene.v().getActiveHierarchy();
                return new ArrayList<>(hierarchy.getImplementersOf(k));
            } catch (Exception e) {
                return Collections.emptyList();
            }
        });
    }
    
    /**
     * 判断是否是JDK类
     */
    private boolean isJDKClass(SootClass cls) {
        String name = cls.getName();
        return name.startsWith("java.") ||
               name.startsWith("javax.") ||
               name.startsWith("sun.") ||
               name.startsWith("com.sun.");
    }
    
    /**
     * 检查类是否实现了Serializable接口（Flash对齐）
     * 
     * <p>反序列化约束：只有Serializable的类才能在反序列化攻击中被实例化
     * 
     * @param cls 要检查的类
     * @return true if 类实现了java.io.Serializable
     */
    private boolean isSerializableClass(SootClass cls) {
        try {
            // 获取Serializable接口（使用forceResolve确保加载）
            SootClass serializable = Scene.v().forceResolve("java.io.Serializable", SootClass.SIGNATURES);
            if (serializable == null) {
                // 如果找不到Serializable接口，保守地允许所有类
                logger.warn("无法找到java.io.Serializable接口，跳过Serializable检查");
                return true;
            }
            
            // 使用递归检查接口（isClassSubclassOfIncluding对接口不适用）
            return implementsInterface(cls, serializable);
        } catch (Exception e) {
            // 出错时保守地允许
            logger.debug("检查Serializable时出错: {}", e.getMessage());
            return true;
        }
    }
    
    /**
     * 递归检查类是否实现了指定接口
     * 
     * @param cls 要检查的类
     * @param targetInterface 目标接口
     * @return true if 类（或其父类/父接口）实现了目标接口
     */
    private boolean implementsInterface(SootClass cls, SootClass targetInterface) {
        if (cls == null) {
            return false;
        }
        
        // 检查直接实现的接口
        for (SootClass intf : cls.getInterfaces()) {
            if (intf.equals(targetInterface)) {
                return true;
            }
            // 递归检查父接口
            if (implementsInterface(intf, targetInterface)) {
                return true;
            }
        }
        
        // 检查父类
        if (cls.hasSuperclass()) {
            return implementsInterface(cls.getSuperclass(), targetInterface);
        }
        
        return false;
    }
    
    /**
     * 检查方法的所有参数类型是否都是Serializable（Flash对齐）
     * 
     * <p>传播约束：只有Serializable的参数才能通过反序列化传递污点
     * 
     * @param method 要检查的方法
     * @return true if 所有参数类型都是Serializable或基本类型
     */
    private boolean allParametersSerializable(SootMethod method) {
        if (method.getParameterCount() == 0) {
            // 无参构造函数总是允许
            return true;
        }
        
        try {
            SootClass serializable = Scene.v().forceResolve("java.io.Serializable", SootClass.SIGNATURES);
            
            if (serializable == null) {
                // 如果找不到Serializable接口，保守地允许
                logger.warn("无法找到java.io.Serializable接口，跳过参数Serializable检查");
                return true;
            }
            
            for (int i = 0; i < method.getParameterCount(); i++) {
                Type paramType = method.getParameterType(i);
                
                // 基本类型总是Serializable
                if (paramType instanceof PrimType) {
                    continue;
                }
                
                // 引用类型：检查是否是Serializable
                if (paramType instanceof RefType) {
                    SootClass paramClass = ((RefType) paramType).getSootClass();
                    
                    // 关键修复：如果参数是接口类型，允许通过
                    // 原因：接口的实际实现类可能是Serializable的（如Templates接口的TemplatesImpl实现）
                    // 在反序列化场景中，传递的是实现类对象，而不是接口本身
                    if (paramClass.isInterface()) {
                        continue;  // 接口类型参数：保守地允许通过
                    }
                    
                    // 具体类：检查是否Serializable
                    if (!implementsInterface(paramClass, serializable)) {
                        return false;  // 发现非Serializable的具体类参数
                    }
                } else if (paramType instanceof ArrayType) {
                    // 数组类型：基本类型数组或Object[]都认为是Serializable
                    // 这是保守策略，因为数组的元素可能是Serializable的
                    continue;
                } else {
                    // 其他类型（如NullType）保守地允许
                    continue;
                }
            }
            
            return true;  // 所有参数都通过检查
        } catch (Exception e) {
            // 出错时保守地允许
            return true;
        }
    }
    
    /**
     * 推断Method.invoke的目标方法
     * 
     * <p><b>保守策略</b>：
     * <ol>
     *   <li>连接到Flash定义的危险sink方法（Runtime.exec等）</li>
     *   <li>🆕 连接到目标库（application classes）的静态方法（如JavaAdapter.readAdapterObject）</li>
     * </ol>
     * 
     * <p>原因：反射调用的Method对象可能来自可序列化字段，攻击者可以控制它指向任意方法。
     * 对于gadget链，中间节点方法（如JavaAdapter.readAdapterObject）同样重要。
     */
    private Set<SootMethod> inferMethodInvokeTargets(CallSite cs) {
        Set<SootMethod> targets = new HashSet<>();
        
        // 检查Method.invoke的参数是否可控
        List<Boolean> argsTainted = cs.getArgsTainted();
        if (argsTainted == null || argsTainted.size() < 2) {
            return Collections.emptySet();
        }
        
        // Method.invoke(Object obj, Object... args)
        boolean objTainted = argsTainted.get(0);
        boolean argsTaintedFlag = argsTainted.get(1);
        
        if (!objTainted && !argsTaintedFlag) {
            return Collections.emptySet();
        }
        
        // 1. 添加危险的sink方法
        Set<SootMethod> allSinks = sinkRegistry.getAllSinkMethods();
        for (SootMethod sink : allSinks) {
            if (sink.getName().equals("<init>") || sink.isAbstract() || sink.isPhantom()) {
                continue;
            }
            if (isDangerousMethod(sink)) {
                targets.add(sink);
            }
        }
        
        // 🆕 2. 添加目标库（application classes）的静态方法
        // 原因：Rhino/BeanShell等库的gadget链中间节点（如JavaAdapter.readAdapterObject）
        //       是静态方法，可以被Method.invoke调用
        // 限制：只添加可能参与gadget的方法，避免调用图爆炸
        int addedAppMethods = 0;
        int maxAppMethods = 200;
        
        for (SootClass cls : Scene.v().getApplicationClasses()) {
            if (cls.isPhantom()) continue;
            
            for (SootMethod method : cls.getMethods()) {
                if (addedAppMethods >= maxAppMethods) break;
                
                // 只添加静态方法（非构造函数、非抽象）
                if (method.isStatic() && !method.isAbstract() && !method.isPhantom()
                    && !method.getName().equals("<init>") && !method.getName().equals("<clinit>")) {
                    
                    // 过滤明显无害的方法
                    if (isLikelyGadgetMethod(method)) {
                        targets.add(method);
                        addedAppMethods++;
                    }
                }
            }
            if (addedAppMethods >= maxAppMethods) break;
        }
        
        logger.debug("Method.invoke 目标推断: {} 个目标 (含 {} 个应用静态方法)", 
            targets.size(), addedAppMethods);
        
        return targets;
    }
    
    /**
     * 判断方法是否可能是gadget链的一部分
     * 保守策略：宁可多添加，不要漏掉
     */
    private boolean isLikelyGadgetMethod(SootMethod method) {
        String name = method.getName();
        
        // 1. 名称包含关键词的方法更可能是gadget
        if (name.contains("read") || name.contains("write") || name.contains("load") ||
            name.contains("create") || name.contains("get") || name.contains("invoke") ||
            name.contains("call") || name.contains("exec") || name.contains("run") ||
            name.contains("transform") || name.contains("convert") || name.contains("parse")) {
            return true;
        }
        
        // 2. 参数包含 ObjectInputStream 的方法（可能参与反序列化）
        for (soot.Type paramType : method.getParameterTypes()) {
            String typeName = paramType.toString();
            if (typeName.contains("ObjectInputStream") || typeName.contains("Scriptable") ||
                typeName.contains("Context") || typeName.contains("Class")) {
                return true;
            }
        }
        
        // 3. 返回值是 Object/Class 的方法（可能返回可控对象）
        String returnType = method.getReturnType().toString();
        if (returnType.equals("java.lang.Object") || returnType.equals("java.lang.Class")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 判断是否是真正危险的方法（高价值sink）
     */
    private boolean isDangerousMethod(SootMethod method) {
        String sig = method.getSignature();
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        
        // 1. Runtime执行类
        if (className.equals("java.lang.Runtime") && methodName.equals("exec")) {
            return true;
        }
        if (className.equals("java.lang.ProcessBuilder") && methodName.equals("start")) {
            return true;
        }
        
        // 2. 类加载类
        if (methodName.equals("defineClass") || methodName.equals("loadClass")) {
            return true;
        }
        if (className.contains("ClassLoader")) {
            return true;
        }
        
        // 3. 模板执行类（JNDI、TemplatesImpl等）
        if (className.contains("TemplatesImpl") && methodName.equals("newTransformer")) {
            return true;
        }
        if (className.contains("JdbcRowSet") && methodName.equals("setAutoCommit")) {
            return true;
        }
        
        // 4. JNDI注入
        if (className.contains("InitialContext") || className.contains("Context")) {
            if (methodName.equals("lookup") || methodName.equals("search")) {
                return true;
            }
        }
        
        // 5. 脚本执行
        if (className.contains("ScriptEngine")) {
            return true;
        }
        
        // 6. 反射调用（递归）
        if (className.equals("java.lang.reflect.Method") && methodName.equals("invoke")) {
            return true;
        }
        
        // 7. 文件操作（高危）
        if (methodName.equals("readObject") && sig.contains("ObjectInputStream")) {
            return true;
        }
        
        // 其他都是低价值sink，不连接
        return false;
    }
    
    /**
     * 判断是否是泛型基类（Object、Serializable等）
     * 这些类的子类数量庞大，不应该截断
     */
    private boolean isGenericBaseClass(SootClass cls) {
        String name = cls.getName();
        return name.equals("java.lang.Object") ||
               name.equals("java.io.Serializable") ||
               name.equals("java.lang.Cloneable") ||
               name.equals("java.lang.Comparable");
    }
    
    /**
     * ProxyImplementation检查（论文条件1）
     * 
     * Handler类必须同时实现：
     * 1. java.io.Serializable (或自定义反序列化机制)
     * 2. java.lang.reflect.InvocationHandler
     * 
     * 这样的Handler才能在反序列化场景下作为动态代理使用
     */
    private boolean isValidProxyHandler(SootClass cls) {
        // 检查1: 必须实现InvocationHandler
        if (!implementsInvocationHandler(cls)) {
            return false;
        }
        
        // 检查2: 必须实现Serializable（反序列化约束）
        if (!isSerializableClass(cls)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * 检查类是否实现InvocationHandler接口
     */
    private boolean implementsInvocationHandler(SootClass cls) {
        try {
            SootClass handlerInterface = Scene.v().getSootClass(
                "java.lang.reflect.InvocationHandler"
            );
            
            // 检查直接实现的接口
            for (SootClass intf : cls.getInterfaces()) {
                if (intf.equals(handlerInterface)) {
                    return true;
                }
                // 递归检查父接口
                if (implementsInterfaceRecursive(intf, handlerInterface)) {
                    return true;
                }
            }
            
            // 检查父类
            if (cls.hasSuperclass()) {
                return implementsInvocationHandler(cls.getSuperclass());
            }
        } catch (Exception e) {
            // 解析失败，保守允许
        }
        
        return false;
    }
    
    /**
     * 递归检查接口继承
     */
    private boolean implementsInterfaceRecursive(SootClass intf, SootClass target) {
        if (intf.equals(target)) {
            return true;
        }
        for (SootClass parent : intf.getInterfaces()) {
            if (implementsInterfaceRecursive(parent, target)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 判断是否是低价值的动态代理方法
     * 
     * 过滤在gadget链中很少被用作攻击路径的方法
     * 平衡性能和覆盖率
     */
    private boolean isLowValueProxyMethod(SootMethod method) {
        String methodName = method.getName();
        String className = method.getDeclaringClass().getName();
        
        // 1. UI/Graphics相关（100%无关反序列化）
        if (className.startsWith("java.awt.") || 
            className.startsWith("javax.swing.") ||
            className.startsWith("sun.java2d.") ||
            className.startsWith("sun.print.")) {
            return true;
        }
        
        // 2. Iterator查询方法（hasNext本身不危险，但next()可能触发）
        if (className.contains("Iterator") || className.contains("Enumeration")) {
            if (methodName.equals("hasNext") || 
                methodName.equals("hasMoreElements")) {
                return true;
            }
        }
        
        // 3. 查询类方法（只读，不改变状态）
        if (methodName.equals("size") || 
            methodName.equals("isEmpty") ||
            methodName.equals("containsKey") ||
            methodName.equals("containsValue")) {
            return true;
        }
        
        // 4. hashCode方法（实验性过滤）
        // hashCode很少是gadget链的关键触发点
        // 但保留equals（可能用于HashMap/HashSet的key比较）
        if (methodName.equals("hashCode")) {
            return true;
        }
        
        // 5. toString方法（很少是gadget关键）
        if (methodName.equals("toString")) {
            return true;
        }
        
        // 注意：保留equals/compare等可能触发链的方法
        
        return false;
    }
    
    /**
     * 判断是否是低价值的接口方法
     * 这些方法通常不是gadget链的关键部分，可以大幅减少目标数
     */
    private boolean isLowValueInterfaceMethod(SootMethod method) {
        String methodName = method.getName();
        String className = method.getDeclaringClass().getName();
        
        // 🔥 优化1：Iterator/Enumeration相关（很少作为gadget入口）
        if (className.contains("Iterator") || className.contains("Enumeration") ||
            className.contains("Spliterator")) {
            return true;
        }
        
        // 🔥 优化2：Collection查询方法（只读，无副作用）
        if (methodName.equals("size") || methodName.equals("isEmpty") || 
            methodName.equals("contains") || methodName.equals("containsKey") ||
            methodName.equals("containsValue") || methodName.equals("indexOf") ||
            methodName.equals("lastIndexOf")) {
            return true;
        }
        
        // 🔥 优化3：Object基础方法
        if (methodName.equals("equals") || methodName.equals("hashCode") || 
            methodName.equals("toString") || methodName.equals("clone") ||
            methodName.equals("finalize")) {
            return true;
        }
        
        // 🔥 优化4：Comparator/Comparable
        if (methodName.equals("compare") || methodName.equals("compareTo") ||
            methodName.equals("reversed") || methodName.equals("thenComparing")) {
            return true;
        }
        
        // 🔥 优化5：Stream API（很少在反序列化链中）
        if (className.startsWith("java.util.stream.")) {
            return true;
        }
        
        // 🔥 优化6：函数式接口的apply/test等（除非有特殊用途）
        if (className.startsWith("java.util.function.") && 
            (methodName.equals("apply") || methodName.equals("test") || 
             methodName.equals("accept") || methodName.equals("get"))) {
            // 保留一些可能有用的，如Supplier.get（可能触发lazy init）
            if (!className.contains("Supplier")) {
                return true;
            }
        }
        
        // 🔥 优化7：AutoCloseable.close（很少作为gadget）
        if (methodName.equals("close") && className.equals("java.lang.AutoCloseable")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 🆕 从CallSite中提取可能的Class类型（VSA优化）
     * 
     * <p>尝试从值集中推断Constructor.newInstance可能的目标类型
     * 
     * @param cs 调用点
     * @return 可能的Class类型集合，如果无法推断则返回null
     */
    private Set<Type> extractPossibleClassTypes(CallSite cs) {
        Set<Type> possibleTypes = new HashSet<>();
        
        // 🚀 VSA: 从base的值集中提取Constructor对应的目标类型
        // Constructor.newInstance调用: base是Constructor对象
        Set<Type> baseValueSet = cs.getBaseValueSet();
        
        
        if (baseValueSet != null && !baseValueSet.isEmpty()) {
            for (Type type : baseValueSet) {
                if (type instanceof soot.RefType) {
                    soot.RefType refType = (soot.RefType) type;
                    SootClass cls = refType.getSootClass();
                    
                    // 🔍 关键：如果这个类型不是Constructor，而是业务类
                    // 说明追踪到了Class对象对应的实际类型
                    String className = cls.getName();
                    
                    // 🔥 关键过滤：排除泛型基类（Object、Serializable等）
                    // 这些类型没有VSA价值，会导致全局搜索
                    if (!className.equals("java.lang.reflect.Constructor") &&
                        !className.equals("java.lang.Class") &&
                        !isGenericBaseClass(cls)) {
                        // 找到了目标类型！
                        possibleTypes.add(type);
                    }
                }
            }
        }
        
        // 如果base值集没有有用信息，尝试从参数值集提取
        // 有些模式可能是: newInstance(Object[] args)，args来自某个特定的数组
        
        if (possibleTypes.isEmpty()) {
            return null;  // 返回null表示需要全局搜索
        }
        
        return possibleTypes;
    }
}

