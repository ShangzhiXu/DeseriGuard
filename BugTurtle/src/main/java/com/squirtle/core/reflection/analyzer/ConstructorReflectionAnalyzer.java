package com.squirtle.core.reflection.analyzer;

import com.squirtle.core.reflection.core.GlobalReflectionFlowMap;
import com.squirtle.core.reflection.core.ReflectionCallSite;
import com.squirtle.core.reflection.core.ReflectionTargetInfo;
import soot.*;
import soot.jimple.*;

import java.util.*;
import java.util.logging.Logger;

/**
 * Constructor 反射分析器（优化版）
 * 
 * 处理 Constructor.newInstance() 调用
 * 
 * 优化内容：
 * 1. 实现了参数类型数组提取
 * 2. 三层智能搜索策略
 * 3. 改进的构造函数匹配算法
 * 4. 添加搜索缓存
 * 
 * @author BugTurtle
 * @version 2.0
 */
public class ConstructorReflectionAnalyzer {
    
    private static final Logger logger = Logger.getLogger(ConstructorReflectionAnalyzer.class.getName());
    
    private final GlobalReflectionFlowMap reflectionFlowMap;
    
    // 搜索结果缓存
    private final Map<String, Set<SootClass>> searchCache = new HashMap<>();
    
    public ConstructorReflectionAnalyzer(GlobalReflectionFlowMap reflectionFlowMap) {
        this.reflectionFlowMap = reflectionFlowMap;
    }
    
    /**
     * 分析一个 Constructor.newInstance() 调用点
     * 
     * @param callSite 反射调用点
     * @return 可能的构造函数目标列表
     */
    public List<ReflectionTargetInfo> analyze(ReflectionCallSite callSite) {
        List<ReflectionTargetInfo> targets = new ArrayList<>();
        
        InvokeExpr invokeExpr = callSite.getInvokeExpr();
        if (!(invokeExpr instanceof VirtualInvokeExpr)) {
            return targets;
        }
        
        VirtualInvokeExpr virtualInvoke = (VirtualInvokeExpr) invokeExpr;
        Value base = virtualInvoke.getBase();  // Constructor 对象
        
        // 策略1：尝试精确推断
        List<ReflectionTargetInfo> preciseTargets = tryPreciseInference(
            callSite.getContainingMethod(), base, callSite.getCallSite());
        
        if (!preciseTargets.isEmpty()) {
            logger.info("🎯 精确推断: " + preciseTargets.size() + " 个目标");
            targets.addAll(preciseTargets);
        } else {
            // 策略2：启发式推断
            logger.info("🔍 使用启发式推断");
            List<ReflectionTargetInfo> heuristicTargets = tryHeuristicInference(
                callSite.getContainingMethod(), base, callSite.getCallSite());
            targets.addAll(heuristicTargets);
            
            if (heuristicTargets.isEmpty()) {
                logger.info("⚠️ 启发式推断也未找到目标");
            }
        }
        
        return targets;
    }
    
    /**
     * 策略1：精确推断
     * 
     * 处理以下模式：
     * 1. TrAXFilter.class.getConstructor(...).newInstance(...)
     * 2. Class.forName("...").getConstructor(...).newInstance(...)
     */
    private List<ReflectionTargetInfo> tryPreciseInference(SootMethod method, Value constructorValue, Unit callSite) {
        List<ReflectionTargetInfo> targets = new ArrayList<>();
        
        if (!(constructorValue instanceof Local)) {
            return targets;
        }
        
        Local constructorLocal = (Local) constructorValue;
        
        // 在方法体中回溯查找 Constructor 对象的定义
        if (!method.hasActiveBody()) {
            return targets;
        }
        
        Body body = method.getActiveBody();
        
        // 找到 Constructor 对象的赋值语句
        for (Unit unit : body.getUnits()) {
            if (!(unit instanceof AssignStmt)) {
                continue;
            }
            
            AssignStmt assignStmt = (AssignStmt) unit;
            if (!assignStmt.getLeftOp().equals(constructorLocal)) {
                continue;
            }
            
            Value rightOp = assignStmt.getRightOp();
            
            // 检查是否是 getConstructor() 调用
            if (rightOp instanceof VirtualInvokeExpr) {
                VirtualInvokeExpr getConstructorInvoke = (VirtualInvokeExpr) rightOp;
                SootMethod calledMethod = getConstructorInvoke.getMethod();
                
                if (calledMethod.getName().equals("getConstructor") &&
                    calledMethod.getDeclaringClass().getName().equals("java.lang.Class")) {
                    
                    // 获取 Class 对象
                    Value classValue = getConstructorInvoke.getBase();
                    
                    // 尝试推断 Class 对象
                    SootClass targetClass = inferClassObject(body, classValue);
                    
                    if (targetClass != null) {
                        // 🆕 获取参数类型（改进版）
                        List<Type> paramTypes = extractParameterTypes(body, getConstructorInvoke);
                        
                        // 查找匹配的构造函数
                        SootMethod constructor = findConstructor(targetClass, paramTypes);
                        
                        if (constructor != null) {
                            ReflectionTargetInfo target = new ReflectionTargetInfo(
                                constructor, targetClass, paramTypes,
                                ReflectionTargetInfo.InferenceStrategy.PRECISE,
                                "Literal class object: " + targetClass.getName()
                            );
                            targets.add(target);
                            logger.fine("✅ 精确推断构造函数: " + constructor.getSignature());
                        }
                    }
                }
            }
        }
        
        return targets;
    }
    
    /**
     * 策略2：启发式推断
     * 
     * 当无法精确推断时，基于以下启发式规则：
     * 1. 类型约束：如果有泛型上界，搜索所有子类
     * 2. 参数类型匹配：搜索所有接受特定参数类型的构造函数
     */
    private List<ReflectionTargetInfo> tryHeuristicInference(SootMethod method, Value constructorValue, Unit callSite) {
        List<ReflectionTargetInfo> targets = new ArrayList<>();
        
        // 启发式规则1：查找构造函数的定义，提取参数类型
        List<Type> paramTypes = extractParameterTypesFromContext(method, constructorValue);
        
        logger.info("📊 提取参数类型结果: " + (paramTypes == null ? "null" : "列表长度=" + paramTypes.size()));
        
        // 启发式规则2：搜索所有匹配参数类型的构造函数
        Set<SootClass> candidateClasses;
        
        if (paramTypes == null) {
            // 无法提取参数类型（可能来自字段），使用全局搜索策略
            logger.info("⚠️ 无法提取参数类型，使用全局搜索策略");
            candidateClasses = unlimitedGlobalSearch();
        } else {
            // 正常流程：根据参数类型搜索
            candidateClasses = findClassesWithMatchingConstructor(paramTypes);
        }
        
        logger.fine("🔍 找到 " + candidateClasses.size() + " 个候选类");
        
        for (SootClass candidateClass : candidateClasses) {
            if (paramTypes == null) {
                // 🔧 保守策略：添加所有公共构造函数
                List<SootMethod> constructors = findAllPublicConstructors(candidateClass);
                for (SootMethod constructor : constructors) {
                    ReflectionTargetInfo target = new ReflectionTargetInfo(
                        constructor, candidateClass, paramTypes,
                        ReflectionTargetInfo.InferenceStrategy.HEURISTIC,
                        "Conservative: all public constructors"
                    );
                    targets.add(target);
                }
            } else {
                // 正常流程：根据参数类型匹配
                SootMethod constructor = findConstructor(candidateClass, paramTypes);
                if (constructor != null) {
                    ReflectionTargetInfo target = new ReflectionTargetInfo(
                        constructor, candidateClass, paramTypes,
                        ReflectionTargetInfo.InferenceStrategy.HEURISTIC,
                        "Parameter type matching: " + paramTypes
                    );
                    targets.add(target);
                }
            }
        }
        
        return targets;
    }
    
    /**
     * 推断 Class 对象
     * 
     * 处理：
     * 1. TrAXFilter.class (ClassConstant)
     * 2. Class.forName("...") (String constant)
     */
    private SootClass inferClassObject(Body body, Value classValue) {
        // 情况1：直接的类字面量
        if (classValue instanceof ClassConstant) {
            ClassConstant classConst = (ClassConstant) classValue;
            String className = classConst.getValue().replace('/', '.');
            return Scene.v().getSootClassUnsafe(className);
        }
        
        // 情况2：通过 Local 回溯
        if (classValue instanceof Local) {
            Local classLocal = (Local) classValue;
            
            for (Unit unit : body.getUnits()) {
                if (!(unit instanceof AssignStmt)) {
                    continue;
                }
                
                AssignStmt assignStmt = (AssignStmt) unit;
                if (!assignStmt.getLeftOp().equals(classLocal)) {
                    continue;
                }
                
                Value rightOp = assignStmt.getRightOp();
                
                // ClassConstant
                if (rightOp instanceof ClassConstant) {
                    ClassConstant classConst = (ClassConstant) rightOp;
                    String className = classConst.getValue().replace('/', '.');
                    return Scene.v().getSootClassUnsafe(className);
                }
                
                // Class.forName("...")
                if (rightOp instanceof StaticInvokeExpr) {
                    StaticInvokeExpr staticInvoke = (StaticInvokeExpr) rightOp;
                    if (staticInvoke.getMethod().getName().equals("forName") &&
                        staticInvoke.getArgCount() > 0) {
                        Value arg = staticInvoke.getArg(0);
                        if (arg instanceof StringConstant) {
                            String className = ((StringConstant) arg).value;
                            return Scene.v().getSootClassUnsafe(className);
                        }
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * 🆕 提取构造函数的参数类型（改进版 - 实现了TODO）
     */
    private List<Type> extractParameterTypes(Body body, VirtualInvokeExpr getConstructorInvoke) {
        List<Type> paramTypes = new ArrayList<>();
        
        if (getConstructorInvoke.getArgCount() == 0) {
            return paramTypes;  // 无参构造函数
        }
        
        Value arg = getConstructorInvoke.getArg(0);  // Class[] 数组
        
        // 🆕 尝试从数组中提取元素类型
        List<Type> extracted = extractTypesFromArray(body, arg);
        if (extracted != null && !extracted.isEmpty()) {
            paramTypes.addAll(extracted);
            logger.fine("✅ 成功提取参数类型: " + extracted.size() + " 个");
        }
        
        return paramTypes;
    }
    
    /**
     * 🆕 从Class[]数组中提取类型信息
     */
    private List<Type> extractTypesFromArray(Body body, Value arrayValue) {
        List<Type> types = new ArrayList<>();
        
        // 情况1：arrayValue是Local，需要回溯查找数组初始化
        if (arrayValue instanceof Local) {
            Local arrayLocal = (Local) arrayValue;
            
            // 第一步：找到数组的创建
            NewArrayExpr newArrayExpr = null;
            for (Unit unit : body.getUnits()) {
                if (unit instanceof AssignStmt) {
                    AssignStmt assign = (AssignStmt) unit;
                    if (assign.getLeftOp().equals(arrayLocal) && 
                        assign.getRightOp() instanceof NewArrayExpr) {
                        newArrayExpr = (NewArrayExpr) assign.getRightOp();
                        break;
                    }
                }
            }
            
            if (newArrayExpr != null) {
                // 第二步：查找数组元素的赋值
                Map<Integer, Type> indexToType = new HashMap<>();
                
                for (Unit unit : body.getUnits()) {
                    if (unit instanceof AssignStmt) {
                        AssignStmt assign = (AssignStmt) unit;
                        
                        // 检查左侧是否是数组引用
                        if (assign.getLeftOp() instanceof ArrayRef) {
                            ArrayRef arrayRef = (ArrayRef) assign.getLeftOp();
                            
                            // 检查是否是我们关注的数组
                            if (arrayRef.getBase().equals(arrayLocal)) {
                                // 获取索引
                                Value indexValue = arrayRef.getIndex();
                                Integer index = extractConstantIndex(indexValue);
                                
                                if (index != null) {
                                    // 获取赋值的类型
                                    Value rightOp = assign.getRightOp();
                                    Type type = extractTypeFromValue(rightOp);
                                    
                                    if (type != null) {
                                        indexToType.put(index, type);
                                        logger.fine("  数组[" + index + "] = " + type);
                                    }
                                }
                            }
                        }
                    }
                }
                
                // 第三步：按索引顺序组装类型列表
                if (!indexToType.isEmpty()) {
                    int maxIndex = Collections.max(indexToType.keySet());
                    for (int i = 0; i <= maxIndex; i++) {
                        Type type = indexToType.get(i);
                        if (type != null) {
                            types.add(type);
                        }
                    }
                }
            }
        }
        
        // 情况2：直接的数组字面量（较少见）
        // 暂时不处理，因为Jimple中很少出现这种情况
        
        return types;
    }
    
    /**
     * 🆕 从常量索引值中提取整数
     */
    private Integer extractConstantIndex(Value indexValue) {
        if (indexValue instanceof IntConstant) {
            return ((IntConstant) indexValue).value;
        }
        return null;
    }
    
    /**
     * 🆕 从Value中提取Type
     */
    private Type extractTypeFromValue(Value value) {
        // 情况1：ClassConstant
        if (value instanceof ClassConstant) {
            ClassConstant classConst = (ClassConstant) value;
            String className = classConst.getValue().replace('/', '.');
            SootClass sootClass = Scene.v().getSootClassUnsafe(className);
            if (sootClass != null) {
                return sootClass.getType();
            }
        }
        
        // 情况2：Local变量，尝试回溯
        // 暂时简化处理，不进行深度回溯
        
        return null;
    }
    
    /**
     * 从上下文中提取参数类型（启发式）
     */
    private List<Type> extractParameterTypesFromContext(SootMethod method, Value constructorValue) {
        // 查找 Constructor 对象的赋值语句
        if (!(constructorValue instanceof Local)) {
            logger.fine("constructorValue 不是 Local，无法回溯");
            return null;
        }
        
        Local constructorLocal = (Local) constructorValue;
        
        // 尝试从 activeBody 获取 units
        if (!method.hasActiveBody()) {
            logger.fine("方法没有 activeBody，无法提取参数类型");
            return null;
        }
        
        Body body = method.getActiveBody();
        
        // 查找 getConstructor() 调用
        logger.fine("在方法体中查找 getConstructor() 调用...");
        for (Unit unit : body.getUnits()) {
            if (!(unit instanceof AssignStmt)) {
                continue;
            }
            
            AssignStmt assignStmt = (AssignStmt) unit;
            if (!assignStmt.getLeftOp().equals(constructorLocal)) {
                continue;
            }
            
            Value rightOp = assignStmt.getRightOp();
            if (!(rightOp instanceof VirtualInvokeExpr)) {
                continue;
            }
            
            VirtualInvokeExpr invoke = (VirtualInvokeExpr) rightOp;
            if (!invoke.getMethod().getName().equals("getConstructor")) {
                continue;
            }
            
            // 获取 getConstructor 的参数（Class[] 数组）
            if (invoke.getArgCount() > 0) {
                Value paramTypesArg = invoke.getArg(0);
                
                logger.info("✅ 找到 getConstructor() 调用，参数: " + paramTypesArg);
                logger.info("   参数类型: " + paramTypesArg.getClass().getSimpleName());
                
                // 🆕 尝试提取数组元素
                List<Type> extractedTypes = extractTypesFromArray(body, paramTypesArg);
                if (extractedTypes != null && !extractedTypes.isEmpty()) {
                    logger.info("   🎯 成功提取了 " + extractedTypes.size() + " 个参数类型");
                    return extractedTypes;
                }
                
                // 🔧 如果提取失败（例如参数类型来自字段），返回 null 触发广泛搜索
                // 不返回空列表，否则只会匹配无参构造函数
                logger.info("   ⚠️ 无法提取参数类型（可能来自字段），返回 null 使用全局搜索");
                return null;
            }
        }
        
        logger.fine("未找到 getConstructor() 调用");
        return null;
    }
    
    /**
     * 无限制的全局搜索（无参数类型时使用）
     * 
     * 当无法提取参数类型时，搜索所有可实例化的类
     */
    private Set<SootClass> unlimitedGlobalSearch() {
        Set<SootClass> candidates = new HashSet<>();
        
        logger.info("🔍 全局搜索：遍历所有可实例化类...");
        
        for (SootClass cls : Scene.v().getClasses()) {
            if (!shouldConsiderClassLoose(cls)) {
                continue;
            }
            
            // 检查是否有公共构造函数
            boolean hasPublicConstructor = false;
            for (SootMethod method : cls.getMethods()) {
                if (method.getName().equals("<init>") && method.isPublic()) {
                    hasPublicConstructor = true;
                    break;
                }
            }
            
            if (hasPublicConstructor) {
                candidates.add(cls);
            }
        }
        
        logger.info("✅ 全局搜索找到 " + candidates.size() + " 个候选类");
        return candidates;
    }
    
    /**
     * 通用候选类搜索策略（零先验知识）
     */
    private Set<SootClass> findClassesWithMatchingConstructor(List<Type> paramTypes) {
        // 构造缓存键
        String cacheKey = buildCacheKey(paramTypes);
        if (searchCache.containsKey(cacheKey)) {
            logger.fine("💾 使用缓存结果");
            return searchCache.get(cacheKey);
        }
        
        Set<SootClass> candidates = new HashSet<>();
        
        logger.info("🔍 搜索构造函数候选类 (参数类型数: " + paramTypes.size() + ")");
        
        // 策略1：优先搜索应用包（非JDK标准包）
        candidates.addAll(searchInRelatedPackages(paramTypes));
        if (!candidates.isEmpty()) {
            logger.info("✅ 策略1(应用包搜索)找到 " + candidates.size() + " 个候选类");
            searchCache.put(cacheKey, candidates);
            return candidates;
        }
        
        // 策略2：全局搜索（无限制，使用宽松过滤）
        candidates.addAll(unlimitedGlobalSearchWithParams(paramTypes));
        if (!candidates.isEmpty()) {
            logger.info("✅ 策略2(全局搜索)找到 " + candidates.size() + " 个候选类");
        } else {
            logger.info("⚠️ 未找到匹配的候选类");
        }
        
        searchCache.put(cacheKey, candidates);
        return candidates;
    }
    
    /**
     * 🆕 构建缓存键
     */
    private String buildCacheKey(List<Type> paramTypes) {
        if (paramTypes.isEmpty()) {
            return "empty";
        }
        StringBuilder sb = new StringBuilder();
        for (Type type : paramTypes) {
            sb.append(type.toString()).append("|");
        }
        return sb.toString();
    }
    
    /**
     * 🆕 策略1：搜索相关包（基于调用上下文）
     */
    private Set<SootClass> searchInRelatedPackages(List<Type> paramTypes) {
        Set<SootClass> candidates = new HashSet<>();
        
        // 收集所有已加载类的包名
        Set<String> loadedPackages = new HashSet<>();
        for (SootClass cls : Scene.v().getClasses()) {
            if (!cls.isPhantom() && !cls.isInterface() && !cls.isAbstract()) {
                loadedPackages.add(cls.getPackageName());
            }
        }
        
        // 在所有已加载的应用包中搜索
        for (String packageName : loadedPackages) {
            // 排除JDK标准包
            if (packageName.startsWith("java.") || 
                packageName.startsWith("javax.") ||
                packageName.startsWith("sun.") ||
                packageName.startsWith("jdk.")) {
                continue;
            }
            
            candidates.addAll(searchInPackage(packageName, paramTypes));
        }
        
        return candidates;
    }
    
    /**
     * 带参数类型匹配的全局搜索
     */
    private Set<SootClass> unlimitedGlobalSearchWithParams(List<Type> paramTypes) {
        Set<SootClass> candidates = new HashSet<>();
        
        logger.fine("执行全局搜索（参数匹配）");
        
        for (SootClass cls : Scene.v().getClasses()) {
            if (!shouldConsiderClassLoose(cls)) {
                continue;
            }
            
            // 检查是否有匹配的构造函数
            SootMethod constructor = findConstructor(cls, paramTypes);
            if (constructor != null) {
                candidates.add(cls);
            }
        }
        
        return candidates;
    }
    
    
    /**
     * 🆕 在指定包中搜索
     */
    private Set<SootClass> searchInPackage(String packageName, List<Type> paramTypes) {
        Set<SootClass> candidates = new HashSet<>();
        
        for (SootClass cls : Scene.v().getClasses()) {
            if (!cls.getName().startsWith(packageName)) {
                continue;
            }
            
            if (!shouldConsiderClassLoose(cls)) {
                continue;
            }
            
            SootMethod constructor = findConstructor(cls, paramTypes);
            if (constructor != null) {
                candidates.add(cls);
            }
        }
        
        return candidates;
    }
    
    
    /**
     * 宽松的类过滤条件（通用策略，不依赖gadget知识）
     * 
     * 只排除明显无关的类，保留所有可能的gadget类
     */
    private boolean shouldConsiderClassLoose(SootClass cls) {
        // 排除Phantom类、接口、抽象类
        if (cls.isPhantom() || cls.isInterface() || cls.isAbstract()) {
            return false;
        }
        
        String className = cls.getName();
        
        // 只排除明显无害的JDK基础包
        if (className.startsWith("java.lang.") && 
            !className.equals("java.lang.Runtime") &&
            !className.equals("java.lang.ProcessBuilder")) {
            return false;
        }
        
        if (className.startsWith("java.util.") ||
            className.startsWith("java.io.") ||
            className.startsWith("java.nio.")) {
            return false;
        }
        
        // 排除测试框架
        if (className.startsWith("org.junit.") ||
            className.startsWith("org.testng.") ||
            className.startsWith("org.mockito.")) {
            return false;
        }
        
        // ✅ 保留所有其他类，包括：
        // - javax.* (javax.swing.JEditorPane, javax.management.*)
        // - sun.* (sun.net.www.protocol.http.HttpCallerInfo)
        // - com.sun.* (com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter)
        // - 所有第三方库
        return true;
    }
    
    /**
     * 🔧 获取类的所有公共构造函数（用于保守策略）
     */
    private List<SootMethod> findAllPublicConstructors(SootClass cls) {
        List<SootMethod> constructors = new ArrayList<>();
        
        try {
            for (SootMethod method : cls.getMethods()) {
                if (method.getName().equals("<init>") && method.isPublic()) {
                    constructors.add(method);
                }
            }
        } catch (Exception e) {
            logger.fine("获取构造函数列表失败: " + cls.getName() + " - " + e.getMessage());
        }
        
        return constructors;
    }
    
    /**
     * 在类中查找匹配的构造函数（改进版）
     */
    private SootMethod findConstructor(SootClass cls, List<Type> paramTypes) {
        try {
            SootMethod firstPublicConstructor = null;
            SootMethod bestMatch = null;
            int bestMatchScore = -1;
            
            for (SootMethod method : cls.getMethods()) {
                if (!method.getName().equals("<init>")) {
                    continue;
                }
                
                // 记录第一个公共构造函数（用于启发式）
                if (firstPublicConstructor == null && method.isPublic()) {
                    firstPublicConstructor = method;
                }
                
                // 🔧 如果paramTypes为null（无法提取参数类型），返回第一个公共构造函数
                if (paramTypes == null) {
                    if (method.isPublic()) {
                        return method;  // 保守策略：返回任意公共构造函数
                    }
                    continue;
                }
                
                // 🆕 如果paramTypes为空，返回无参构造函数（最优）或第一个公共构造函数
                if (paramTypes.isEmpty()) {
                    if (method.getParameterCount() == 0) {
                        return method;  // 无参构造函数是最佳匹配
                    }
                    continue;
                }
                
                // 精确匹配参数数量
                if (method.getParameterCount() != paramTypes.size()) {
                    continue;
                }
                
                // 🆕 计算类型匹配度
                int matchScore = calculateTypeMatchScore(method, paramTypes);
                if (matchScore > bestMatchScore) {
                    bestMatchScore = matchScore;
                    bestMatch = method;
                }
            }
            
            // 返回最佳匹配
            if (bestMatch != null) {
                return bestMatch;
            }
            
            // 如果paramTypes为空且没有无参构造函数，返回第一个公共构造函数
            if (paramTypes.isEmpty() && firstPublicConstructor != null) {
                return firstPublicConstructor;
            }
            
        } catch (Exception e) {
            logger.fine("查找构造函数失败: " + cls.getName() + " - " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * 🆕 计算类型匹配度评分
     * 返回值越高表示匹配越好
     */
    private int calculateTypeMatchScore(SootMethod constructor, List<Type> paramTypes) {
        int score = 0;
        
        for (int i = 0; i < paramTypes.size(); i++) {
            Type expectedType = paramTypes.get(i);
            Type actualType = constructor.getParameterType(i);
            
            if (expectedType.equals(actualType)) {
                score += 10;  // 完全匹配
            } else if (isAssignableFrom(expectedType, actualType)) {
                score += 5;   // 类型兼容
            } else if (expectedType instanceof RefType && actualType instanceof RefType) {
                // 都是引用类型，给一些基础分
                score += 1;
            }
        }
        
        return score;
    }
    
    /**
     * 🆕 简单的类型兼容性检查
     */
    private boolean isAssignableFrom(Type superType, Type subType) {
        if (!(superType instanceof RefType) || !(subType instanceof RefType)) {
            return false;
        }
        
        try {
            SootClass superClass = ((RefType) superType).getSootClass();
            SootClass subClass = ((RefType) subType).getSootClass();
            
            // 检查继承关系
            return isSubclassOf(subClass, superClass);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 🆕 检查继承关系
     */
    private boolean isSubclassOf(SootClass subClass, SootClass superClass) {
        if (subClass.equals(superClass)) {
            return true;
        }
        
        try {
            // 检查直接父类
            if (subClass.hasSuperclass()) {
                SootClass parent = subClass.getSuperclass();
                if (isSubclassOf(parent, superClass)) {
                    return true;
                }
            }
            
            // 检查实现的接口
            for (SootClass iface : subClass.getInterfaces()) {
                if (isSubclassOf(iface, superClass)) {
                    return true;
                }
            }
        } catch (Exception e) {
            // 忽略异常
        }
        
        return false;
    }
}
