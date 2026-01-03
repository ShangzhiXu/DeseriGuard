package com.squirtle.core.reflection.analyzer;

import com.squirtle.core.reflection.PhantomSinkManager;
import com.squirtle.core.reflection.core.GlobalReflectionFlowMap;
import com.squirtle.core.reflection.core.ReflectionCallSite;
import com.squirtle.core.reflection.core.ReflectionTargetInfo;
import soot.*;
import soot.jimple.*;

import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Method 反射分析器（优化版）
 * 
 * 处理 Method.invoke() 调用
 * 
 * 优化内容：
 * 1. 改进的方法名提取
 * 2. 智能搜索策略
 * 3. 添加搜索缓存
 * 4. ⭐ 学习Flash：支持Phantom类的sink方法
 * 
 * @author BugTurtle
 * @version 3.0
 */
public class MethodReflectionAnalyzer {
    
    private static final Logger logger = Logger.getLogger(MethodReflectionAnalyzer.class.getName());
    
    private final GlobalReflectionFlowMap reflectionFlowMap;
    
    // ⭐ 学习Flash：Phantom sink管理器
    private final PhantomSinkManager phantomSinkManager;
    
    // 搜索结果缓存
    private final Map<String, List<SootMethod>> searchCache = new HashMap<>();
    
    public MethodReflectionAnalyzer(GlobalReflectionFlowMap reflectionFlowMap) {
        this.reflectionFlowMap = reflectionFlowMap;
        this.phantomSinkManager = new PhantomSinkManager();
        
        logger.info("⭐ MethodReflectionAnalyzer初始化完成，已加载 " + 
            phantomSinkManager.getAllPhantomSinks().size() + " 个Phantom sink方法");
    }
    
    /**
     * 分析一个 Method.invoke() 调用点
     * 
     * @param callSite 反射调用点
     * @return 可能的方法目标列表
     */
    public List<ReflectionTargetInfo> analyze(ReflectionCallSite callSite) {
        List<ReflectionTargetInfo> targets = new ArrayList<>();
        
        InvokeExpr invokeExpr = callSite.getInvokeExpr();
        if (!(invokeExpr instanceof VirtualInvokeExpr)) {
            return targets;
        }
        
        VirtualInvokeExpr virtualInvoke = (VirtualInvokeExpr) invokeExpr;
        Value base = virtualInvoke.getBase();  // Method 对象
        
        // 策略1：尝试精确推断
        List<ReflectionTargetInfo> preciseTargets = tryPreciseInference(
            callSite.getContainingMethod(), base, callSite.getCallSite());
        
        if (!preciseTargets.isEmpty()) {
            logger.fine("🎯 精确推断: " + preciseTargets.size() + " 个目标");
            targets.addAll(preciseTargets);
        } else {
            // 策略2：启发式推断
            logger.fine("🔍 使用启发式推断");
            List<ReflectionTargetInfo> heuristicTargets = tryHeuristicInference(
                callSite.getContainingMethod(), base, callSite.getCallSite());
            targets.addAll(heuristicTargets);
        }
        
        return targets;
    }
    
    /**
     * 策略1：精确推断
     * 
     * 处理以下模式：
     * 1. clazz.getMethod("methodName", ...).invoke(...)
     * 2. clazz.getDeclaredMethod("methodName", ...).invoke(...)
     */
    private List<ReflectionTargetInfo> tryPreciseInference(SootMethod method, Value methodValue, Unit callSite) {
        List<ReflectionTargetInfo> targets = new ArrayList<>();
        
        if (!(methodValue instanceof Local)) {
            return targets;
        }
        
        Local methodLocal = (Local) methodValue;
        
        if (!method.hasActiveBody()) {
            return targets;
        }
        
        Body body = method.getActiveBody();
        
        // 找到 Method 对象的赋值语句
        for (Unit unit : body.getUnits()) {
            if (!(unit instanceof AssignStmt)) {
                continue;
            }
            
            AssignStmt assignStmt = (AssignStmt) unit;
            if (!assignStmt.getLeftOp().equals(methodLocal)) {
                continue;
            }
            
            Value rightOp = assignStmt.getRightOp();
            
            // 检查是否是 getMethod() 或 getDeclaredMethod() 调用
            if (rightOp instanceof VirtualInvokeExpr) {
                VirtualInvokeExpr getMethodInvoke = (VirtualInvokeExpr) rightOp;
                SootMethod calledMethod = getMethodInvoke.getMethod();
                
                if ((calledMethod.getName().equals("getMethod") || 
                     calledMethod.getName().equals("getDeclaredMethod")) &&
                    calledMethod.getDeclaringClass().getName().equals("java.lang.Class")) {
                    
                    // 获取 Class 对象
                    Value classValue = getMethodInvoke.getBase();
                    
                    // 获取方法名（第一个参数）
                    String methodName = extractMethodName(getMethodInvoke);
                    
                    if (methodName != null) {
                        // 尝试推断 Class 对象
                        SootClass targetClass = inferClassObject(body, classValue);
                        
                        // 获取参数类型
                        List<Type> paramTypes = extractParameterTypes(getMethodInvoke);
                        
                        if (targetClass != null) {
                            // 查找匹配的方法
                            SootMethod targetMethod = findMethod(targetClass, methodName, paramTypes);
                            
                            if (targetMethod != null) {
                                ReflectionTargetInfo target = new ReflectionTargetInfo(
                                    targetMethod, methodName, paramTypes,
                                    ReflectionTargetInfo.InferenceStrategy.PRECISE,
                                    "Literal class and method name: " + targetClass.getName() + "." + methodName
                                );
                                targets.add(target);
                                logger.fine("✅ 精确推断方法: " + targetMethod.getSignature());
                            }
                        } else {
                            // Class 对象未知，但方法名已知
                            // 🆕 使用智能搜索策略
                            List<SootMethod> candidateMethods = findMethodsByNameSmart(methodName, paramTypes);
                            for (SootMethod candidateMethod : candidateMethods) {
                                ReflectionTargetInfo target = new ReflectionTargetInfo(
                                    candidateMethod, methodName, paramTypes,
                                    ReflectionTargetInfo.InferenceStrategy.PRECISE,
                                    "Known method name: " + methodName
                                );
                                targets.add(target);
                            }
                        }
                    }
                }
            }
        }
        
        return targets;
    }
    
    /**
     * 策略2：启发式推断（通用策略，不依赖gadget知识）
     * 
     * 当无法精确推断时，返回空列表
     * 注：Method.invoke的目标由CallTargetResolver处理（连接到Flash sinks）
     */
    private List<ReflectionTargetInfo> tryHeuristicInference(SootMethod method, Value methodValue, Unit callSite) {
        // 不再使用hard-coded的危险方法列表
        // Method.invoke的目标由TaintGuidedCallGraphBuilder中的CallTargetResolver处理
        // 它会连接到Flash定义的30个sink，保证soundness
        return new ArrayList<>();
    }
    
    
    /**
     * 提取方法名（字符串常量）
     */
    private String extractMethodName(VirtualInvokeExpr getMethodInvoke) {
        if (getMethodInvoke.getArgCount() > 0) {
            Value arg = getMethodInvoke.getArg(0);
            if (arg instanceof StringConstant) {
                return ((StringConstant) arg).value;
            }
            
            // 🆕 尝试回溯Local变量
            if (arg instanceof Local) {
                return extractMethodNameFromLocal(getMethodInvoke, (Local) arg);
            }
        }
        return null;
    }
    
    /**
     * 🆕 从Local变量回溯提取方法名
     */
    private String extractMethodNameFromLocal(VirtualInvokeExpr invoke, Local local) {
        // 获取包含此调用的方法
        try {
            SootMethod containingMethod = invoke.getMethod().getDeclaringClass()
                .getMethodByName(invoke.getMethod().getName());
            
            if (!containingMethod.hasActiveBody()) {
                return null;
            }
            
            Body body = containingMethod.getActiveBody();
            for (Unit unit : body.getUnits()) {
                if (unit instanceof AssignStmt) {
                    AssignStmt assign = (AssignStmt) unit;
                    if (assign.getLeftOp().equals(local) && 
                        assign.getRightOp() instanceof StringConstant) {
                        return ((StringConstant) assign.getRightOp()).value;
                    }
                }
            }
        } catch (Exception e) {
            logger.fine("回溯方法名失败: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * 推断 Class 对象（与 ConstructorReflectionAnalyzer 相同）
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
                
                // obj.getClass()
                if (rightOp instanceof VirtualInvokeExpr) {
                    VirtualInvokeExpr virtualInvoke = (VirtualInvokeExpr) rightOp;
                    if (virtualInvoke.getMethod().getName().equals("getClass")) {
                        // 尝试推断 obj 的类型
                        Value base = virtualInvoke.getBase();
                        if (base.getType() instanceof RefType) {
                            return ((RefType) base.getType()).getSootClass();
                        }
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * 提取方法的参数类型
     */
    private List<Type> extractParameterTypes(VirtualInvokeExpr getMethodInvoke) {
        List<Type> paramTypes = new ArrayList<>();
        
        if (getMethodInvoke.getArgCount() < 2) {
            return paramTypes;  // 无参方法
        }
        
        Value arg = getMethodInvoke.getArg(1);  // Class[] 数组
        
        // TODO: 完整实现数组元素提取（可以复用ConstructorReflectionAnalyzer的实现）
        
        return paramTypes;
    }
    
    /**
     * 在类中查找匹配的方法
     */
    /**
     * 查找单个方法（保留向后兼容性）
     */
    private SootMethod findMethod(SootClass cls, String methodName, List<Type> paramTypes) {
        try {
            // 🔥 确保解析级别
            if (cls.resolvingLevel() < SootClass.SIGNATURES) {
                cls.setResolvingLevel(SootClass.SIGNATURES);
            }
            
            for (SootMethod method : cls.getMethods()) {
                if (!method.getName().equals(methodName)) {
                    continue;
                }
                
                // 匹配参数类型
                if (method.getParameterCount() == paramTypes.size()) {
                    // 简化：只检查数量
                    return method;
                }
                
                // 如果 paramTypes 为空，返回第一个匹配名称的方法
                if (paramTypes.isEmpty()) {
                    return method;
                }
            }
        } catch (Exception e) {
            logger.fine("查找方法失败: " + cls.getName() + "." + methodName + " - " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * 🆕 查找所有匹配的方法（包括所有重载）
     */
    private List<SootMethod> findAllMethods(SootClass cls, String methodName, List<Type> paramTypes) {
        List<SootMethod> foundMethods = new ArrayList<>();
        
        try {
            // 🔥 确保解析级别
            if (cls.resolvingLevel() < SootClass.SIGNATURES) {
                cls.setResolvingLevel(SootClass.SIGNATURES);
            }
            
            for (SootMethod method : cls.getMethods()) {
                if (!method.getName().equals(methodName)) {
                    continue;
                }
                
                // 如果指定了参数类型，进行匹配
                if (!paramTypes.isEmpty()) {
                    if (method.getParameterCount() == paramTypes.size()) {
                        foundMethods.add(method);
                    }
                } else {
                    // 如果没有指定参数类型，返回所有同名方法（所有重载）
                    foundMethods.add(method);
                }
            }
        } catch (Exception e) {
            logger.fine("查找方法失败: " + cls.getName() + "." + methodName + " - " + e.getMessage());
        }
        
        return foundMethods;
    }
    
    /**
     * 🆕 智能按方法名搜索（优化版）
     */
    private List<SootMethod> findMethodsByNameSmart(String methodName, List<Type> paramTypes) {
        // 检查缓存
        String cacheKey = methodName + "|" + paramTypes.size();
        if (searchCache.containsKey(cacheKey)) {
            logger.fine("💾 使用缓存结果: " + methodName);
            return searchCache.get(cacheKey);
        }
        
        List<SootMethod> methods = new ArrayList<>();
        
        logger.fine("🔍 智能搜索方法: " + methodName);
        
        // 策略1：优先搜索应用程序类
        methods.addAll(searchInApplicationClasses(methodName, paramTypes));
        
        // 策略2：搜索JDK关键类
        methods.addAll(searchInJDKClasses(methodName, paramTypes));
        
        // ⭐ 策略3：搜索Phantom sink方法（学习Flash） - 始终执行！
        List<SootMethod> phantomMethods = phantomSinkManager.findPhantomSinksByName(methodName);
        if (!phantomMethods.isEmpty()) {
            // ✅ Phantom sink 不做序列化检查
            // 原因：它们通常通过反射调用，receiver 是动态构造的（如 new InitialContext()）
            // Flash 的策略：如果 receiver 可控，不检查 declaring class 的序列化性
            logger.info("✨ 找到Phantom sink: " + methodName + " (" + phantomMethods.size() + "个)");
            methods.addAll(phantomMethods);
        }
        
        // 如果已经找到方法，直接返回（应用类、JDK类或Phantom sink）
        if (!methods.isEmpty()) {
            logger.fine("✅ 共找到 " + methods.size() + " 个候选方法");
            searchCache.put(cacheKey, methods);
            return methods;
        }
        
        // 策略4：限制全局搜索（只有都找不到时才执行）
        methods.addAll(searchGloballyLimited(methodName, paramTypes, 50));
        
        searchCache.put(cacheKey, methods);
        return methods;
    }
    
    /**
     * 🆕 在应用程序类中搜索
     */
    private List<SootMethod> searchInApplicationClasses(String methodName, List<Type> paramTypes) {
        List<SootMethod> methods = new ArrayList<>();
        
        for (SootClass cls : Scene.v().getApplicationClasses()) {
            if (cls.isPhantom()) {
                continue;
            }
            
            try {
                // 🔥 确保解析级别
                if (cls.resolvingLevel() < SootClass.SIGNATURES) {
                    cls.setResolvingLevel(SootClass.SIGNATURES);
                }
                
                for (SootMethod method : cls.getMethods()) {
                    if (method.getName().equals(methodName)) {
                        if (paramTypes.isEmpty() || method.getParameterCount() == paramTypes.size()) {
                            methods.add(method);
                        }
                    }
                }
            } catch (Exception e) {
                // 忽略错误
            }
        }
        
        return methods;
    }
    
    /**
     * 🆕 在JDK关键类中搜索
     */
    private List<SootMethod> searchInJDKClasses(String methodName, List<Type> paramTypes) {
        List<SootMethod> methods = new ArrayList<>();
        
        // 关键的JDK类
        String[] keyClasses = {
            "java.lang.Runtime",
            "java.lang.ProcessBuilder",
            "java.lang.Class",
            "java.lang.ClassLoader",           // 🆕 添加ClassLoader
            "java.net.URLClassLoader",         // 🆕 添加URLClassLoader
            "java.lang.reflect.Method",
            "java.lang.reflect.Constructor",
            "javax.xml.transform.Transformer",
            "javax.xml.transform.Templates"
        };
        
        for (String className : keyClasses) {
            if (!Scene.v().containsClass(className)) {
                continue;
            }
            
            try {
                SootClass cls = Scene.v().getSootClass(className);
                // 🔧 修改：查找所有匹配的方法（包括所有重载）
                List<SootMethod> foundMethods = findAllMethods(cls, methodName, paramTypes);
                methods.addAll(foundMethods);
            } catch (Exception e) {
                // 忽略错误
            }
        }
        
        return methods;
    }
    
    /**
     * 🆕 限制的全局搜索
     */
    private List<SootMethod> searchGloballyLimited(String methodName, List<Type> paramTypes, int maxResults) {
        List<SootMethod> methods = new ArrayList<>();
        
        int count = 0;
        for (SootClass cls : Scene.v().getClasses()) {
            if (count >= maxResults) {
                break;
            }
            
            if (cls.isPhantom()) {
                continue;
            }
            
            try {
                // 🔥 确保解析级别
                if (cls.resolvingLevel() < SootClass.SIGNATURES) {
                    cls.setResolvingLevel(SootClass.SIGNATURES);
                }
                
                for (SootMethod method : cls.getMethods()) {
                    if (method.getName().equals(methodName)) {
                        if (paramTypes.isEmpty() || method.getParameterCount() == paramTypes.size()) {
                            methods.add(method);
                            count++;
                            
                            if (count >= maxResults) {
                                break;
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // 忽略错误
            }
        }
        
        return methods;
    }
    
    /**
     * 检查类是否可序列化（学习Flash的过滤策略）
     * 
     * 在反序列化攻击场景中，receiver 对象必须可序列化才能在攻击链中使用
     * 
     * @param cls 要检查的类
     * @return 如果类实现了 Serializable 接口则返回 true
     */
    private boolean isSerializableClass(SootClass cls) {
        if (cls == null) {
            return false;
        }
        
        try {
            // 获取 Serializable 接口
            SootClass serializableClass = Scene.v().getSootClassUnsafe("java.io.Serializable");
            if (serializableClass == null) {
                logger.warning("无法获取 java.io.Serializable 类");
                return false;
            }
            
            // 检查当前类是否是 Serializable（用于接口本身）
            if (cls.equals(serializableClass)) {
                return true;
            }
            
            // 快速路径：检查接口列表
            if (cls.getInterfaceCount() > 0) {
                for (SootClass iface : cls.getInterfaces()) {
                    if (iface.equals(serializableClass)) {
                        return true;
                    }
                    // 递归检查父接口
                    if (isSerializableClass(iface)) {
                        return true;
                    }
                }
            }
            
            // 递归检查父类
            if (cls.hasSuperclass()) {
                SootClass superClass = cls.getSuperclass();
                if (superClass != null && !superClass.getName().equals("java.lang.Object")) {
                    return isSerializableClass(superClass);
                }
            }
            
            return false;
        } catch (Exception e) {
            logger.fine("检查序列化性失败: " + cls.getName() + " - " + e.getMessage());
            return false;
        }
    }
}
