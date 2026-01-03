package com.squirtle.core.reflection.controllability;

import soot.*;
import soot.jimple.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Modifier;
import java.util.*;

/**
 * 反射目标可控性分析器
 * 
 * 分析调用 Method.invoke / Constructor.newInstance 的方法，
 * 判断反射目标（方法名/类名）是否可被攻击者控制。
 * 
 * <p><b>核心思路</b>：
 * <ul>
 *   <li>如果 getMethod("constant") 的参数是字符串常量 → 不可控</li>
 *   <li>如果 getMethod(this.fieldName) 的参数来自可序列化字段 → 可控</li>
 *   <li>无法判断时 → 保守处理为 UNKNOWN（保持 soundness）</li>
 * </ul>
 * 
 * <p><b>典型案例</b>：
 * <ul>
 *   <li>InvokerTransformer: iMethodName 是可序列化字段 → CONTROLLABLE</li>
 *   <li>PrototypeCloneFactory: 硬编码 "clone" → NOT_CONTROLLABLE</li>
 * </ul>
 * 
 * @author BugTurtle
 */
public class ReflectionControllabilityAnalyzer {
    
    private static final Logger logger = LoggerFactory.getLogger(ReflectionControllabilityAnalyzer.class);
    
    /**
     * 反射目标的可控性状态
     */
    public enum Controllability {
        /** 可控：方法名/类名来自可序列化字段，攻击者可以通过反序列化控制 */
        CONTROLLABLE,
        
        /** 不可控：方法名/类名是硬编码的常量 */
        NOT_CONTROLLABLE,
        
        /** 未知：无法确定，保守处理为可控（保持 soundness） */
        UNKNOWN
    }
    
    /**
     * 分析结果
     */
    public static class AnalysisResult {
        private final Controllability controllability;
        private final String reason;
        private final String methodNameValue;  // 如果是常量，记录具体值
        
        public AnalysisResult(Controllability controllability, String reason) {
            this(controllability, reason, null);
        }
        
        public AnalysisResult(Controllability controllability, String reason, String methodNameValue) {
            this.controllability = controllability;
            this.reason = reason;
            this.methodNameValue = methodNameValue;
        }
        
        public Controllability getControllability() {
            return controllability;
        }
        
        public String getReason() {
            return reason;
        }
        
        public String getMethodNameValue() {
            return methodNameValue;
        }
        
        public boolean isControllable() {
            // UNKNOWN 保守处理为可控
            return controllability != Controllability.NOT_CONTROLLABLE;
        }
        
        @Override
        public String toString() {
            return controllability + ": " + reason + 
                   (methodNameValue != null ? " (value: " + methodNameValue + ")" : "");
        }
    }
    
    // 分析结果缓存
    private final Map<String, AnalysisResult> cache = new HashMap<>();
    
    /**
     * 分析调用反射方法的方法，判断反射目标是否可控
     * 
     * @param caller 调用 Method.invoke 的方法（如 InvokerTransformer.transform）
     * @return 分析结果
     */
    public AnalysisResult analyzeControllability(SootMethod caller) {
        String key = caller.getSignature();
        
        // 检查缓存
        if (cache.containsKey(key)) {
            return cache.get(key);
        }
        
        AnalysisResult result = doAnalyze(caller);
        cache.put(key, result);
        
        logger.debug("反射可控性分析: {} → {}", caller.getName(), result);
        return result;
    }
    
    /**
     * 执行实际分析
     */
    private AnalysisResult doAnalyze(SootMethod caller) {
        // 检查方法是否有方法体
        if (!caller.hasActiveBody()) {
            try {
                caller.retrieveActiveBody();
            } catch (Exception e) {
                return new AnalysisResult(Controllability.UNKNOWN, 
                    "无法获取方法体: " + e.getMessage());
            }
        }
        
        if (!caller.hasActiveBody()) {
            return new AnalysisResult(Controllability.UNKNOWN, "方法没有方法体");
        }
        
        Body body = caller.getActiveBody();
        SootClass declaringClass = caller.getDeclaringClass();
        
        // 查找 getMethod / getDeclaredMethod 调用
        List<GetMethodCallInfo> getMethodCalls = findGetMethodCalls(body);
        
        if (getMethodCalls.isEmpty()) {
            // 没有找到 getMethod 调用，可能是其他反射模式
            // 检查是否有直接的字段访问模式（如存储 Method 对象）
            return analyzeMethodFieldPattern(body, declaringClass);
        }
        
        // 分析每个 getMethod 调用
        for (GetMethodCallInfo callInfo : getMethodCalls) {
            AnalysisResult result = analyzeGetMethodCall(callInfo, body, declaringClass);
            
            // 如果发现任何一个是常量（不可控），整体就是不可控
            if (result.getControllability() == Controllability.NOT_CONTROLLABLE) {
                return result;
            }
            
            // 如果发现可控的，记录下来
            if (result.getControllability() == Controllability.CONTROLLABLE) {
                return result;
            }
        }
        
        return new AnalysisResult(Controllability.UNKNOWN, "无法确定 getMethod 参数来源");
    }
    
    /**
     * 查找方法体中的 getMethod / getDeclaredMethod 调用
     */
    private List<GetMethodCallInfo> findGetMethodCalls(Body body) {
        List<GetMethodCallInfo> calls = new ArrayList<>();
        
        for (Unit unit : body.getUnits()) {
            if (!(unit instanceof Stmt)) continue;
            Stmt stmt = (Stmt) unit;
            
            if (!stmt.containsInvokeExpr()) continue;
            InvokeExpr invoke = stmt.getInvokeExpr();
            
            SootMethod method = invoke.getMethod();
            String methodName = method.getName();
            String className = method.getDeclaringClass().getName();
            
            // 检查是否是 Class.getMethod 或 Class.getDeclaredMethod
            if (className.equals("java.lang.Class") && 
                (methodName.equals("getMethod") || methodName.equals("getDeclaredMethod"))) {
                
                if (invoke.getArgCount() > 0) {
                    Value methodNameArg = invoke.getArg(0);
                    calls.add(new GetMethodCallInfo(stmt, invoke, methodNameArg));
                }
            }
        }
        
        return calls;
    }
    
    /**
     * 分析单个 getMethod 调用
     */
    private AnalysisResult analyzeGetMethodCall(GetMethodCallInfo callInfo, Body body, SootClass declaringClass) {
        Value methodNameArg = callInfo.methodNameArg;
        
        // 情况1：直接是字符串常量
        if (methodNameArg instanceof StringConstant) {
            String value = ((StringConstant) methodNameArg).value;
            return new AnalysisResult(Controllability.NOT_CONTROLLABLE, 
                "方法名是字符串常量", value);
        }
        
        // 情况2：是 Local 变量，需要回溯
        if (methodNameArg instanceof Local) {
            return traceLocalOrigin((Local) methodNameArg, body, declaringClass);
        }
        
        // 情况3：直接是字段引用
        if (methodNameArg instanceof InstanceFieldRef) {
            return analyzeFieldRef((InstanceFieldRef) methodNameArg, declaringClass);
        }
        
        return new AnalysisResult(Controllability.UNKNOWN, 
            "无法识别的参数类型: " + methodNameArg.getClass().getSimpleName());
    }
    
    /**
     * 回溯 Local 变量的来源（使用工作列表算法，无硬编码深度限制）
     * 
     * 核心思想：使用visited集合检测循环，而非硬编码深度限制
     * 优点：自动适应任意深度的数据流，同时避免无限循环
     */
    private AnalysisResult traceLocalOrigin(Local local, Body body, SootClass declaringClass) {
        Set<Local> visited = new HashSet<>();
        Deque<Local> worklist = new ArrayDeque<>();
        worklist.add(local);
        
        while (!worklist.isEmpty()) {
            Local current = worklist.poll();
            
            // 循环检测：已访问过的Local跳过
            if (visited.contains(current)) {
                continue;
            }
            visited.add(current);
            
            // 检查是否是方法参数
            int paramIndex = getParameterIndex(current, body);
            if (paramIndex >= 0) {
                return new AnalysisResult(Controllability.UNKNOWN, 
                    "方法名来自参数 " + paramIndex + "，需要跨方法分析");
            }
            
            // 在方法体中查找对该 Local 的赋值
            for (Unit unit : body.getUnits()) {
                if (!(unit instanceof AssignStmt)) continue;
                
                AssignStmt assign = (AssignStmt) unit;
                if (!assign.getLeftOp().equals(current)) continue;
                
                Value rightOp = assign.getRightOp();
                
                // 来自字符串常量 → 不可控
                if (rightOp instanceof StringConstant) {
                    String value = ((StringConstant) rightOp).value;
                    return new AnalysisResult(Controllability.NOT_CONTROLLABLE, 
                        "Local 来自字符串常量", value);
                }
                
                // 来自实例字段 → 分析字段
                if (rightOp instanceof InstanceFieldRef) {
                    return analyzeFieldRef((InstanceFieldRef) rightOp, declaringClass);
                }
                
                // 来自另一个 Local → 加入工作列表继续追溯（无深度限制）
                if (rightOp instanceof Local) {
                    worklist.add((Local) rightOp);
                }
                
                // 来自方法调用（如 String.valueOf、toString 等）
                if (rightOp instanceof InvokeExpr) {
                    InvokeExpr invoke = (InvokeExpr) rightOp;
                    if (invoke instanceof VirtualInvokeExpr) {
                        VirtualInvokeExpr virtInvoke = (VirtualInvokeExpr) invoke;
                        if (virtInvoke.getBase() instanceof Local) {
                            // 继续追溯 base
                            worklist.add((Local) virtInvoke.getBase());
                        }
                    }
                    // 检查参数是否来自可控源
                    for (Value arg : invoke.getArgs()) {
                        if (arg instanceof Local) {
                            worklist.add((Local) arg);
                        }
                    }
                }
            }
        }
        
        return new AnalysisResult(Controllability.UNKNOWN, "无法追溯 Local 变量来源");
    }
    
    /**
     * 分析字段引用
     */
    private AnalysisResult analyzeFieldRef(InstanceFieldRef fieldRef, SootClass declaringClass) {
        SootField field = fieldRef.getField();
        SootClass fieldClass = field.getDeclaringClass();
        
        // 检查字段所在类是否实现 Serializable
        if (isSerializable(fieldClass)) {
            // 检查字段是否是 transient
            if (Modifier.isTransient(field.getModifiers())) {
                return new AnalysisResult(Controllability.NOT_CONTROLLABLE, 
                    "字段 " + field.getName() + " 是 transient，不会被序列化");
            }
            
            return new AnalysisResult(Controllability.CONTROLLABLE, 
                "字段 " + field.getName() + " 来自 Serializable 类 " + fieldClass.getName());
        }
        
        return new AnalysisResult(Controllability.UNKNOWN, 
            "字段 " + field.getName() + " 所在类 " + fieldClass.getName() + " 不是 Serializable");
    }
    
    /**
     * 分析 Method 字段存储模式（如 PrototypeCloneFactory 存储 Method 对象）
     */
    private AnalysisResult analyzeMethodFieldPattern(Body body, SootClass declaringClass) {
        logger.debug("analyzeMethodFieldPattern: 分析类 {}", declaringClass.getName());
        
        // 策略1：查找类中存储 Method 类型的字段
        for (SootField field : declaringClass.getFields()) {
            String typeName = field.getType().toString();
            logger.trace("检查字段: {} : {}", field.getName(), typeName);
            
            if (typeName.equals("java.lang.reflect.Method") || typeName.contains("Method")) {
                logger.debug("找到 Method 类型字段: {}", field.getName());
                
                // 🔥 关键修复：如果类是可序列化的且字段不是 transient，默认为可控
                // 因为攻击者可以通过反序列化控制字段值
                if (isSerializable(declaringClass) && !Modifier.isTransient(field.getModifiers())) {
                    logger.debug("字段 {} 在可序列化类中且非 transient，判断为可控", field.getName());
                    return new AnalysisResult(Controllability.CONTROLLABLE,
                        "Method 字段在可序列化类中: " + field.getName());
                }
                
                // 找到 Method 类型字段，检查它是如何初始化的
                AnalysisResult initResult = analyzeMethodFieldInitialization(field, declaringClass);
                logger.debug("字段初始化分析结果: {}", initResult);
                if (initResult != null) {
                    return initResult;
                }
            }
        }
        
        // 策略2：分析方法体中的 Method.invoke 调用，追溯 Method 对象来源
        for (Unit unit : body.getUnits()) {
            if (!(unit instanceof Stmt)) continue;
            Stmt stmt = (Stmt) unit;
            if (!stmt.containsInvokeExpr()) continue;
            
            InvokeExpr invoke = stmt.getInvokeExpr();
            SootMethod calledMethod = invoke.getMethod();
            
            // 检查是否是 Method.invoke 调用
            if (calledMethod.getDeclaringClass().getName().equals("java.lang.reflect.Method") &&
                calledMethod.getName().equals("invoke")) {
                
                // 获取 Method 对象（base）
                if (invoke instanceof VirtualInvokeExpr) {
                    Value methodObj = ((VirtualInvokeExpr) invoke).getBase();
                    
                    // 追溯 Method 对象的来源
                    AnalysisResult result = traceMethodObjectOrigin(methodObj, body, declaringClass);
                    if (result != null) {
                        return result;
                    }
                }
            }
        }
        
        return new AnalysisResult(Controllability.UNKNOWN, "没有找到 getMethod 调用或 Method 字段");
    }
    
    /**
     * 追溯 Method 对象的来源
     */
    private AnalysisResult traceMethodObjectOrigin(Value methodObj, Body body, SootClass declaringClass) {
        // 如果直接是字段引用
        if (methodObj instanceof InstanceFieldRef) {
            SootField field = ((InstanceFieldRef) methodObj).getField();
            
            // 🔥 关键修复：如果 Method 对象来自可序列化类的字段，默认为可控
            // 因为字段值可以通过反序列化被攻击者控制
            if (isSerializable(declaringClass) && !Modifier.isTransient(field.getModifiers())) {
                logger.debug("Method 对象来自可序列化字段 {}.{}, 判断为可控", 
                    declaringClass.getShortName(), field.getName());
                return new AnalysisResult(Controllability.CONTROLLABLE,
                    "Method 对象来自可序列化字段: " + field.getName());
            }
            
            return analyzeMethodFieldInitialization(field, declaringClass);
        }
        
        // 如果是 Local 变量，追溯赋值
        if (methodObj instanceof Local) {
            Local local = (Local) methodObj;
            
            for (Unit unit : body.getUnits()) {
                if (!(unit instanceof AssignStmt)) continue;
                AssignStmt assign = (AssignStmt) unit;
                
                if (!assign.getLeftOp().equals(local)) continue;
                
                Value rightOp = assign.getRightOp();
                
                // 来自字段
                if (rightOp instanceof InstanceFieldRef) {
                    SootField field = ((InstanceFieldRef) rightOp).getField();
                    
                    // 🔥 关键修复：如果 Method 对象来自可序列化类的字段，默认为可控
                    if (isSerializable(declaringClass) && !Modifier.isTransient(field.getModifiers())) {
                        logger.debug("Method 对象来自可序列化字段 {}.{}, 判断为可控", 
                            declaringClass.getShortName(), field.getName());
                        return new AnalysisResult(Controllability.CONTROLLABLE,
                            "Method 对象来自可序列化字段: " + field.getName());
                    }
                    
                    return analyzeMethodFieldInitialization(field, declaringClass);
                }
                
                // 直接是 getMethod 调用
                if (rightOp instanceof VirtualInvokeExpr) {
                    VirtualInvokeExpr vinvoke = (VirtualInvokeExpr) rightOp;
                    String methodName = vinvoke.getMethod().getName();
                    
                    if (methodName.equals("getMethod") || methodName.equals("getDeclaredMethod")) {
                        if (vinvoke.getArgCount() > 0) {
                            Value arg = vinvoke.getArg(0);
                            if (arg instanceof StringConstant) {
                                String value = ((StringConstant) arg).value;
                                return new AnalysisResult(Controllability.NOT_CONTROLLABLE,
                                    "Method 对象来自常量 getMethod 调用", value);
                            }
                        }
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * 分析 Method 字段的初始化
     */
    private AnalysisResult analyzeMethodFieldInitialization(SootField methodField, SootClass declaringClass) {
        logger.debug("analyzeMethodFieldInitialization: 查找字段 {} 的初始化", methodField.getName());
        
        // 检查所有方法（不仅是构造函数，因为字段可能在其他方法中初始化，如 findCloneMethod）
        for (SootMethod method : declaringClass.getMethods()) {
            // 跳过 create 方法本身（我们要找的是初始化字段的方法）
            if (method.getName().equals("create")) {
                continue;
            }
            
            logger.trace("检查方法: {}", method.getName());
            
            if (!method.hasActiveBody()) {
                try {
                    method.retrieveActiveBody();
                } catch (Exception e) {
                    logger.trace("无法加载方法体: {}", e.getMessage());
                    continue;
                }
            }
            
            if (!method.hasActiveBody()) continue;
            
            Body body = method.getActiveBody();
            
            // 查找对该字段的赋值，同时也查找任何 getMethod 调用
            boolean foundFieldAssign = false;
            for (Unit unit : body.getUnits()) {
                if (!(unit instanceof AssignStmt)) continue;
                
                AssignStmt assign = (AssignStmt) unit;
                Value leftOp = assign.getLeftOp();
                Value rightOp = assign.getRightOp();
                
                // 检查是否有 getMethod 调用（不管赋值给谁）
                if (rightOp instanceof VirtualInvokeExpr) {
                    VirtualInvokeExpr invoke = (VirtualInvokeExpr) rightOp;
                    String invokedMethodName = invoke.getMethod().getName();
                    
                    if (invokedMethodName.equals("getMethod") || invokedMethodName.equals("getDeclaredMethod")) {
                        logger.debug("发现 {} 调用: {}", invokedMethodName, unit);
                        if (invoke.getArgCount() > 0) {
                            Value arg = invoke.getArg(0);
                            logger.trace("第一个参数: {} (类型: {})", arg, arg.getClass().getSimpleName());
                            if (arg instanceof StringConstant) {
                                String value = ((StringConstant) arg).value;
                                logger.debug("是字符串常量: \"{}\"", value);
                                return new AnalysisResult(Controllability.NOT_CONTROLLABLE,
                                    "getMethod 使用常量方法名", value);
                            }
                        }
                    }
                }
                
                // 检查字段赋值
                if (leftOp instanceof InstanceFieldRef) {
                    InstanceFieldRef fieldRef = (InstanceFieldRef) leftOp;
                    String fieldName = fieldRef.getField().getName();
                    if (fieldName.equals(methodField.getName())) {
                        foundFieldAssign = true;
                        logger.trace("发现字段赋值: {} = {}", fieldName, rightOp.getClass().getSimpleName());
                    }
                }
            }
            
            if (foundFieldAssign) {
                logger.trace("找到字段赋值但没有找到常量 getMethod");
            }
        }
        
        return null;
    }
    
    /**
     * 获取 Local 变量对应的参数索引（如果是参数的话）
     */
    private int getParameterIndex(Local local, Body body) {
        int index = 0;
        for (Local param : body.getParameterLocals()) {
            if (param.equals(local)) {
                return index;
            }
            index++;
        }
        return -1;
    }
    
    /**
     * 检查类是否实现 Serializable
     */
    private boolean isSerializable(SootClass cls) {
        try {
            SootClass serializable = Scene.v().getSootClassUnsafe("java.io.Serializable");
            if (serializable == null) {
                return false;
            }
            return implementsInterface(cls, serializable);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 递归检查类是否实现指定接口
     */
    private boolean implementsInterface(SootClass cls, SootClass targetInterface) {
        if (cls == null) return false;
        
        // 检查直接实现的接口
        for (SootClass intf : cls.getInterfaces()) {
            if (intf.equals(targetInterface)) {
                return true;
            }
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
     * 清除缓存
     */
    public void clearCache() {
        cache.clear();
    }
    
    /**
     * getMethod 调用信息
     */
    private static class GetMethodCallInfo {
        final Stmt stmt;
        final InvokeExpr invoke;
        final Value methodNameArg;
        
        GetMethodCallInfo(Stmt stmt, InvokeExpr invoke, Value methodNameArg) {
            this.stmt = stmt;
            this.invoke = invoke;
            this.methodNameArg = methodNameArg;
        }
    }
}
