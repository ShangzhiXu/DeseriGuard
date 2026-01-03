package com.squirtle.core.pruning;

import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.callgraph.CallGraph.CallEdge;
import com.squirtle.core.taint.FieldSensitiveTaintAnalysis;
import com.squirtle.core.taint.summary.GlobalTaintState;
import com.squirtle.core.taint.summary.MethodTaintSummary;
import soot.*;
import soot.jimple.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * 调用边可控性分析器
 * 
 * 实现设计文档第四步：调用边可控性判断
 * 
 * 判断规则（Summary-based污点分析）：
 * 1. 如果 callee 的 this 或任何参数是污点 → CONTROLLABLE
 * 2. 如果 obj 的静态类型是确定安全的类型 → UNCONTROLLABLE
 * 3. 否则 → UNKNOWN（Sound模式下视为CONTROLLABLE）
 * 
 * @author BugTurtle
 * @version 2.0 - Summary-based污点分析（Flash完整模型）
 */
public class CallEdgeControllabilityAnalyzer {
    
    private static final Logger logger = Logger.getLogger(CallEdgeControllabilityAnalyzer.class.getName());
    
    /**
     * 可控性枚举
     */
    public enum Controllability {
        CONTROLLABLE,       // 确定可控
        UNCONTROLLABLE,     // 确定不可控
        UNKNOWN             // 不确定（Sound模式下视为CONTROLLABLE）
    }
    
    // 确定安全的类型（设计文档第四步）
    // 
    // ⚠️ 注意：java.lang.Class 已从此列表移除！
    // 原因：在反序列化攻击中，Class 对象是可控的（如 CC1 链中的 TemplatesImpl.getTransletInstance()）
    // Class.newInstance(), Class.forName() 等都是常见的 gadget sink
    private static final Set<String> SAFE_TYPES = new HashSet<>(Arrays.asList(
        // 基础类型包装类
        "java.lang.Integer",
        "java.lang.Long",
        "java.lang.Boolean",
        "java.lang.Double",
        "java.lang.Float",
        "java.lang.Byte",
        "java.lang.Short",
        "java.lang.Character",
        
        // String类
        "java.lang.String"
        
        // ❌ 已移除 java.lang.Class - 在gadget链中可被利用
        // ❌ 已移除 java.lang.reflect.Method - 可用于反射调用
        // ❌ 已移除 java.lang.reflect.Field - 可用于字段访问
        // ❌ 已移除 java.lang.reflect.Constructor - 可用于实例化
    ));
    
    private GlobalTaintState globalTaintState;
    private FieldSensitiveTaintAnalysis.TaintAnalysisResult taintResult;  // 旧API兼容
    private Map<CallEdge, Controllability> edgeControllability;
    
    public CallEdgeControllabilityAnalyzer() {
        this.edgeControllability = new HashMap<>();
    }
    
    /**
     * 分析调用图的边可控性（旧API - 兼容AnalysisEngine）
     */
    public Map<CallEdge, Controllability> analyzeControllability(
            CallGraph callGraph,
            FieldSensitiveTaintAnalysis.TaintAnalysisResult taintResult) {
        
        logger.info("🎯 开始分析调用边可控性（Field-sensitive）...");
        this.taintResult = taintResult;
        this.globalTaintState = null;  // 使用旧API
        this.edgeControllability.clear();
        
        Set<CallEdge> allEdges = callGraph.getAllEdges();
        int controllable = 0;
        int uncontrollable = 0;
        int unknown = 0;
        
        for (CallEdge edge : allEdges) {
            Controllability controllability = analyzeEdgeControllability(edge);
            edgeControllability.put(edge, controllability);
            
            switch (controllability) {
                case CONTROLLABLE:
                    controllable++;
                    break;
                case UNCONTROLLABLE:
                    uncontrollable++;
                    break;
                case UNKNOWN:
                    unknown++;
                    break;
            }
        }
        
        logger.info("✅ 可控性分析完成:");
        logger.info("  可控边: " + controllable);
        logger.info("  不可控边: " + uncontrollable);
        logger.info("  未知边: " + unknown);
        
        return edgeControllability;
    }
    
    /**
     * 分析调用图的边可控性（新API - Summary-based）
     */
    public Map<CallEdge, Controllability> analyzeControllability(
            CallGraph callGraph,
            GlobalTaintState globalTaintState) {
        
        logger.info("🎯 开始分析调用边可控性（Summary-based）...");
        this.globalTaintState = globalTaintState;
        this.taintResult = null;  // 使用新API
        this.edgeControllability.clear();
        
        Set<CallEdge> allEdges = callGraph.getAllEdges();
        int controllable = 0;
        int uncontrollable = 0;
        int unknown = 0;
        
        for (CallEdge edge : allEdges) {
            Controllability controllability = analyzeEdgeControllability(edge);
            edgeControllability.put(edge, controllability);
            
            switch (controllability) {
                case CONTROLLABLE:
                    controllable++;
                    break;
                case UNCONTROLLABLE:
                    uncontrollable++;
                    break;
                case UNKNOWN:
                    unknown++;
                    break;
            }
        }
        
        logger.info("✅ 可控性分析完成:");
        logger.info("  可控边: " + controllable);
        logger.info("  不可控边: " + uncontrollable);
        logger.info("  未知边: " + unknown);
        
        return edgeControllability;
    }
    
    /**
     * 分析单条边的可控性
     */
    private Controllability analyzeEdgeControllability(CallEdge edge) {
        Unit callSite = edge.getCallSite();
        SootMethod caller = edge.getCaller();
        CallGraph.CallType callType = edge.getCallType();
        
        if (!(callSite instanceof Stmt)) {
            return Controllability.UNKNOWN;
        }
        
        Stmt stmt = (Stmt) callSite;
        if (!stmt.containsInvokeExpr()) {
            return Controllability.UNKNOWN;
        }
        
        InvokeExpr invoke = stmt.getInvokeExpr();
        
        // 特殊处理：反射和代理边（第五步）
        if (callType == CallGraph.CallType.REFLECTION) {
            return analyzeReflectionEdgeControllability(caller, invoke);
        }
        
        if (callType == CallGraph.CallType.PROXY) {
            return analyzeProxyEdgeControllability(caller, invoke);
        }
        
        // 规则1：检查base对象和参数的污点状态
        Controllability taintBasedControllability = checkTaintBasedControllability(caller, invoke);
        if (taintBasedControllability == Controllability.CONTROLLABLE) {
            return Controllability.CONTROLLABLE;
        }
        // 如果污点分析确定不可控，直接返回（不要被后续规则覆盖）
        if (taintBasedControllability == Controllability.UNCONTROLLABLE) {
            return Controllability.UNCONTROLLABLE;
        }
        
        // 规则2：类型敏感判断（只有污点分析返回UNKNOWN时才执行）
        Controllability typeBasedControllability = checkTypeBasedControllability(invoke);
        if (typeBasedControllability == Controllability.UNCONTROLLABLE) {
            return Controllability.UNCONTROLLABLE;
        }
        
        // 规则3：不确定的情况返回UNKNOWN
        return Controllability.UNKNOWN;
    }
    
    /**
     * 规则1：基于污点的可控性判断
     * 
     * 支持两种模式：
     * - Summary-based（新）：检查callee的this和参数是否污点
     * - Field-sensitive（旧）：检查caller中的base和参数值是否污点
     */
    private Controllability checkTaintBasedControllability(SootMethod caller, InvokeExpr invoke) {
        // 新API：Summary-based
        if (globalTaintState != null) {
            return checkTaintBasedControllability_SummaryBased(caller, invoke);
        }
        // 旧API：Field-sensitive
        else if (taintResult != null) {
            return checkTaintBasedControllability_FieldSensitive(caller, invoke);
        }
        
        return Controllability.UNKNOWN;
    }
    
    /**
     * 🔥 关键修复：调用点敏感的污点判断（参考Flash和Tabby）
     * 
     * **错误的做法（之前）**：
     * - 看被调用方法（callee）的全局摘要
     * - 问题：`HashMap.put()`的摘要可能说this和参数都是污点（因为某些调用点是污点）
     * - 结果：即使当前调用点`map.put(cleanKey, cleanValue)`不是污点，也会被误判为CONTROLLABLE
     * 
     * **正确的做法（现在）**：
     * - 看当前调用点（callSite）在caller方法中的污点状态
     * - 问题：`map.put(taintedKey, taintedValue)`中，taintedKey和taintedValue在这个调用点是否是污点？
     * - 结果：只有当前调用点的this或参数是污点时，才判断为CONTROLLABLE
     * 
     * 参考：
     * - Tabby: `SimpleTypeAnalysis.notContainsPollutedValue(ie.getUseBoxes(), container)`
     * - Flash: 在调用点查询参数的Contr值（`param-0`, `this`, `polluted`等）
     */
    private Controllability checkTaintBasedControllability_SummaryBased(SootMethod caller, InvokeExpr invoke) {
        // 🔥 关键修复：查询caller方法的摘要（不是callee的！）
        MethodTaintSummary callerSummary = globalTaintState.getSummary(caller);
        
        if (callerSummary == null) {
            // 如果caller没有摘要，说明caller方法没有被分析过
            // 这通常意味着caller不在污点传播路径上
            logger.finest("  ⚪ UNKNOWN - caller没有污点摘要");
            return Controllability.UNKNOWN;
        }
        
        // 🔥 特殊处理：如果caller是readObject或其他污点源方法，保守处理
        // 因为readObject内部的局部变量可能都被污染了，但我们无法精确追踪
        if (isSourceMethod(caller)) {
            // readObject方法内的调用，只要caller有污点（this或参数），就认为可能可控
            if (callerSummary.isThisTainted()) {
                logger.finest("  ✅ CONTROLLABLE - caller是readObject且this是污点");
                return Controllability.CONTROLLABLE;
            }
            for (int i = 0; i < caller.getParameterCount(); i++) {
                if (callerSummary.isParameterTainted(i)) {
                    logger.finest("  ✅ CONTROLLABLE - caller是readObject且参数[" + i + "]是污点");
                    return Controllability.CONTROLLABLE;
                }
            }
        }
        
        // 🔥 检查调用点的base对象是否是污点（在caller方法的上下文中）
        if (invoke instanceof InstanceInvokeExpr) {
            InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) invoke;
            Value base = instanceInvoke.getBase();
            
            // 检查base是否在caller方法中是污点
            if (isValueTaintedInMethod(base, callerSummary, caller)) {
                logger.finest("  ✅ CONTROLLABLE - 调用点的base对象在caller中是污点: " + base);
                return Controllability.CONTROLLABLE;
            }
        }
        
        // 🔥 检查调用点的参数是否是污点（在caller方法的上下文中）
        for (int i = 0; i < invoke.getArgCount(); i++) {
            Value arg = invoke.getArg(i);
            
            if (isValueTaintedInMethod(arg, callerSummary, caller)) {
                logger.finest("  ✅ CONTROLLABLE - 调用点的参数[" + i + "]在caller中是污点: " + arg);
                return Controllability.CONTROLLABLE;
            }
        }
        
        // 🔥 改进：不再直接返回UNCONTROLLABLE，而是返回UNKNOWN
        // 因为我们的污点追踪可能不够精确，保守一点避免漏报
        logger.finest("  ⚪ UNKNOWN - 调用点的this和参数在caller中都不是污点（保守处理）");
        return Controllability.UNKNOWN;
    }
    
    /**
     * 检查方法是否为Source方法（readObject等）
     */
    private boolean isSourceMethod(SootMethod method) {
        String sig = method.getSignature();
        return sig.contains(": void readObject(java.io.ObjectInputStream)");
    }
    
    /**
     * 🔥 检查一个Value在给定方法中是否是污点
     * 
     * 判断逻辑（参考Flash和Tabby）：
     * 1. 如果value是this引用，检查methodSummary.isThisTainted()
     * 2. 如果value是参数，检查methodSummary.isParameterTainted(index)
     * 3. 如果value是局部变量，检查它是否依赖于污点源（保守：返回false）
     * 4. 如果value是字段引用，检查字段是否可控（使用globalTaintState）
     * 5. 其他情况（常量等）：返回false
     */
    private boolean isValueTaintedInMethod(Value value, MethodTaintSummary methodSummary, SootMethod method) {
        // 情况1：Local变量（包括this和参数）
        if (value instanceof Local) {
            Local local = (Local) value;
            
            // 检查是否是this对象
            if (local.getName().equals("this") || local.getName().startsWith("this$")) {
                return methodSummary.isThisTainted();
            }
            
            // 检查是否是参数（Soot的参数命名通常是r0, r1, r2...或者保留参数名）
            // 但我们无法直接从Local判断它是不是参数，需要更精细的分析
            // 保守策略：检查方法摘要的所有参数是否有污点
            for (int i = 0; i < method.getParameterCount(); i++) {
                if (methodSummary.isParameterTainted(i)) {
                    // 如果某个参数是污点，保守地认为local可能是污点
                    // 注意：这会有误报，但为了不漏报，暂时这样处理
                    logger.finest("    参数[" + i + "]是污点，local可能被污染: " + local);
                    return true;
                }
            }
            
            // 局部变量可能是污点传播的结果，但我们无法精确判断
            // 保守策略：如果方法有污点源（this或参数），认为局部变量可能被污染
            return false;  // 这里返回false是为了更精确的剪枝
        }
        
        // 情况2：字段引用（实例字段或静态字段）
        if (value instanceof FieldRef) {
            FieldRef fieldRef = (FieldRef) value;
            SootField field = fieldRef.getField();
            
            // 检查字段是否可控
            if (globalTaintState.isFieldControllable(field)) {
                logger.finest("    字段是可控的: " + field.getSignature());
                return true;
            }
            
            return false;
        }
        
        // 情况3：常量（不是污点）
        if (value instanceof Constant) {
            return false;
        }
        
        // 其他情况：保守返回false（不认为是污点，允许剪枝）
        return false;
    }
    
    /**
     * Field-sensitive污点判断（旧逻辑）
     */
    private Controllability checkTaintBasedControllability_FieldSensitive(SootMethod caller, InvokeExpr invoke) {
        // 检查base对象
        if (invoke instanceof InstanceInvokeExpr) {
            InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) invoke;
            Value base = instanceInvoke.getBase();
            
            if (isTainted(caller, base)) {
                logger.finest("  ✅ CONTROLLABLE - base对象是污点");
                return Controllability.CONTROLLABLE;
            }
        }
        
        // 检查参数
        for (int i = 0; i < invoke.getArgCount(); i++) {
            Value arg = invoke.getArg(i);
            
            if (isTainted(caller, arg)) {
                logger.finest("  ✅ CONTROLLABLE - 参数" + i + "是污点");
                return Controllability.CONTROLLABLE;
            }
        }
        
        return Controllability.UNKNOWN;
    }
    
    /**
     * 检查值是否被污染（旧API使用）
     */
    private boolean isTainted(SootMethod method, Value value) {
        if (taintResult == null) return false;
        
        FieldSensitiveTaintAnalysis.MethodTaintInfo methodInfo = 
            taintResult.getMethodTaintInfo(method);
        
        if (methodInfo != null) {
            return methodInfo.isTainted(value);
        }
        
        return false;
    }
    
    /**
     * 规则2：基于类型的可控性判断
     */
    private Controllability checkTypeBasedControllability(InvokeExpr invoke) {
        if (invoke instanceof InstanceInvokeExpr) {
            InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) invoke;
            Value base = instanceInvoke.getBase();
            Type baseType = base.getType();
            
            // 只有在确定是安全类型时才标记为UNCONTROLLABLE
            if (baseType instanceof RefType) {
                RefType refType = (RefType) baseType;
                String className = refType.getClassName();
                
                if (SAFE_TYPES.contains(className)) {
                    logger.finest("  ❌ UNCONTROLLABLE - 安全类型: " + className);
                    return Controllability.UNCONTROLLABLE;
                }
            }
        }
        
        return Controllability.UNKNOWN;
    }
    
    /**
     * 第五步：分析反射边的可控性（Summary-based）
     * 
     * 规则：
     * - method.invoke(obj, args)
     * - 检查callee的this和参数是否污点
     */
    private Controllability analyzeReflectionEdgeControllability(SootMethod caller, InvokeExpr invoke) {
        // 反射边直接使用summary-based判断
        return checkTaintBasedControllability(caller, invoke);
    }
    
    /**
     * 第五步：分析代理边的可控性
     * 
     * 规则（设计文档）：
     * - proxyObj.method(args)
     * - 如果 proxyObj 或 args 是污点 → CONTROLLABLE
     * - 否则 → UNCONTROLLABLE
     */
    private Controllability analyzeProxyEdgeControllability(SootMethod caller, InvokeExpr invoke) {
        // 代理边直接使用summary-based判断
        return checkTaintBasedControllability(caller, invoke);
    }
    
    /**
     * 获取边的可控性
     */
    public Controllability getControllability(CallEdge edge) {
        return edgeControllability.getOrDefault(edge, Controllability.UNKNOWN);
    }
    
    /**
     * 检查边是否可控（Sound模式：UNKNOWN视为CONTROLLABLE）
     */
    public boolean isControllable(CallEdge edge, boolean soundMode) {
        Controllability c = getControllability(edge);
        
        if (soundMode) {
            // Sound模式：只有明确UNCONTROLLABLE的才不可控
            return c != Controllability.UNCONTROLLABLE;
        } else {
            // 精确模式：只有明确CONTROLLABLE的才可控
            return c == Controllability.CONTROLLABLE;
        }
    }
}
