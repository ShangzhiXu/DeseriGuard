package com.squirtle.core.taint;

import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.fields.ControllableFieldGraph;
import com.squirtle.core.fields.FieldAccessGraph;
import com.squirtle.core.fields.FieldAccessGraph.FieldAccess;
import soot.*;
import soot.jimple.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * 字段敏感污点分析 - 核心实现
 * 
 * 实现设计文档中的：
 * - 第二步：污点源定义（所有可控字段的读取点）
 * - 第三步：污点传播规则（值级传播）
 * 
 * 核心设计：
 * 1. 污点源 = 所有可控字段的读取
 * 2. 只传播值，不传播对象引用
 * 3. 方法内传播 + 方法间传播
 * 
 * @author BugTurtle
 * @version 1.0 - 字段敏感污点分析
 */
public class FieldSensitiveTaintAnalysis {
    
    private static final Logger logger = Logger.getLogger(FieldSensitiveTaintAnalysis.class.getName());
    
    // 输入数据
    private CallGraph callGraph;
    private ControllableFieldGraph controllableFieldGraph;
    private FieldAccessGraph fieldAccessGraph;
    private Map<SootMethod, List<Unit>> methodBodies;
    
    // 污点分析结果
    private final Map<SootMethod, MethodTaintInfo> methodTaints;           // 方法级污点信息
    private final Map<Unit, Set<Value>> unitTaintedValues;                 // 语句级污点值
    private final Set<Value> globalTaintedValues;                          // 全局污点值集合
    
    // 工作列表
    private final Queue<SootMethod> methodWorkList;
    private final Set<SootMethod> processedMethods;
    
    // 迭代控制
    private static final int MAX_ITERATIONS = 20;
    private int currentIteration = 0;
    
    public FieldSensitiveTaintAnalysis() {
        this.methodTaints = new ConcurrentHashMap<>();
        this.unitTaintedValues = new ConcurrentHashMap<>();
        this.globalTaintedValues = ConcurrentHashMap.newKeySet();
        this.methodWorkList = new LinkedList<>();
        this.processedMethods = ConcurrentHashMap.newKeySet();
    }
    
    /**
     * 执行污点分析
     */
    public TaintAnalysisResult performAnalysis(
            CallGraph callGraph,
            ControllableFieldGraph controllableFieldGraph,
            FieldAccessGraph fieldAccessGraph,
            Map<SootMethod, List<Unit>> methodBodies) {
        
        logger.info("🎯 开始字段敏感污点分析...");
        long startTime = System.currentTimeMillis();
        
        this.callGraph = callGraph;
        this.controllableFieldGraph = controllableFieldGraph;
        this.fieldAccessGraph = fieldAccessGraph;
        this.methodBodies = methodBodies;
        
        // 清空之前的结果
        clear();
        
        // 第一步：识别污点源（可控字段的读取点）
        int taintSourceCount = identifyTaintSources();
        logger.info("✅ 识别了 " + taintSourceCount + " 个污点源");
        
        // 第二步：初始化工作列表（包含所有有方法体的方法）
        initializeWorkList();
        
        // 第三步：迭代传播污点
        propagateTaint();
        
        long duration = System.currentTimeMillis() - startTime;
        logger.info("✅ 污点分析完成，耗时: " + duration + "ms");
        
        return new TaintAnalysisResult(methodTaints, unitTaintedValues);
    }
    
    /**
     * 第二步：识别污点源
     * 
     * 🔥 关键修复：污点源定义（参考Flash和Tabby的真正做法）
     * 
     * 污点源有两类：
     * 1. **主要污点源**：readObject方法的参数
     *    - this对象（要反序列化的对象）
     *    - ObjectInputStream参数（从它读取的对象都是不可信的）
     * 
     * 2. **次要污点源**：可控字段的读取点
     *    - 这是污点传播的结果，不是真正的源头
     *    - 但为了兼容现有架构，也保留这部分
     */
    private int identifyTaintSources() {
        logger.info("📍 识别污点源...");
        int count = 0;
        
        // 🔥 第一类：readObject方法入口的参数（真正的污点源）
        count += identifyReadObjectParameterSources();
        
        // 第二类：可控字段读取点（保留以支持字段敏感分析）
        count += identifyControllableFieldSources();
        
        logger.info("发现 " + count + " 个污点源");
        return count;
    }
    
    /**
     * 🔥 识别readObject方法的参数作为污点源（关键修复）
     * 
     * 参考Tabby的做法：
     * - 在方法入口，将this和参数标记为POLLUTED
     * - 这是反序列化漏洞检测的真正污点源
     */
    private int identifyReadObjectParameterSources() {
        int count = 0;
        
        for (Map.Entry<SootMethod, List<Unit>> entry : methodBodies.entrySet()) {
            SootMethod method = entry.getKey();
            List<Unit> units = entry.getValue();
            
            // 只处理readObject方法
            if (!method.getName().equals("readObject")) {
                continue;
            }
            
            // 检查方法签名：void readObject(ObjectInputStream)
            if (method.getParameterCount() != 1) {
                continue;
            }
            if (!method.getParameterType(0).toString().equals("java.io.ObjectInputStream")) {
                continue;
            }
            
            logger.info("🔥 发现readObject方法，标记参数为污点源: " + method.getSignature());
            
            // 获取方法体的IdentityStmt（@this和@parameter语句）
            for (Unit unit : units) {
                if (unit instanceof IdentityStmt) {
                    IdentityStmt idStmt = (IdentityStmt) unit;
                    Value leftOp = idStmt.getLeftOp();
                    Value rightOp = idStmt.getRightOp();
                    
                    // 标记this对象为污点源（要反序列化的对象）
                    if (rightOp instanceof ThisRef) {
                        markValueAsTainted(method, unit, leftOp);
                        getOrCreateMethodTaintInfo(method).markThisAsTainted();
                        count++;
                        logger.info("  ✅ 污点源: this对象 = " + leftOp);
                    }
                    
                    // 标记ObjectInputStream参数为污点源（不可信的输入流）
                    if (rightOp instanceof ParameterRef) {
                        ParameterRef paramRef = (ParameterRef) rightOp;
                        int paramIndex = paramRef.getIndex();
                        markValueAsTainted(method, unit, leftOp);
                        getOrCreateMethodTaintInfo(method).markParameterAsTainted(paramIndex);
                        count++;
                        logger.info("  ✅ 污点源: 参数[" + paramIndex + "] = " + leftOp + 
                                   " : " + method.getParameterType(paramIndex));
                    }
                }
            }
        }
        
        if (count > 0) {
            logger.info("✅ 标记了 " + count + " 个readObject参数污点源");
        }
        return count;
    }
    
    /**
     * 识别可控字段读取点作为污点源（保留原有逻辑）
     */
    private int identifyControllableFieldSources() {
        int count = 0;
        
        Set<SootField> controllableFields = controllableFieldGraph.getAllControllableFields();
        
        for (SootField field : controllableFields) {
            // 获取该字段的所有读取访问
            Set<FieldAccess> reads = fieldAccessGraph.getFieldReads(field);
            
            for (FieldAccess read : reads) {
                SootMethod method = read.getMethod();
                Unit site = read.getAccessSite();
                Value taintedValue = read.getAccessValue();  // 读取到的值
                
                // 标记为污点
                markValueAsTainted(method, site, taintedValue);
                count++;
                
                logger.fine("🟡 污点源（字段读取）: " + field.getName() + " -> " + taintedValue + 
                           " in " + method.getName());
            }
        }
        
        if (count > 0) {
            logger.fine("标记了 " + count + " 个可控字段读取点");
        }
        return count;
    }
    
    /**
     * 初始化工作列表
     */
    private void initializeWorkList() {
        for (SootMethod method : methodBodies.keySet()) {
            methodWorkList.offer(method);
        }
        logger.info("工作列表初始化: " + methodWorkList.size() + " 个方法");
    }
    
    /**
     * 第三步：污点传播（迭代直到不动点）
     */
    private void propagateTaint() {
        logger.info("🔄 开始污点传播...");
        
        currentIteration = 0;
        boolean changed = true;
        
        while (changed && currentIteration < MAX_ITERATIONS) {
            currentIteration++;
            changed = false;
            
            logger.info("  迭代 " + currentIteration + "...");
            int methodsProcessed = 0;
            
            Queue<SootMethod> currentWorkList = new LinkedList<>(methodWorkList);
            methodWorkList.clear();
            
            while (!currentWorkList.isEmpty()) {
                SootMethod method = currentWorkList.poll();
                
                boolean methodChanged = analyzeMethod(method);
                if (methodChanged) {
                    changed = true;
                    methodsProcessed++;
                    
                    // 将调用者加入工作列表
                    for (CallGraph.CallEdge edge : callGraph.getIncomingEdges(method)) {
                        if (!methodWorkList.contains(edge.getCaller())) {
                            methodWorkList.offer(edge.getCaller());
                        }
                    }
                }
            }
            
            logger.info("    处理了 " + methodsProcessed + " 个方法");
        }
        
        if (currentIteration >= MAX_ITERATIONS) {
            logger.warning("⚠️ 污点传播达到最大迭代次数限制");
        }
        
        logger.info("✅ 污点传播完成，共迭代 " + currentIteration + " 次");
    }
    
    /**
     * 分析单个方法的污点传播
     */
    private boolean analyzeMethod(SootMethod method) {
        List<Unit> units = methodBodies.get(method);
        if (units == null || units.isEmpty()) {
            return false;
        }
        
        boolean changed = false;
        MethodTaintInfo methodInfo = getOrCreateMethodTaintInfo(method);
        int initialTaintCount = methodInfo.getTaintedValuesCount();
        
        // 方法内传播
        changed |= performIntraMethodPropagation(method, units, methodInfo);
        
        // 方法间传播（处理方法调用）
        changed |= performInterMethodPropagation(method, units, methodInfo);
        
        int finalTaintCount = methodInfo.getTaintedValuesCount();
        return finalTaintCount > initialTaintCount;
    }
    
    /**
     * 方法内污点传播
     * 
     * 规则（设计文档第三步）：
     * 1. 赋值传播: y = x → 如果x是污点，y也是污点
     * 2. 字段读取已在污点源识别阶段处理
     */
    private boolean performIntraMethodPropagation(SootMethod method, List<Unit> units, 
                                                  MethodTaintInfo methodInfo) {
        boolean changed = false;
        
        for (Unit unit : units) {
            if (unit instanceof AssignStmt) {
                AssignStmt assign = (AssignStmt) unit;
                Value leftOp = assign.getLeftOp();
                Value rightOp = assign.getRightOp();
                
                // 规则3：赋值传播 y = x
                if (isTainted(method, rightOp)) {
                    if (markValueAsTainted(method, unit, leftOp)) {
                        changed = true;
                        logger.finest("  📤 赋值传播: " + rightOp + " -> " + leftOp);
                    }
                }
            }
        }
        
        return changed;
    }
    
    /**
     * 方法间污点传播
     * 
     * 规则4（设计文档）：
     * - 如果 obj 是污点 → 被调用方法的 this 被污染
     * - 如果 arg 是污点 → 被调用方法的对应参数被污染
     * 
     * 规则5：返回值传播（需要被调用方法的分析结果）
     */
    private boolean performInterMethodPropagation(SootMethod method, List<Unit> units,
                                                  MethodTaintInfo methodInfo) {
        boolean changed = false;
        
        for (Unit unit : units) {
            if (!((unit instanceof Stmt) && ((Stmt) unit).containsInvokeExpr())) {
                continue;
            }
            
            Stmt stmt = (Stmt) unit;
            InvokeExpr invoke = stmt.getInvokeExpr();
            
            // 处理实例方法调用
            if (invoke instanceof InstanceInvokeExpr) {
                InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) invoke;
                Value base = instanceInvoke.getBase();
                
                // 如果base是污点，传播到被调用方法的this
                if (isTainted(method, base)) {
                    for (CallGraph.CallEdge edge : callGraph.getCallSiteEdges(unit)) {
                        SootMethod callee = edge.getCallee();
                        MethodTaintInfo calleeInfo = getOrCreateMethodTaintInfo(callee);
                        
                        if (calleeInfo.markThisAsTainted()) {
                            changed = true;
                            logger.finest("  📞 this污染传播: " + method.getName() + 
                                        " -> " + callee.getName());
                        }
                    }
                }
            }
            
            // 处理参数传播
            for (int i = 0; i < invoke.getArgCount(); i++) {
                Value arg = invoke.getArg(i);
                
                if (isTainted(method, arg)) {
                    for (CallGraph.CallEdge edge : callGraph.getCallSiteEdges(unit)) {
                        SootMethod callee = edge.getCallee();
                        MethodTaintInfo calleeInfo = getOrCreateMethodTaintInfo(callee);
                        
                        if (calleeInfo.markParameterAsTainted(i)) {
                            changed = true;
                            logger.finest("  📞 参数污染传播: arg" + i + " to " + callee.getName());
                        }
                    }
                }
            }
            
            // 处理返回值传播（如果被调用方法的返回值被污染）
            if (unit instanceof AssignStmt) {
                AssignStmt assign = (AssignStmt) unit;
                Value leftOp = assign.getLeftOp();
                
                for (CallGraph.CallEdge edge : callGraph.getCallSiteEdges(unit)) {
                    SootMethod callee = edge.getCallee();
                    MethodTaintInfo calleeInfo = getOrCreateMethodTaintInfo(callee);
                    
                    if (calleeInfo.isReturnTainted()) {
                        if (markValueAsTainted(method, unit, leftOp)) {
                            changed = true;
                            logger.finest("  📥 返回值污染传播: " + callee.getName() + 
                                        " -> " + leftOp);
                        }
                    }
                }
            }
        }
        
        return changed;
    }
    
    /**
     * 标记值为污点
     */
    private boolean markValueAsTainted(SootMethod method, Unit site, Value value) {
        if (value == null) return false;
        
        MethodTaintInfo methodInfo = getOrCreateMethodTaintInfo(method);
        boolean changed = methodInfo.addTaintedValue(value);
        
        if (changed) {
            unitTaintedValues.computeIfAbsent(site, k -> ConcurrentHashMap.newKeySet()).add(value);
            globalTaintedValues.add(value);
        }
        
        return changed;
    }
    
    /**
     * 检查值是否被污染
     */
    public boolean isTainted(SootMethod method, Value value) {
        if (value == null) return false;
        
        MethodTaintInfo methodInfo = methodTaints.get(method);
        if (methodInfo != null && methodInfo.isTainted(value)) {
            return true;
        }
        
        // 全局污点检查
        return globalTaintedValues.contains(value);
    }
    
    /**
     * 获取或创建方法污点信息
     */
    private MethodTaintInfo getOrCreateMethodTaintInfo(SootMethod method) {
        return methodTaints.computeIfAbsent(method, k -> new MethodTaintInfo(method));
    }
    
    /**
     * 清空分析结果
     */
    private void clear() {
        methodTaints.clear();
        unitTaintedValues.clear();
        globalTaintedValues.clear();
        methodWorkList.clear();
        processedMethods.clear();
        currentIteration = 0;
    }
    
    /**
     * 方法级污点信息
     */
    public static class MethodTaintInfo {
        private final SootMethod method;
        private final Set<Value> taintedValues;
        private boolean thisIsTainted;
        private final Set<Integer> taintedParameters;
        private boolean returnIsTainted;
        
        public MethodTaintInfo(SootMethod method) {
            this.method = method;
            this.taintedValues = ConcurrentHashMap.newKeySet();
            this.thisIsTainted = false;
            this.taintedParameters = ConcurrentHashMap.newKeySet();
            this.returnIsTainted = false;
        }
        
        public boolean addTaintedValue(Value value) {
            return taintedValues.add(value);
        }
        
        public boolean isTainted(Value value) {
            return taintedValues.contains(value);
        }
        
        public boolean markThisAsTainted() {
            if (!thisIsTainted) {
                thisIsTainted = true;
                return true;
            }
            return false;
        }
        
        public boolean isThisTainted() {
            return thisIsTainted;
        }
        
        public boolean markParameterAsTainted(int paramIndex) {
            return taintedParameters.add(paramIndex);
        }
        
        public boolean isParameterTainted(int paramIndex) {
            return taintedParameters.contains(paramIndex);
        }
        
        public boolean markReturnAsTainted() {
            if (!returnIsTainted) {
                returnIsTainted = true;
                return true;
            }
            return false;
        }
        
        public boolean isReturnTainted() {
            return returnIsTainted;
        }
        
        public int getTaintedValuesCount() {
            return taintedValues.size();
        }
        
        public Set<Value> getTaintedValues() {
            return Collections.unmodifiableSet(taintedValues);
        }
    }
    
    /**
     * 污点分析结果
     */
    public static class TaintAnalysisResult {
        private final Map<SootMethod, MethodTaintInfo> methodTaints;
        private final Map<Unit, Set<Value>> unitTaintedValues;
        
        public TaintAnalysisResult(Map<SootMethod, MethodTaintInfo> methodTaints,
                                  Map<Unit, Set<Value>> unitTaintedValues) {
            this.methodTaints = new HashMap<>(methodTaints);
            this.unitTaintedValues = new HashMap<>(unitTaintedValues);
        }
        
        public MethodTaintInfo getMethodTaintInfo(SootMethod method) {
            return methodTaints.get(method);
        }
        
        public Set<Value> getTaintedValues(Unit unit) {
            return unitTaintedValues.getOrDefault(unit, Collections.emptySet());
        }
        
        public Map<SootMethod, MethodTaintInfo> getAllMethodTaints() {
            return Collections.unmodifiableMap(methodTaints);
        }
    }
}







