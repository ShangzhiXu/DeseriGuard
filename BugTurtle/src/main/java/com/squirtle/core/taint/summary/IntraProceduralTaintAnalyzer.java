package com.squirtle.core.taint.summary;

import soot.*;
import soot.jimple.*;
import java.util.Set;

/**
 * 过程内污点分析器（Intra-procedural Taint Analyzer）
 * 
 * 实现Flash的15条污点传播规则，在方法内部分析污点流动。
 * 
 * 污点传播规则：
 * 1. [Controllable-Field-Load]: x = o.field (field可控)
 * 2. [Tainted-Field-Load]: x = o.field (field污点)
 * 3. [Static-Field-Load]: x = Class.field
 * 4. [Instance-Field-Store]: o.field = x
 * 5. [Static-Field-Store]: Class.field = x
 * 6. [Instance-Call-Args]: o.m(a1, a2)
 * 7. [Static-Call-Args]: Class.m(a1, a2)
 * 8. [Instance-Call-Return]: x = o.m(...)
 * 9. [Static-Call-Return]: x = Class.m(...)
 * 10. [Call-Side-Effect-This]: o.m(...) 修改 o
 * 11. [Return-Side-Effect]: summary变化触发caller更新
 * 12. [Return-Stmt]: return x
 * 13. [Array-Load/Store]: x = arr[i] / arr[i] = x
 * 14. [Phi-Node]: 通过迭代自动处理
 * 15. [Cast-Propagation]: x = (Type) y
 * 
 * @see docs/减少UNKNOWN边的方案.md
 * @author BugTurtle
 * @version 2.0 - Summary-based Taint Analysis
 */
public class IntraProceduralTaintAnalyzer {
    
    /** 最大迭代次数（防止死循环） */
    private static final int MAX_ITERATIONS = 100;
    
    /**
     * 分析方法的过程内污点传播
     * 
     * @param method 待分析方法
     * @param globalState 全局状态
     * @return summary是否发生变化
     */
    public boolean analyzeMethod(SootMethod method, GlobalTaintState globalState) {
        // 无方法体的方法（abstract、native、phantom）直接返回
        if (!method.hasActiveBody()) {
            return false;
        }
        
        try {
            // 1. 创建过程内状态
            IntraProceduralTaintState state = new IntraProceduralTaintState(method);
            MethodTaintSummary summary = globalState.getOrCreateSummary(method);
            
            // 2. 应用参数污点（从summary）
            state.applyParameterTaints(summary);
            
            // 3. 迭代分析直到不动点
            boolean changed = true;
            int iteration = 0;
            
            while (changed && iteration < MAX_ITERATIONS) {
                changed = analyzeOnce(method, state, globalState, summary);
                iteration++;
            }
            
            if (iteration >= MAX_ITERATIONS) {
                System.err.println("[WARNING] 方法分析超过最大迭代次数: " + method.getSignature());
            }
            
            // 4. 提取返回值污点（已在processReturnStmt中处理）
            // summary的变化已经在分析过程中记录
            
            return false;  // 返回值在processReturnStmt中已处理
            
        } catch (Exception e) {
            System.err.println("[ERROR] 分析方法失败: " + method.getSignature());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 单次遍历分析（一轮迭代）
     * 
     * @param method 方法
     * @param state 过程内状态
     * @param globalState 全局状态
     * @param summary 方法摘要
     * @return 是否发生变化
     */
    private boolean analyzeOnce(SootMethod method,
                               IntraProceduralTaintState state,
                               GlobalTaintState globalState,
                               MethodTaintSummary summary) {
        boolean changed = false;
        
        // 遍历所有Jimple语句
        for (Unit unit : method.getActiveBody().getUnits()) {
            if (!(unit instanceof Stmt)) {
                continue;
            }
            
            Stmt stmt = (Stmt) unit;
            changed |= processStmt(stmt, state, globalState, summary, method);
        }
        
        return changed;
    }
    
    /**
     * 处理单个语句（分发到具体规则）
     * 
     * @param stmt 语句
     * @param state 过程内状态
     * @param globalState 全局状态
     * @param summary 方法摘要
     * @param method 当前方法
     * @return 是否发生变化
     */
    private boolean processStmt(Stmt stmt,
                               IntraProceduralTaintState state,
                               GlobalTaintState globalState,
                               MethodTaintSummary summary,
                               SootMethod method) {
        boolean changed = false;
        
        // AssignStmt: 规则1-11, 13, 15
        if (stmt instanceof AssignStmt) {
            changed |= processAssignStmt((AssignStmt) stmt, state, globalState, summary);
        }
        
        // InvokeStmt: 规则6-7, 10（仅副作用）
        else if (stmt instanceof InvokeStmt) {
            changed |= processInvokeStmt((InvokeStmt) stmt, state, globalState, summary);
        }
        
        // ReturnStmt: 规则12
        else if (stmt instanceof ReturnStmt) {
            changed |= processReturnStmt((ReturnStmt) stmt, state, globalState, summary, method);
        }
        
        // IdentityStmt: 已在初始化时处理，这里跳过
        
        return changed;
    }
    
    // ========== AssignStmt处理 ==========
    
    /**
     * 处理赋值语句
     * 
     * @param stmt 赋值语句
     * @param state 过程内状态
     * @param globalState 全局状态
     * @param summary 方法摘要
     * @return 是否发生变化
     */
    private boolean processAssignStmt(AssignStmt stmt,
                                     IntraProceduralTaintState state,
                                     GlobalTaintState globalState,
                                     MethodTaintSummary summary) {
        boolean changed = false;
        
        Value leftOp = stmt.getLeftOp();
        Value rightOp = stmt.getRightOp();
        
        // 规则1-3: 字段读取
        if (rightOp instanceof InstanceFieldRef) {
            changed |= processInstanceFieldLoad(leftOp, (InstanceFieldRef) rightOp, state, globalState);
        } else if (rightOp instanceof StaticFieldRef) {
            changed |= processStaticFieldLoad(leftOp, (StaticFieldRef) rightOp, state, globalState);
        }
        
        // 规则4-5: 字段存储
        if (leftOp instanceof InstanceFieldRef) {
            changed |= processInstanceFieldStore((InstanceFieldRef) leftOp, rightOp, state, globalState);
        } else if (leftOp instanceof StaticFieldRef) {
            changed |= processStaticFieldStore((StaticFieldRef) leftOp, rightOp, state, globalState);
        }
        
        // 规则6-10: 方法调用
        if (rightOp instanceof InvokeExpr) {
            changed |= processMethodCall(leftOp, (InvokeExpr) rightOp, state, globalState, summary);
        }
        
        // 规则13: 数组访问
        if (rightOp instanceof ArrayRef) {
            changed |= processArrayLoad(leftOp, (ArrayRef) rightOp, state);
        }
        if (leftOp instanceof ArrayRef) {
            changed |= processArrayStore((ArrayRef) leftOp, rightOp, state);
        }
        
        // 规则15: 类型转换
        if (rightOp instanceof CastExpr) {
            changed |= processCast(leftOp, (CastExpr) rightOp, state);
        }
        
        // 规则0: 普通赋值传播（x = y）
        if (rightOp instanceof Local) {
            if (state.isTainted(rightOp)) {
                changed |= state.markTainted(leftOp);
            }
        }
        
        return changed;
    }
    
    // ========== 字段访问处理 ==========
    
    /**
     * 规则1-2: 实例字段读取
     * τ(x) = τ(x) ∨ isControllable(field)  // 规则1（修正）
     * τ(x) = τ(x) ∨ τ(field)                // 规则2
     * 
     * 修正说明：可控字段本身就是污点源，不需要base也污点
     */
    private boolean processInstanceFieldLoad(Value leftOp,
                                            InstanceFieldRef fieldRef,
                                            IntraProceduralTaintState state,
                                            GlobalTaintState globalState) {
        boolean changed = false;
        Value base = fieldRef.getBase();
        SootField field = fieldRef.getField();
        
        // 规则1修正: field可控 → x污点（可控字段读取是污点源）
        if (globalState.isFieldControllable(field)) {
            changed |= state.markTainted(leftOp);
        }
        
        // 规则2: field全局污点 → x污点
        if (globalState.isFieldTainted(field)) {
            changed |= state.markTainted(leftOp);
        }
        
        return changed;
    }
    
    /**
     * 规则3: 静态字段读取
     * τ(x) = τ(x) ∨ τ(field)
     */
    private boolean processStaticFieldLoad(Value leftOp,
                                          StaticFieldRef fieldRef,
                                          IntraProceduralTaintState state,
                                          GlobalTaintState globalState) {
        SootField field = fieldRef.getField();
        
        if (globalState.isFieldTainted(field)) {
            return state.markTainted(leftOp);
        }
        
        return false;
    }
    
    /**
     * 规则4: 实例字段存储
     * τ(field) = τ(field) ∨ (τ(o) ∧ τ(x))
     */
    private boolean processInstanceFieldStore(InstanceFieldRef fieldRef,
                                             Value rightOp,
                                            IntraProceduralTaintState state,
                                             GlobalTaintState globalState) {
        Value base = fieldRef.getBase();
        SootField field = fieldRef.getField();
        
        // base污点 且 rightOp污点 → field污点
        if (state.isTainted(base) && state.isTainted(rightOp)) {
            return globalState.markFieldTainted(field);
        }
        
        return false;
    }
    
    /**
     * 规则5: 静态字段存储
     * τ(field) = τ(field) ∨ τ(x)
     */
    private boolean processStaticFieldStore(StaticFieldRef fieldRef,
                                           Value rightOp,
                                           IntraProceduralTaintState state,
                                           GlobalTaintState globalState) {
        SootField field = fieldRef.getField();
        
        if (state.isTainted(rightOp)) {
            return globalState.markFieldTainted(field);
        }
        
        return false;
    }
    
    // ========== 方法调用处理 ==========
    
    /**
     * 规则6-10: 方法调用（所有规则整合）
     * 
     * @param leftOp 接收返回值的变量（可能为null，如果是InvokeStmt）
     * @param invoke 调用表达式
     * @param state 过程内状态
     * @param globalState 全局状态
     * @param callerSummary 调用者摘要
     * @return 是否发生变化
     */
    private boolean processMethodCall(Value leftOp,
                                     InvokeExpr invoke,
                                     IntraProceduralTaintState state,
                                     GlobalTaintState globalState,
                                     MethodTaintSummary callerSummary) {
        boolean changed = false;
        
        SootMethod callee = invoke.getMethod();
        MethodTaintSummary calleeSummary = globalState.getOrCreateSummary(callee);
        
        // 规则6: 传播参数污点到callee的summary
        changed |= propagateArgumentTaints(invoke, state, globalState, calleeSummary);
        
        // 规则8-9: 传播返回值污点到leftOp
        if (leftOp != null) {
            changed |= propagateReturnTaint(leftOp, invoke, state, globalState, calleeSummary);
        }
        
        // 规则10: 传播this副作用到base
        changed |= propagateThisSideEffect(invoke, state, globalState, calleeSummary);
        
        return changed;
    }
    
    /**
     * 规则6-7: 传播参数污点
     * τ(g_this) = τ(g_this) ∨ τ(o)  (实例调用)
     * τ(pi) = τ(pi) ∨ τ(ai)
     */
    private boolean propagateArgumentTaints(InvokeExpr invoke,
                                           IntraProceduralTaintState state,
                                           GlobalTaintState globalState,
                                           MethodTaintSummary calleeSummary) {
        boolean changed = false;
        SootMethod callee = invoke.getMethod();
        
        // 实例调用：传播base到this
        if (invoke instanceof InstanceInvokeExpr) {
            Value base = ((InstanceInvokeExpr) invoke).getBase();
            if (state.isTainted(base)) {
                boolean summaryChanged = calleeSummary.setThisTainted(true);
                if (summaryChanged) {
                    // 触发worklist更新（规则11）
                    globalState.addToWorklist(callee);
                    changed = true;
                }
            }
        }
        
        // 传播参数污点
        for (int i = 0; i < invoke.getArgCount(); i++) {
            Value arg = invoke.getArg(i);
            if (state.isTainted(arg)) {
                boolean summaryChanged = calleeSummary.setParameterTainted(i, true);
                if (summaryChanged) {
                    globalState.addToWorklist(callee);
                    changed = true;
                }
            }
        }
        
        return changed;
    }
    
    /**
     * 规则8-9: 传播返回值污点
     * τ(x) = τ(x) ∨ (τ(g_ret) ∧ τ(o))  (实例调用, 规则8)
     * τ(x) = τ(x) ∨ τ(g_ret)            (静态调用, 规则9)
     */
    private boolean propagateReturnTaint(Value leftOp,
                                        InvokeExpr invoke,
                                        IntraProceduralTaintState state,
                                        GlobalTaintState globalState,
                                        MethodTaintSummary calleeSummary) {
        // 返回值污点
        if (!calleeSummary.isReturnTainted()) {
            return false;
        }
        
        // 实例调用：需要base也污点
        if (invoke instanceof InstanceInvokeExpr) {
            Value base = ((InstanceInvokeExpr) invoke).getBase();
            if (state.isTainted(base)) {
                return state.markTainted(leftOp);
            }
        }
        // 静态调用：直接传播
        else {
            return state.markTainted(leftOp);
        }
        
        return false;
    }
    
    /**
     * 规则10: 传播this的副作用
     * τ(o) = τ(o) ∨ (τ(g_this) ∧ τ(o_before))
     * 
     * 如果callee修改了this（τ(g_this)=true），则base也污点
     */
    private boolean propagateThisSideEffect(InvokeExpr invoke,
                                           IntraProceduralTaintState state,
                                           GlobalTaintState globalState,
                                           MethodTaintSummary calleeSummary) {
        if (!(invoke instanceof InstanceInvokeExpr)) {
            return false;
        }
        
        Value base = ((InstanceInvokeExpr) invoke).getBase();
        
        // callee的this污点 → base污点（副作用）
        if (calleeSummary.isThisTainted()) {
            return state.markTainted(base);
        }
        
        return false;
    }
    
    // ========== InvokeStmt处理 ==========
    
    /**
     * 处理无返回值的方法调用（仅副作用）
     */
    private boolean processInvokeStmt(InvokeStmt stmt,
                                     IntraProceduralTaintState state,
                                     GlobalTaintState globalState,
                                     MethodTaintSummary summary) {
        InvokeExpr invoke = stmt.getInvokeExpr();
        return processMethodCall(null, invoke, state, globalState, summary);
    }
    
    // ========== ReturnStmt处理 ==========
    
    /**
     * 规则12: 返回语句
     * τ(g_ret) = τ(g_ret) ∨ τ(x)
     */
    private boolean processReturnStmt(ReturnStmt stmt,
                                     IntraProceduralTaintState state,
                                     GlobalTaintState globalState,
                                     MethodTaintSummary summary,
                                     SootMethod method) {
        Value returnValue = stmt.getOp();
        
        if (state.isTainted(returnValue)) {
            boolean summaryChanged = summary.setReturnTainted(true);
            if (summaryChanged) {
                // 规则11: 将所有caller加入worklist
                Set<SootMethod> callers = globalState.getCallers(method);
                for (SootMethod caller : callers) {
                    globalState.addToWorklist(caller);
                }
                return true;
            }
        }
        
        return false;
    }
    
    // ========== 数组访问处理 ==========
    
    /**
     * 规则13: 数组读取
     * τ(x) = τ(x) ∨ τ(arr)
     */
    private boolean processArrayLoad(Value leftOp,
                                    ArrayRef arrayRef,
                                    IntraProceduralTaintState state) {
        Value base = arrayRef.getBase();
        
        // 保守：数组污点 → 元素污点
        if (state.isTainted(base)) {
            return state.markTainted(leftOp);
        }
        
        return false;
    }
    
    /**
     * 规则13: 数组存储
     * τ(arr) = τ(arr) ∨ τ(x)
     */
    private boolean processArrayStore(ArrayRef arrayRef,
                                     Value rightOp,
                                     IntraProceduralTaintState state) {
        Value base = arrayRef.getBase();
        
        // 元素污点 → 数组污点
        if (state.isTainted(rightOp)) {
            return state.markTainted(base);
        }
        
        return false;
    }
    
    // ========== 类型转换处理 ==========
    
    /**
     * 规则15: 类型转换
     * τ(x) = τ(x) ∨ τ(y)
     */
    private boolean processCast(Value leftOp,
                               CastExpr castExpr,
                               IntraProceduralTaintState state) {
        Value operand = castExpr.getOp();
        
        // 污点直接传播
        if (state.isTainted(operand)) {
            return state.markTainted(leftOp);
        }
        
        return false;
    }
}






