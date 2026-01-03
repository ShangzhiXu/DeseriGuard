package com.squirtle.core.taint.summary;

import soot.*;
import soot.jimple.*;
import java.util.*;

/**
 * 过程内污点状态（Intra-procedural Taint State）
 * 
 * 记录方法内部的污点状态，包括：
 * - Local变量的污点状态
 * - 参数索引到Local变量的映射
 * 
 * 与MethodTaintSummary的区别：
 * - MethodTaintSummary：方法级全局污点（参数、this、返回值）
 * - IntraProceduralTaintState：方法内局部污点（Local变量）
 * 
 * @see docs/减少UNKNOWN边的方案.md
 * @author BugTurtle
 * @version 2.0 - Summary-based Taint Analysis
 */
public class IntraProceduralTaintState {
    
    /** 所属方法 */
    private final SootMethod method;
    
    /** Local变量的污点状态 */
    private final Map<Local, Boolean> localTaints;
    
    /** 参数索引到Local变量的映射 */
    private final Map<Integer, Local> parameterLocals;
    
    /** this参数对应的Local变量（实例方法） */
    private Local thisLocal;
    
    /**
     * 构造函数
     * 
     * @param method 方法
     */
    public IntraProceduralTaintState(SootMethod method) {
        this.method = method;
        this.localTaints = new HashMap<>();
        this.parameterLocals = new HashMap<>();
        this.thisLocal = null;
        
        // 构建参数映射
        if (method.hasActiveBody()) {
            buildParameterMapping();
        }
    }
    
    /**
     * 构建参数索引到Local变量的映射
     * 
     * 在Jimple IR中，方法开头的IdentityStmt建立参数到Local的映射：
     * - r0 := @this: ClassName      // this → r0
     * - r1 := @parameter0: Type     // p0 → r1
     * - i0 := @parameter1: int      // p1 → i0
     */
    private void buildParameterMapping() {
        for (Unit unit : method.getActiveBody().getUnits()) {
            if (!(unit instanceof IdentityStmt)) {
                continue;
            }
            
            IdentityStmt idStmt = (IdentityStmt) unit;
            Value rightOp = idStmt.getRightOp();
            Local local = (Local) idStmt.getLeftOp();
            
            if (rightOp instanceof ThisRef) {
                // this参数
                this.thisLocal = local;
            } else if (rightOp instanceof ParameterRef) {
                // 普通参数
                ParameterRef paramRef = (ParameterRef) rightOp;
                int index = paramRef.getIndex();
                parameterLocals.put(index, local);
            }
        }
    }
    
    // ========== 污点查询和标记 ==========
    
    /**
     * 检查值是否为污点
     * 
     * @param v 值
     * @return 是否污点
     */
    public boolean isTainted(Value v) {
        if (v instanceof Local) {
            return localTaints.getOrDefault((Local) v, false);
        }
        // 其他类型（Constant、FieldRef等）默认不是污点
        return false;
    }
    
    /**
     * 标记值为污点
     * 
     * @param v 值
     * @return 是否发生变化
     */
    public boolean markTainted(Value v) {
        if (v instanceof Local) {
            Local local = (Local) v;
            Boolean oldValue = localTaints.put(local, true);
            return oldValue == null || !oldValue;  // 返回是否有变化
        }
        return false;
    }
    
    /**
     * 标记值为非污点
     * 
     * @param v 值
     * @return 是否发生变化
     */
    public boolean markUntainted(Value v) {
        if (v instanceof Local) {
            Local local = (Local) v;
            Boolean oldValue = localTaints.put(local, false);
            return oldValue != null && oldValue;  // 从true变为false
        }
        return false;
    }
    
    // ========== 参数污点应用 ==========
    
    /**
     * 应用方法摘要中的参数污点到Local变量
     * 
     * 这是过程间传播的入口：将caller传递的污点参数应用到callee的方法体
     * 
     * 对应Flash规则：
     * - [Instance-Call-Args]: τ(g_this) = τ(g_this) ∨ τ(o)
     * - [Instance-Call-Args]: τ(pi) = τ(pi) ∨ τ(ai)
     * 
     * @param summary 方法摘要
     * @return 是否发生变化
     */
    public boolean applyParameterTaints(MethodTaintSummary summary) {
        if (summary.getMethod() != this.method) {
            throw new IllegalArgumentException("方法不匹配");
        }
        
        boolean changed = false;
        
        // 应用this污点
        if (summary.isThisTainted() && thisLocal != null) {
            changed |= markTainted(thisLocal);
        }
        
        // 应用参数污点
        for (int i = 0; i < summary.getParameterCount(); i++) {
            if (summary.isParameterTainted(i)) {
                Local paramLocal = parameterLocals.get(i);
                if (paramLocal != null) {
                    changed |= markTainted(paramLocal);
                }
            }
        }
        
        return changed;
    }
    
    // ========== Getters ==========
    
    public SootMethod getMethod() {
        return method;
    }
    
    public Local getThisLocal() {
        return thisLocal;
    }
    
    public Local getParameterLocal(int index) {
        return parameterLocals.get(index);
    }
    
    public Map<Local, Boolean> getLocalTaints() {
        return Collections.unmodifiableMap(localTaints);
    }
    
    /**
     * 获取所有被标记为污点的Local变量
     * 
     * @return 污点Local集合
     */
    public Set<Local> getTaintedLocals() {
        Set<Local> tainted = new HashSet<>();
        for (Map.Entry<Local, Boolean> entry : localTaints.entrySet()) {
            if (entry.getValue()) {
                tainted.add(entry.getKey());
            }
        }
        return tainted;
    }
    
    /**
     * 转换为可读字符串（用于调试）
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("IntraProceduralTaintState{");
        sb.append("method=").append(method.getName());
        sb.append(", thisLocal=").append(thisLocal);
        sb.append(", paramLocals=").append(parameterLocals);
        sb.append(", taintedLocals=").append(getTaintedLocals().size());
        sb.append('}');
        return sb.toString();
    }
}






