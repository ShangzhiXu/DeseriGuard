package com.squirtle.core.reflection.core;

import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;

/**
 * 反射调用点信息
 * 
 * 记录一个反射调用的位置和上下文信息
 */
public class ReflectionCallSite {
    
    /**
     * 反射调用的类型
     */
    public enum ReflectionType {
        CONSTRUCTOR_NEW_INSTANCE,  // Constructor.newInstance()
        METHOD_INVOKE,             // Method.invoke()
        CLASS_NEW_INSTANCE         // Class.newInstance()
    }
    
    private final SootMethod containingMethod;  // 包含此反射调用的方法
    private final Unit callSite;                // 调用点（Jimple Unit）
    private final InvokeExpr invokeExpr;        // 调用表达式
    private final ReflectionType type;          // 反射类型
    
    public ReflectionCallSite(SootMethod containingMethod, Unit callSite, 
                             InvokeExpr invokeExpr, ReflectionType type) {
        this.containingMethod = containingMethod;
        this.callSite = callSite;
        this.invokeExpr = invokeExpr;
        this.type = type;
    }
    
    public SootMethod getContainingMethod() {
        return containingMethod;
    }
    
    public Unit getCallSite() {
        return callSite;
    }
    
    public InvokeExpr getInvokeExpr() {
        return invokeExpr;
    }
    
    public ReflectionType getType() {
        return type;
    }
    
    @Override
    public String toString() {
        return String.format("ReflectionCallSite[%s in %s]", 
            type, containingMethod.getSignature());
    }
}











