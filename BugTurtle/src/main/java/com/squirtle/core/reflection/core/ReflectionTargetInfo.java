package com.squirtle.core.reflection.core;

import soot.SootClass;
import soot.SootMethod;
import soot.Type;

import java.util.List;

/**
 * 反射目标信息
 * 
 * 封装反射调用可能的目标方法或构造函数
 */
public class ReflectionTargetInfo {
    
    /**
     * 推断策略
     */
    public enum InferenceStrategy {
        PRECISE,     // 策略1：精确推断（字面量、常量）
        HEURISTIC    // 策略2：启发式推断（类型约束、全局搜索）
    }
    
    private final SootMethod targetMethod;           // 目标方法或构造函数
    private final InferenceStrategy strategy;        // 使用的推断策略
    private final String reason;                     // 推断原因（用于调试）
    
    // 构造函数反射的额外信息
    private final SootClass targetClass;             // 目标类
    private final List<Type> parameterTypes;         // 参数类型
    
    // 方法反射的额外信息
    private final String methodName;                 // 方法名
    
    /**
     * 构造函数反射目标
     */
    public ReflectionTargetInfo(SootMethod targetMethod, SootClass targetClass,
                               List<Type> parameterTypes, InferenceStrategy strategy, String reason) {
        this.targetMethod = targetMethod;
        this.targetClass = targetClass;
        this.parameterTypes = parameterTypes;
        this.methodName = null;
        this.strategy = strategy;
        this.reason = reason;
    }
    
    /**
     * 方法反射目标
     */
    public ReflectionTargetInfo(SootMethod targetMethod, String methodName,
                               List<Type> parameterTypes, InferenceStrategy strategy, String reason) {
        this.targetMethod = targetMethod;
        this.targetClass = targetMethod.getDeclaringClass();
        this.parameterTypes = parameterTypes;
        this.methodName = methodName;
        this.strategy = strategy;
        this.reason = reason;
    }
    
    public SootMethod getTargetMethod() {
        return targetMethod;
    }
    
    public SootClass getTargetClass() {
        return targetClass;
    }
    
    public List<Type> getParameterTypes() {
        return parameterTypes;
    }
    
    public String getMethodName() {
        return methodName;
    }
    
    public InferenceStrategy getStrategy() {
        return strategy;
    }
    
    public String getReason() {
        return reason;
    }
    
    public boolean isPrecise() {
        return strategy == InferenceStrategy.PRECISE;
    }
    
    @Override
    public String toString() {
        return String.format("ReflectionTarget[%s, strategy=%s, reason=%s]",
            targetMethod.getSignature(), strategy, reason);
    }
}











