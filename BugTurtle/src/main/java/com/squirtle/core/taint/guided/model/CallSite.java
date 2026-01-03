package com.squirtle.core.taint.guided.model;

import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.jimple.InvokeExpr;
import java.util.*;

/**
 * 调用点信息（支持VSA值集传播）
 * 
 * 包含调用的所有上下文信息：
 * - 调用语句和表达式
 * - 类型约束（用于CHA精化）
 * - 污点信息（base和参数）
 * - Base来源（用于决定是否展开CHA）
 * - 调用者方法（用于Lambda解析）
 * - 🆕 值集信息（base和参数的类型集合，用于跨方法传播）
 */
public class CallSite {
    private final Unit unit;
    private final InvokeExpr invoke;
    private final TypeConstraints typeInfo;
    private final boolean baseTainted;
    private final List<Boolean> argsTainted;
    private final BaseOrigin baseOrigin;
    private final SootMethod caller;
    
    // 🆕 VSA: base和参数的值集（用于跨方法传播）
    private final Set<Type> baseValueSet;
    private final Map<Integer, Set<Type>> argsValueSets;
    
    // 🆕 动态代理：base是否被cast（用于NoCast检查）
    private final boolean baseHasCast;
    
    public CallSite(Unit unit, InvokeExpr invoke, TypeConstraints typeInfo,
                    boolean baseTainted, List<Boolean> argsTainted,
                    BaseOrigin baseOrigin, SootMethod caller,
                    Set<Type> baseValueSet, Map<Integer, Set<Type>> argsValueSets) {
        this(unit, invoke, typeInfo, baseTainted, argsTainted, baseOrigin, caller,
             baseValueSet, argsValueSets, false);
    }
    
    public CallSite(Unit unit, InvokeExpr invoke, TypeConstraints typeInfo,
                    boolean baseTainted, List<Boolean> argsTainted,
                    BaseOrigin baseOrigin, SootMethod caller,
                    Set<Type> baseValueSet, Map<Integer, Set<Type>> argsValueSets,
                    boolean baseHasCast) {
        this.unit = unit;
        this.invoke = invoke;
        this.typeInfo = typeInfo;
        this.baseTainted = baseTainted;
        this.argsTainted = new ArrayList<>(argsTainted);
        this.baseOrigin = baseOrigin;
        this.caller = caller;
        this.baseValueSet = baseValueSet != null ? new HashSet<>(baseValueSet) : new HashSet<>();
        this.argsValueSets = argsValueSets != null ? new HashMap<>(argsValueSets) : new HashMap<>();
        this.baseHasCast = baseHasCast;
    }
    
    // Getters
    public Unit getUnit() {
        return unit;
    }
    
    public InvokeExpr getInvoke() {
        return invoke;
    }
    
    public TypeConstraints getTypeInfo() {
        return typeInfo;
    }
    
    public boolean isBaseTainted() {
        return baseTainted;
    }
    
    public List<Boolean> getArgsTainted() {
        return argsTainted;
    }
    
    public BaseOrigin getBaseOrigin() {
        return baseOrigin;
    }
    
    public SootMethod getCaller() {
        return caller;
    }
    
    /**
     * 🆕 获取base的值集
     */
    public Set<Type> getBaseValueSet() {
        return baseValueSet != null ? new HashSet<>(baseValueSet) : new HashSet<>();
    }
    
    /**
     * 获取参数的值集
     */
    public Map<Integer, Set<Type>> getArgsValueSets() {
        return argsValueSets != null ? new HashMap<>(argsValueSets) : new HashMap<>();
    }
    
    /**
     * 判断base是否被cast
     */
    public boolean baseHasCast() {
        return baseHasCast;
    }
    
    @Override
    public String toString() {
        return String.format("CallSite{invoke=%s, baseTainted=%s, argsTainted=%s, baseOrigin=%s}",
                invoke, baseTainted, argsTainted, baseOrigin);
    }
}
