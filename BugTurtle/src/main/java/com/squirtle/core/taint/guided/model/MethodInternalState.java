package com.squirtle.core.taint.guided.model;

import soot.*;
import soot.jimple.*;
import java.util.*;

/**
 * 方法内部污点状态（增强版：支持值集分析）
 * 
 * 只在单个方法内使用，不跨方法传递
 * 注意：taintedStaticFields是全局共享的（static）
 * 
 * 值集：追踪每个Local变量的可能类型
 */
public class MethodInternalState {
    private Set<Local> taintedLocals;
    private Set<Local> taintedArrays;
    
    // 🆕 值集：Local变量的可能类型集合
    private Map<Local, Set<Type>> localTypes;
    
    // 🆕 Cast追踪：记录哪些Local被cast过（用于动态代理NoCast检查）
    private Set<Local> castedLocals;
    
    // 静态字段污染（全局共享）
    private static Set<SootField> taintedStaticFields = Collections.synchronizedSet(new HashSet<>());
    
    public MethodInternalState() {
        this.taintedLocals = new HashSet<>();
        this.taintedArrays = new HashSet<>();
        this.localTypes = new HashMap<>();
        this.castedLocals = new HashSet<>();
    }
    
    /**
     * 清空全局静态字段污点（在buildTaintGuidedCallGraph开始时调用）
     */
    public static void clearStaticFieldTaints() {
        taintedStaticFields.clear();
    }
    
    /**
     * 判断Value是否被污染
     */
    public boolean isTainted(Value value) {
        if (value instanceof Local) {
            return taintedLocals.contains((Local) value);
        }
        
        if (value instanceof InstanceFieldRef) {
            Value base = ((InstanceFieldRef) value).getBase();
            return isTainted(base);  // 字段污染基于base对象
        }
        
        if (value instanceof StaticFieldRef) {
            SootField field = ((StaticFieldRef) value).getField();
            return taintedStaticFields.contains(field);
        }
        
        if (value instanceof ArrayRef) {
            Value base = ((ArrayRef) value).getBase();
            if (base instanceof Local) {
                // 检查数组污染集合和Local污染集合（处理别名）
                return taintedArrays.contains((Local) base) ||
                       taintedLocals.contains((Local) base);
            }
        }
        
        // CastExpr：检查操作数的污点
        if (value instanceof soot.jimple.CastExpr) {
            Value op = ((soot.jimple.CastExpr) value).getOp();
            return isTainted(op);
        }
        
        // InstanceOfExpr：检查操作数的污点（虽然instanceof本身不传播污点，但在某些上下文中需要检查）
        if (value instanceof soot.jimple.InstanceOfExpr) {
            Value op = ((soot.jimple.InstanceOfExpr) value).getOp();
            return isTainted(op);
        }
        
        return false;
    }
    
    /**
     * 标记Value为污染（只支持Local）
     */
    public void markAsTainted(Value value) {
        if (value instanceof Local) {
            taintedLocals.add((Local) value);
        }
    }
    
    /**
     * 🆕 标记Local为污染，并设置可能的类型
     */
    public void markAsTainted(Local local, Set<Type> possibleTypes) {
        taintedLocals.add(local);
        if (possibleTypes != null && !possibleTypes.isEmpty()) {
            localTypes.put(local, new HashSet<>(possibleTypes));
        }
    }
    
    /**
     * 移除Local的污染（用于赋值时清除旧污点）
     * 
     * 🔥 重要：不删除值集！污点和值集是独立的：
     * - 污点表示数据是否可控
     * - 值集表示数据的可能类型
     * 
     * 例如：cls = Integer.class
     * - cls不是污点（常量赋值）
     * - 但cls有值集{Integer}（用于VSA）
     */
    public void removeTaint(Local local) {
        taintedLocals.remove(local);
        taintedArrays.remove(local);
        // ❌ 不要删除值集！
        // localTypes.remove(local);
    }
    
    /**
     * 标记数组为污染
     */
    public void markArrayAsTainted(Local arrayLocal) {
        taintedArrays.add(arrayLocal);
    }
    
    /**
     * 标记静态字段为污染
     */
    public static void markStaticFieldAsTainted(SootField field) {
        taintedStaticFields.add(field);
    }
    
    // Getters
    public Set<Local> getTaintedLocals() {
        return taintedLocals;
    }
    
    public Set<Local> getTaintedArrays() {
        return taintedArrays;
    }
    
    public static Set<SootField> getTaintedStaticFields() {
        return taintedStaticFields;
    }
    
    // 值集相关方法
    
    /**
     * 设置Local的类型（单个）
     */
    public void setLocalType(Local local, Type type) {
        if (type != null) {
            localTypes.computeIfAbsent(local, k -> new HashSet<>()).clear();
            localTypes.get(local).add(type);
        }
    }
    
    /**
     * 设置Local的可能类型集合（批量）
     */
    public void setLocalTypes(Local local, Set<Type> types) {
        if (types != null && !types.isEmpty()) {
            localTypes.put(local, new HashSet<>(types));
        }
    }
    
    /**
     * 添加Local的可能类型（追加，不覆盖）
     */
    public void addLocalTypes(Local local, Set<Type> types) {
        if (types != null && !types.isEmpty()) {
            localTypes.computeIfAbsent(local, k -> new HashSet<>()).addAll(types);
        }
    }
    
    /**
     * 获取Local变量的可能类型集合
     */
    public Set<Type> getLocalTypes(Local local) {
        Set<Type> types = localTypes.get(local);
        if (types != null && !types.isEmpty()) {
            return new HashSet<>(types);
        }
        // 🚀 VSA关键修复：如果没有记录，返回空集，而不是声明类型
        // 原因：返回声明类型会污染精确类型分析（如java.lang.Class会覆盖Integer.class）
        return new HashSet<>();
    }
    
    /**
     * 添加Local变量的可能类型
     */
    public void addLocalType(Local local, Type type) {
        localTypes.computeIfAbsent(local, k -> new HashSet<>()).add(type);
    }
    
    /**
     * 🆕 标记Local被cast过（用于动态代理NoCast检查）
     * 
     * @param local 被cast的Local变量
     */
    public void markAsCasted(Local local) {
        castedLocals.add(local);
    }
    
    /**
     * 🆕 检查Local是否被cast过（通过数据流追踪）
     * 
     * @param local 要检查的Local变量
     * @return true if 该Local或其源头变量被cast过
     */
    public boolean hasCast(Local local) {
        return castedLocals.contains(local);
    }
    
    /**
     * 🆕 传播cast标记：当a=b时，如果b有cast标记，则a也标记
     * 
     * @param target 目标Local
     * @param source 源Local
     */
    public void propagateCast(Local target, Local source) {
        if (castedLocals.contains(source)) {
            castedLocals.add(target);
        }
    }
}

