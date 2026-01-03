package com.squirtle.core.reflection.core;

import soot.Local;
import soot.SootField;
import soot.SootMethod;
import soot.Value;

import java.util.*;

/**
 * 全局反射数据流映射
 * 
 * 跟踪 Class 对象、Method 对象、Constructor 对象的数据流
 */
public class GlobalReflectionFlowMap {
    
    // Local → ReflectionTargetInfo
    private final Map<Local, Set<ReflectionTargetInfo>> localToTargets = new HashMap<>();
    
    // SootField → ReflectionTargetInfo
    private final Map<SootField, Set<ReflectionTargetInfo>> fieldToTargets = new HashMap<>();
    
    // SootMethod return → ReflectionTargetInfo
    private final Map<SootMethod, Set<ReflectionTargetInfo>> returnToTargets = new HashMap<>();
    
    /**
     * 记录局部变量指向的反射目标
     */
    public void addLocalTarget(Local local, ReflectionTargetInfo target) {
        localToTargets.computeIfAbsent(local, k -> new HashSet<>()).add(target);
    }
    
    /**
     * 获取局部变量可能的反射目标
     */
    public Set<ReflectionTargetInfo> getLocalTargets(Local local) {
        return localToTargets.getOrDefault(local, Collections.emptySet());
    }
    
    /**
     * 记录字段指向的反射目标
     */
    public void addFieldTarget(SootField field, ReflectionTargetInfo target) {
        fieldToTargets.computeIfAbsent(field, k -> new HashSet<>()).add(target);
    }
    
    /**
     * 获取字段可能的反射目标
     */
    public Set<ReflectionTargetInfo> getFieldTargets(SootField field) {
        return fieldToTargets.getOrDefault(field, Collections.emptySet());
    }
    
    /**
     * 记录方法返回值的反射目标
     */
    public void addReturnTarget(SootMethod method, ReflectionTargetInfo target) {
        returnToTargets.computeIfAbsent(method, k -> new HashSet<>()).add(target);
    }
    
    /**
     * 获取方法返回值可能的反射目标
     */
    public Set<ReflectionTargetInfo> getReturnTargets(SootMethod method) {
        return returnToTargets.getOrDefault(method, Collections.emptySet());
    }
    
    /**
     * 获取 Value 可能的反射目标（统一接口）
     */
    public Set<ReflectionTargetInfo> getTargets(Value value) {
        if (value instanceof Local) {
            return getLocalTargets((Local) value);
        }
        // 可以扩展支持其他 Value 类型
        return Collections.emptySet();
    }
    
    /**
     * 清空所有映射
     */
    public void clear() {
        localToTargets.clear();
        fieldToTargets.clear();
        returnToTargets.clear();
    }
    
    /**
     * 统计信息
     */
    public String getStatistics() {
        return String.format("ReflectionFlowMap[locals=%d, fields=%d, returns=%d]",
            localToTargets.size(), fieldToTargets.size(), returnToTargets.size());
    }
}











