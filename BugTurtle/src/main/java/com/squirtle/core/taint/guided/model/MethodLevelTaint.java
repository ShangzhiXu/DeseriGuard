package com.squirtle.core.taint.guided.model;

import soot.Type;
import java.util.*;

/**
 * 跨方法传递的污点状态（增强版：支持值集分析）
 * 
 * 表示方法入口/出口时的污点状态：
 * - this对象是否污染 + 可能的类型集合
 * - 各参数是否污染 + 可能的类型集合
 * 
 * 值集分析（VSA）：不仅追踪污点，还追踪可能的具体类型
 * 用于精确化反射调用目标（如Constructor.newInstance）
 */
public class MethodLevelTaint {
    private boolean thisTainted;
    private Map<Integer, Boolean> paramTaints;
    
    // 🆕 值集：可能的类型集合
    private Set<Type> thisPossibleTypes;
    private Map<Integer, Set<Type>> paramPossibleTypes;
    
    public MethodLevelTaint() {
        this.thisTainted = false;
        this.paramTaints = new HashMap<>();
        this.thisPossibleTypes = new HashSet<>();
        this.paramPossibleTypes = new HashMap<>();
    }
    
    public MethodLevelTaint(boolean thisTainted, Map<Integer, Boolean> paramTaints) {
        this.thisTainted = thisTainted;
        this.paramTaints = new HashMap<>(paramTaints);
        this.thisPossibleTypes = new HashSet<>();
        this.paramPossibleTypes = new HashMap<>();
    }
    
    /**
     * 判断this是否比other有更严格的污点
     * 用于去重：如果已有更严格的污点，则跳过当前分析
     */
    public boolean isStricterThan(MethodLevelTaint other) {
        // 如果this有污点但other没有 → this更严格
        if (this.thisTainted && !other.thisTainted) {
            return true;
        }
        
        // 检查参数：如果this的某个参数污点但other没有 → this更严格
        for (Map.Entry<Integer, Boolean> entry : this.paramTaints.entrySet()) {
            if (entry.getValue() && !other.paramTaints.getOrDefault(entry.getKey(), false)) {
                return true;
            }
        }
        
        return false;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MethodLevelTaint)) return false;
        
        MethodLevelTaint that = (MethodLevelTaint) o;
        return thisTainted == that.thisTainted &&
               paramTaints.equals(that.paramTaints);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(thisTainted, paramTaints);
    }
    
    // Getters and setters
    public boolean isThisTainted() {
        return thisTainted;
    }
    
    public void setThisTainted(boolean thisTainted) {
        this.thisTainted = thisTainted;
    }
    
    /**
     * 🆕 设置this污点和可能的类型集合
     */
    public void setThisTainted(boolean thisTainted, Set<Type> possibleTypes) {
        this.thisTainted = thisTainted;
        if (possibleTypes != null && !possibleTypes.isEmpty()) {
            this.thisPossibleTypes = new HashSet<>(possibleTypes);
        }
    }
    
    public Map<Integer, Boolean> getParamTaints() {
        return paramTaints;
    }
    
    public void setParamTaint(int index, boolean tainted) {
        paramTaints.put(index, tainted);
    }
    
    /**
     * 🆕 设置参数污点和可能的类型集合
     */
    public void setParamTaint(int index, boolean tainted, Set<Type> possibleTypes) {
        paramTaints.put(index, tainted);
        if (possibleTypes != null && !possibleTypes.isEmpty()) {
            paramPossibleTypes.put(index, new HashSet<>(possibleTypes));
        }
    }
    
    public boolean isParamTainted(int index) {
        return paramTaints.getOrDefault(index, false);
    }
    
    /**
     * 🆕 获取this的可能类型集合
     */
    public Set<Type> getThisPossibleTypes() {
        return thisPossibleTypes != null ? new HashSet<>(thisPossibleTypes) : new HashSet<>();
    }
    
    /**
     * 🆕 获取参数的可能类型集合
     */
    public Set<Type> getParamPossibleTypes(int index) {
        Set<Type> types = paramPossibleTypes.get(index);
        return types != null ? new HashSet<>(types) : new HashSet<>();
    }
    
    /**
     * 🆕 设置this的可能类型集合
     */
    public void setThisPossibleTypes(Set<Type> types) {
        if (types != null && !types.isEmpty()) {
            this.thisPossibleTypes = new HashSet<>(types);
        }
    }
    
    /**
     * 🆕 设置参数的可能类型集合
     */
    public void setParamPossibleTypes(int index, Set<Type> types) {
        if (types != null && !types.isEmpty()) {
            this.paramPossibleTypes.put(index, new HashSet<>(types));
        }
    }
    
    /**
     * 🆕 添加this的可能类型
     */
    public void addThisPossibleType(Type type) {
        if (thisPossibleTypes == null) {
            thisPossibleTypes = new HashSet<>();
        }
        thisPossibleTypes.add(type);
    }
    
    /**
     * 🆕 添加参数的可能类型
     */
    public void addParamPossibleType(int index, Type type) {
        paramPossibleTypes.computeIfAbsent(index, k -> new HashSet<>()).add(type);
    }
    
    /**
     * 🆕 合并另一个污点状态的类型集合
     */
    public void mergeTypes(MethodLevelTaint other) {
        if (other.thisPossibleTypes != null) {
            if (this.thisPossibleTypes == null) {
                this.thisPossibleTypes = new HashSet<>();
            }
            this.thisPossibleTypes.addAll(other.thisPossibleTypes);
        }
        
        for (Map.Entry<Integer, Set<Type>> entry : other.paramPossibleTypes.entrySet()) {
            this.paramPossibleTypes.computeIfAbsent(entry.getKey(), k -> new HashSet<>())
                .addAll(entry.getValue());
        }
    }
    
    @Override
    public String toString() {
        return String.format("MethodLevelTaint{this=%s, params=%s, thisTypes=%d, paramTypes=%s}", 
            thisTainted, paramTaints, 
            thisPossibleTypes != null ? thisPossibleTypes.size() : 0,
            paramPossibleTypes.size());
    }
}









