package com.squirtle.core.fields;

import soot.*;
import soot.jimple.*;
import java.util.*;

/**
 * 字段访问图 - 记录所有字段的读写访问
 * 
 * 核心功能：
 * 1. 记录字段读取访问（为污点源识别提供基础）
 * 2. 记录字段写入访问（可选，用于数据流分析）
 * 3. 提供访问点查询接口
 * 
 * 设计目的：
 * - 为污点分析提供字段读取点信息
 * - 支持 "x = obj.field" 这类污点源的识别
 * 
 * @author BugTurtle
 * @version 2.0 - 字段敏感污点分析专用版
 */
public class FieldAccessGraph {
    
    /**
     * 访问类型
     */
    public enum AccessType {
        READ,   // 字段读取
        WRITE   // 字段写入
    }
    
    /**
     * 字段访问记录
     */
    public static class FieldAccess {
        private final SootMethod method;           // 访问所在方法
        private final Unit accessSite;             // 访问点（语句）
        private final SootField field;             // 被访问的字段
        private final Value baseObject;            // 基对象（obj in obj.field）
        private final Value accessValue;           // 访问值（读取时是左值，写入时是右值）
        private final AccessType accessType;       // 访问类型
        
        public FieldAccess(SootMethod method, Unit accessSite, SootField field, 
                          Value baseObject, Value accessValue, AccessType accessType) {
            this.method = method;
            this.accessSite = accessSite;
            this.field = field;
            this.baseObject = baseObject;
            this.accessValue = accessValue;
            this.accessType = accessType;
        }
        
        public SootMethod getMethod() { return method; }
        public Unit getAccessSite() { return accessSite; }
        public SootField getField() { return field; }
        public Value getBaseObject() { return baseObject; }
        public Value getAccessValue() { return accessValue; }
        public AccessType getAccessType() { return accessType; }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof FieldAccess)) return false;
            FieldAccess other = (FieldAccess) obj;
            return Objects.equals(method, other.method) &&
                   Objects.equals(accessSite, other.accessSite) &&
                   Objects.equals(field, other.field);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(method, accessSite, field);
        }
        
        @Override
        public String toString() {
            return String.format("FieldAccess{%s %s.%s in %s}", 
                               accessType, 
                               field.getDeclaringClass().getShortName(),
                               field.getName(),
                               method.getName());
        }
    }
    
    // 核心数据结构
    private final Set<FieldAccess> allAccesses;                             // 所有访问记录
    private final Map<SootField, Set<FieldAccess>> fieldToAccesses;         // 字段 -> 访问记录
    private final Map<SootMethod, Set<FieldAccess>> methodToAccesses;       // 方法 -> 访问记录
    private final Map<AccessType, Set<FieldAccess>> accessesByType;         // 访问类型 -> 访问记录
    
    public FieldAccessGraph() {
        this.allAccesses = new HashSet<>();
        this.fieldToAccesses = new HashMap<>();
        this.methodToAccesses = new HashMap<>();
        this.accessesByType = new HashMap<>();
        
        // 初始化访问类型映射
        for (AccessType type : AccessType.values()) {
            accessesByType.put(type, new HashSet<>());
        }
    }
    
    /**
     * 添加字段访问记录
     */
    public void addFieldAccess(FieldAccess access) {
        if (access == null) return;
        
        allAccesses.add(access);
        fieldToAccesses.computeIfAbsent(access.getField(), k -> new HashSet<>()).add(access);
        methodToAccesses.computeIfAbsent(access.getMethod(), k -> new HashSet<>()).add(access);
        accessesByType.get(access.getAccessType()).add(access);
    }
    
    /**
     * 获取字段的所有访问记录
     */
    public Set<FieldAccess> getFieldAccesses(SootField field) {
        return fieldToAccesses.getOrDefault(field, Collections.emptySet());
    }
    
    /**
     * 获取字段的所有读取访问
     */
    public Set<FieldAccess> getFieldReads(SootField field) {
        return getFieldAccesses(field).stream()
            .filter(access -> access.getAccessType() == AccessType.READ)
            .collect(java.util.stream.Collectors.toSet());
    }
    
    /**
     * 获取字段的所有写入访问
     */
    public Set<FieldAccess> getFieldWrites(SootField field) {
        return getFieldAccesses(field).stream()
            .filter(access -> access.getAccessType() == AccessType.WRITE)
            .collect(java.util.stream.Collectors.toSet());
    }
    
    /**
     * 获取方法中的所有字段访问
     */
    public Set<FieldAccess> getMethodAccesses(SootMethod method) {
        return methodToAccesses.getOrDefault(method, Collections.emptySet());
    }
    
    /**
     * 获取所有字段访问记录
     */
    public Set<FieldAccess> getAllFieldAccesses() {
        return Collections.unmodifiableSet(allAccesses);
    }
    
    /**
     * 获取所有被访问的字段
     */
    public Set<SootField> getAllAccessedFields() {
        return Collections.unmodifiableSet(fieldToAccesses.keySet());
    }
    
    /**
     * 获取特定类型的所有访问
     */
    public Set<FieldAccess> getAccessesByType(AccessType type) {
        return accessesByType.getOrDefault(type, Collections.emptySet());
    }
    
    /**
     * 获取统计信息
     */
    public Statistics getStatistics() {
        Map<AccessType, Integer> countByType = new HashMap<>();
        for (AccessType type : AccessType.values()) {
            countByType.put(type, accessesByType.get(type).size());
        }
        
        return new Statistics(
            fieldToAccesses.size(),
            allAccesses.size(),
            countByType
        );
    }
    
    /**
     * 清空所有数据
     */
    public void clear() {
        allAccesses.clear();
        fieldToAccesses.clear();
        methodToAccesses.clear();
        for (Set<FieldAccess> accesses : accessesByType.values()) {
            accesses.clear();
        }
    }
    
    /**
     * 统计信息类
     */
    public static class Statistics {
        private final int fieldCount;
        private final int totalAccesses;
        private final Map<AccessType, Integer> accessCountByType;
        
        public Statistics(int fieldCount, int totalAccesses, Map<AccessType, Integer> accessCountByType) {
            this.fieldCount = fieldCount;
            this.totalAccesses = totalAccesses;
            this.accessCountByType = new HashMap<>(accessCountByType);
        }
        
        public int getFieldCount() { return fieldCount; }
        public int getTotalAccesses() { return totalAccesses; }
        public Map<AccessType, Integer> getAccessCountByType() { 
            return Collections.unmodifiableMap(accessCountByType); 
        }
        
        @Override
        public String toString() {
            return String.format("FieldAccessStats{fields=%d, accesses=%d, reads=%d, writes=%d}",
                               fieldCount, totalAccesses, 
                               accessCountByType.getOrDefault(AccessType.READ, 0),
                               accessCountByType.getOrDefault(AccessType.WRITE, 0));
        }
    }
}
