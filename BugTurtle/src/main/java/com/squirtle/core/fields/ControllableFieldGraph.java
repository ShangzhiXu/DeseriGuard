package com.squirtle.core.fields;

import soot.SootField;
import soot.SootClass;
import java.util.*;

/**
 * 可控字段图 - 字段敏感污点分析专用
 * 
 * 核心功能：
 * 1. 存储所有攻击者可控字段（非static、非transient，包括final）
 * 2. 按类组织可控字段
 * 3. 提供高效的可控字段查询接口
 * 
 * 设计原则（来自设计文档）：
 * - 可控字段 = 非static && 非transient（包括final字段）
 * - 作为污点源的基础数据结构
 * 
 * @author BugTurtle
 * @version 2.0 - 字段敏感污点分析专用版
 */
public class ControllableFieldGraph {
    
    // 核心数据结构
    private final Set<SootField> controllableFields;                    // 所有可控字段
    private final Map<SootClass, Set<SootField>> classToFields;         // 类 -> 可控字段映射
    private final Map<SootField, SootClass> fieldToClass;               // 字段 -> 所属类映射
    
    public ControllableFieldGraph() {
        this.controllableFields = new HashSet<>();
        this.classToFields = new HashMap<>();
        this.fieldToClass = new HashMap<>();
    }
    
    /**
     * 添加可控字段
     */
    public void addControllableField(SootField field) {
        if (field == null) return;
        
        controllableFields.add(field);
        
        SootClass declaringClass = field.getDeclaringClass();
        classToFields.computeIfAbsent(declaringClass, k -> new HashSet<>()).add(field);
        fieldToClass.put(field, declaringClass);
    }
    
    /**
     * 批量添加可控字段
     */
    public void addControllableFields(Collection<SootField> fields) {
        for (SootField field : fields) {
            addControllableField(field);
        }
    }
    
    /**
     * 检查字段是否可控
     */
    public boolean isControllableField(SootField field) {
        return controllableFields.contains(field);
    }
    
    /**
     * 检查类是否有可控字段
     */
    public boolean hasControllableFields(SootClass clazz) {
        Set<SootField> fields = classToFields.get(clazz);
        return fields != null && !fields.isEmpty();
    }
    
    /**
     * 获取所有可控字段
     */
    public Set<SootField> getAllControllableFields() {
        return Collections.unmodifiableSet(controllableFields);
    }
    
    /**
     * 获取类的所有可控字段
     */
    public Set<SootField> getControllableFields(SootClass clazz) {
        return classToFields.getOrDefault(clazz, Collections.emptySet());
    }
    
    /**
     * 获取字段所属的类
     */
    public SootClass getDeclaringClass(SootField field) {
        return fieldToClass.get(field);
    }
    
    /**
     * 获取有可控字段的所有类
     */
    public Set<SootClass> getClassesWithControllableFields() {
        return Collections.unmodifiableSet(classToFields.keySet());
    }
    
    /**
     * 获取统计信息
     */
    public Statistics getStatistics() {
        return new Statistics(
            controllableFields.size(),
            classToFields.size()
        );
    }
    
    /**
     * 打印摘要
     */
    public void printSummary() {
        Statistics stats = getStatistics();
        System.out.println("🎯 可控字段图统计:");
        System.out.println("  可控字段数量: " + stats.getFieldCount());
        System.out.println("  涉及类数量: " + stats.getClassCount());
    }
    
    /**
     * 清空所有数据
     */
    public void clear() {
        controllableFields.clear();
        classToFields.clear();
        fieldToClass.clear();
    }
    
    /**
     * 检查是否为空
     */
    public boolean isEmpty() {
        return controllableFields.isEmpty();
    }
    
    /**
     * 统计信息类
     */
    public static class Statistics {
        private final int fieldCount;
        private final int classCount;
        
        public Statistics(int fieldCount, int classCount) {
            this.fieldCount = fieldCount;
            this.classCount = classCount;
        }
        
        public int getFieldCount() { return fieldCount; }
        public int getClassCount() { return classCount; }
        
        @Override
        public String toString() {
            return String.format("ControllableFieldStats{fields=%d, classes=%d}",
                               fieldCount, classCount);
        }
    }
}
