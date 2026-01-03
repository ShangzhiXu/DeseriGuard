package com.squirtle.core.analyzer;

import com.squirtle.core.fields.ControllableFieldGraph;
import soot.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * 可控字段分析器 - 字段敏感污点分析专用
 * 
 * 核心功能：
 * 识别攻击者可控字段（反序列化场景）
 * 
 * 可控字段定义（来自设计文档）：
 * 1. 所属类实现了 Serializable 接口
 * 2. 非 static 字段（static字段不参与序列化）
 * 3. 非 transient 字段（transient字段不参与序列化）
 * 4. 包括 final 字段（反序列化时JVM允许赋值）
 * 
 * @author BugTurtle
 * @version 2.0 - 字段敏感污点分析专用版
 */
public class ControllableFieldAnalyzer {
    
    private static final Logger logger = Logger.getLogger(ControllableFieldAnalyzer.class.getName());
    
    private ControllableFieldGraph controllableFieldGraph;
    
    public ControllableFieldAnalyzer() {
        this.controllableFieldGraph = new ControllableFieldGraph();
    }
    
    /**
     * 构建可控字段图
     * 
     * @param serializableClasses 可序列化类集合
     * @return 可控字段图
     */
    public ControllableFieldGraph buildControllableFieldGraph(Set<SootClass> serializableClasses) {
        logger.info("🎯 开始识别可控字段...");
        
        // 清空之前的结果
        controllableFieldGraph.clear();
        
        // 识别所有可控字段
        Set<SootField> controllableFields = identifyControllableFields(serializableClasses);
        
        // 添加到图中
        controllableFieldGraph.addControllableFields(controllableFields);
        
        // 打印统计信息
        controllableFieldGraph.printSummary();
        
        logger.info("✅ 可控字段识别完成");
        return controllableFieldGraph;
    }
    
    /**
     * 识别攻击者可控字段
     */
    private Set<SootField> identifyControllableFields(Set<SootClass> serializableClasses) {
        Set<SootField> controllableFields = new HashSet<>();
        
        for (SootClass clazz : serializableClasses) {
            for (SootField field : clazz.getFields()) {
                if (isAttackerControllable(field)) {
                    controllableFields.add(field);
                    logger.fine("✅ 可控字段: " + field.getSignature());
                }
            }
        }
        
        logger.info("发现 " + controllableFields.size() + " 个可控字段");
        return controllableFields;
    }
    
    /**
     * 判断字段是否为攻击者可控
     * 
     * 规则（来自设计文档）：
     * 1. 非 static 字段 - static字段不序列化
     * 2. 非 transient 字段 - transient字段不序列化
     * 3. 包括 final 字段 - 反序列化时可控
     * 
     * @param field 字段
     * @return true 如果字段可控
     */
    private boolean isAttackerControllable(SootField field) {
        int modifiers = field.getModifiers();
        
        // 排除 static 字段
        if (soot.Modifier.isStatic(modifiers)) {
            return false;
        }
        
        // 排除 transient 字段
        if (soot.Modifier.isTransient(modifiers)) {
            return false;
        }
        
        // 其他字段（包括 final）都是可控的
        return true;
    }
    
    /**
     * 获取构建的可控字段图
     */
    public ControllableFieldGraph getControllableFieldGraph() {
        return controllableFieldGraph;
    }
    
    /**
     * 清空分析结果
     */
    public void clear() {
        controllableFieldGraph.clear();
    }
}
