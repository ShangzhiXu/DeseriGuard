package com.squirtle.core.analyzer;

import com.squirtle.core.fields.FieldAccessGraph;
import com.squirtle.core.fields.FieldAccessGraph.FieldAccess;
import com.squirtle.core.fields.FieldAccessGraph.AccessType;
import soot.*;
import soot.jimple.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * 字段访问分析器 - 识别所有字段的读写访问
 * 
 * 核心功能：
 * 1. 扫描方法体，识别字段读取（x = obj.field）
 * 2. 扫描方法体，识别字段写入（obj.field = x）
 * 3. 构建字段访问图
 * 
 * 设计目的：
 * - 为污点分析提供字段访问点信息
 * - 特别是字段读取点，作为污点源的候选位置
 * 
 * @author BugTurtle
 * @version 2.0 - 字段敏感污点分析专用版
 */
public class FieldAccessAnalyzer {
    
    private static final Logger logger = Logger.getLogger(FieldAccessAnalyzer.class.getName());
    
    private final FieldAccessGraph fieldAccessGraph;
    
    public FieldAccessAnalyzer() {
        this.fieldAccessGraph = new FieldAccessGraph();
    }
    
    /**
     * 构建字段访问图
     * 
     * @param methodBodies 方法体映射
     * @return 字段访问图
     */
    public FieldAccessGraph buildFieldAccessGraph(Map<SootMethod, List<Unit>> methodBodies) {
        logger.info("🔍 开始分析字段访问...");
        
        // 清空之前的结果
        fieldAccessGraph.clear();
        
        int totalAccesses = 0;
        for (Map.Entry<SootMethod, List<Unit>> entry : methodBodies.entrySet()) {
            SootMethod method = entry.getKey();
            List<Unit> units = entry.getValue();
            
            totalAccesses += analyzeMethodFieldAccesses(method, units);
        }
        
        // 打印统计信息
        FieldAccessGraph.Statistics stats = fieldAccessGraph.getStatistics();
        logger.info("✅ 字段访问分析完成: " + stats);
        
        return fieldAccessGraph;
    }
    
    /**
     * 分析方法中的所有字段访问
     */
    private int analyzeMethodFieldAccesses(SootMethod method, List<Unit> units) {
        int accessCount = 0;
        
        for (Unit unit : units) {
            if (unit instanceof AssignStmt) {
                AssignStmt assign = (AssignStmt) unit;
                
                // 检查字段读取: x = obj.field
                accessCount += analyzeFieldRead(method, assign);
                
                // 检查字段写入: obj.field = x
                accessCount += analyzeFieldWrite(method, assign);
            }
        }
        
        return accessCount;
    }
    
    /**
     * 分析字段读取访问: x = obj.field
     */
    private int analyzeFieldRead(SootMethod method, AssignStmt assign) {
        Value rightOp = assign.getRightOp();
        Value leftOp = assign.getLeftOp();
        
        if (rightOp instanceof InstanceFieldRef) {
            InstanceFieldRef fieldRef = (InstanceFieldRef) rightOp;
            
            try {
                SootField field = fieldRef.getField();
                Value baseObject = fieldRef.getBase();
                
                FieldAccess access = new FieldAccess(
                    method,
                    assign,
                    field,
                    baseObject,
                    leftOp,  // 读取到的值存储在leftOp中
                    AccessType.READ
                );
                
                fieldAccessGraph.addFieldAccess(access);
                logger.finest("📖 字段读取: " + field.getName() + " in " + method.getName());
                
                return 1;
                
            } catch (soot.ResolutionFailedException e) {
                logger.fine("⚠️ 字段解析失败: " + fieldRef + " - " + e.getMessage());
            }
        } else if (rightOp instanceof StaticFieldRef) {
            StaticFieldRef fieldRef = (StaticFieldRef) rightOp;
            
            try {
                SootField field = fieldRef.getField();
                
                FieldAccess access = new FieldAccess(
                    method,
                    assign,
                    field,
                    null,  // static字段没有base对象
                    leftOp,
                    AccessType.READ
                );
                
                fieldAccessGraph.addFieldAccess(access);
                logger.finest("📖 静态字段读取: " + field.getName() + " in " + method.getName());
                
                return 1;
                
            } catch (soot.ResolutionFailedException e) {
                logger.fine("⚠️ 字段解析失败: " + fieldRef + " - " + e.getMessage());
            }
        }
        
        return 0;
    }
    
    /**
     * 分析字段写入访问: obj.field = x
     */
    private int analyzeFieldWrite(SootMethod method, AssignStmt assign) {
        Value leftOp = assign.getLeftOp();
        Value rightOp = assign.getRightOp();
        
        if (leftOp instanceof InstanceFieldRef) {
            InstanceFieldRef fieldRef = (InstanceFieldRef) leftOp;
            
            try {
                SootField field = fieldRef.getField();
                Value baseObject = fieldRef.getBase();
                
                FieldAccess access = new FieldAccess(
                    method,
                    assign,
                    field,
                    baseObject,
                    rightOp,  // 写入的值来自rightOp
                    AccessType.WRITE
                );
                
                fieldAccessGraph.addFieldAccess(access);
                logger.finest("✍️ 字段写入: " + field.getName() + " in " + method.getName());
                
                return 1;
                
            } catch (soot.ResolutionFailedException e) {
                logger.fine("⚠️ 字段解析失败: " + fieldRef + " - " + e.getMessage());
            }
        } else if (leftOp instanceof StaticFieldRef) {
            StaticFieldRef fieldRef = (StaticFieldRef) leftOp;
            
            try {
                SootField field = fieldRef.getField();
                
                FieldAccess access = new FieldAccess(
                    method,
                    assign,
                    field,
                    null,  // static字段没有base对象
                    rightOp,
                    AccessType.WRITE
                );
                
                fieldAccessGraph.addFieldAccess(access);
                logger.finest("✍️ 静态字段写入: " + field.getName() + " in " + method.getName());
                
                return 1;
                
            } catch (soot.ResolutionFailedException e) {
                logger.fine("⚠️ 字段解析失败: " + fieldRef + " - " + e.getMessage());
            }
        }
        
        return 0;
    }
    
    /**
     * 获取构建的字段访问图
     */
    public FieldAccessGraph getFieldAccessGraph() {
        return fieldAccessGraph;
    }
    
    /**
     * 清空分析结果
     */
    public void clear() {
        fieldAccessGraph.clear();
    }
}
