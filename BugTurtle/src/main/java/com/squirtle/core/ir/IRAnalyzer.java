package com.squirtle.core.ir;

import soot.*;
import soot.jimple.*;
import java.util.*;

/**
 * Jimple IR 分析器
 * 
 * 功能：
 * 1. 提供Jimple IR的统一遍历接口
 * 2. 分析IR结构和模式
 * 3. 提取程序的基础信息
 * 
 * @author BugTurtle
 * @version 1.0
 */
public class IRAnalyzer {
    
    /**
     * IR统计信息
     */
    public static class IRStatistics {
        private int totalClasses = 0;
        private int totalMethods = 0;
        private int totalUnits = 0;
        private Map<String, Integer> unitTypeCount = new HashMap<>();
        private Map<String, Integer> valueTypeCount = new HashMap<>();
        
        public void incrementClass() { totalClasses++; }
        public void incrementMethod() { totalMethods++; }
        public void incrementUnit() { totalUnits++; }
        public void incrementUnitType(String type) { 
            unitTypeCount.merge(type, 1, Integer::sum); 
        }
        public void incrementValueType(String type) { 
            valueTypeCount.merge(type, 1, Integer::sum); 
        }
        
        // Getters
        public int getTotalClasses() { return totalClasses; }
        public int getTotalMethods() { return totalMethods; }
        public int getTotalUnits() { return totalUnits; }
        public Map<String, Integer> getUnitTypeCount() { return unitTypeCount; }
        public Map<String, Integer> getValueTypeCount() { return valueTypeCount; }
        
        @Override
        public String toString() {
            return String.format("IRStats{classes=%d, methods=%d, units=%d}", 
                               totalClasses, totalMethods, totalUnits);
        }
    }
    
    /**
     * 分析类集合的IR结构
     */
    public IRStatistics analyzeClasses(Collection<SootClass> classes) {
        IRStatistics stats = new IRStatistics();
        
        for (SootClass sootClass : classes) {
            analyzeClass(sootClass, stats);
        }
        
        return stats;
    }
    
    /**
     * 分析单个类的IR结构
     */
    public void analyzeClass(SootClass sootClass, IRStatistics stats) {
        stats.incrementClass();
        
        try {
            // 直接尝试获取方法，如果解析级别不够会自动处理
            for (SootMethod method : sootClass.getMethods()) {
                analyzeMethod(method, stats);
            }
        } catch (RuntimeException e) {
            // 如果是解析级别问题，尝试设置解析级别后重试
            if (e.getMessage() != null && e.getMessage().contains("resolving level")) {
                try {
                    sootClass.setResolvingLevel(SootClass.SIGNATURES);
                    for (SootMethod method : sootClass.getMethods()) {
                        analyzeMethod(method, stats);
                    }
                } catch (Exception retryException) {
                    System.err.println("警告: 无法分析类 " + sootClass.getName() + ": " + retryException.getMessage());
                }
            } else {
                System.err.println("警告: 无法分析类 " + sootClass.getName() + ": " + e.getMessage());
            }
        }
    }
    
    /**
     * 分析单个方法的IR结构
     */
    public void analyzeMethod(SootMethod method, IRStatistics stats) {
        stats.incrementMethod();
        
        if (!method.hasActiveBody()) return;
        
        Body body = method.getActiveBody();
        for (Unit unit : body.getUnits()) {
            analyzeUnit(unit, stats);
        }
    }
    
    /**
     * 分析单个Unit的结构
     */
    public void analyzeUnit(Unit unit, IRStatistics stats) {
        stats.incrementUnit();
        stats.incrementUnitType(unit.getClass().getSimpleName());
        
        // 分析Unit中的所有Value
        for (ValueBox valueBox : unit.getUseAndDefBoxes()) {
            Value value = valueBox.getValue();
            analyzeValue(value, stats);
        }
    }
    
    /**
     * 分析Value的类型
     */
    public void analyzeValue(Value value, IRStatistics stats) {
        stats.incrementValueType(value.getClass().getSimpleName());
    }
    
    /**
     * 提取方法的所有调用表达式
     */
    public List<InvokeExpr> extractInvokeExpressions(SootMethod method) {
        List<InvokeExpr> invokeExprs = new ArrayList<>();
        
        if (!method.hasActiveBody()) return invokeExprs;
        
        Body body = method.getActiveBody();
        for (Unit unit : body.getUnits()) {
            if (unit instanceof InvokeStmt) {
                InvokeStmt invokeStmt = (InvokeStmt) unit;
                invokeExprs.add(invokeStmt.getInvokeExpr());
            } else if (unit instanceof AssignStmt) {
                AssignStmt assignStmt = (AssignStmt) unit;
                Value rightOp = assignStmt.getRightOp();
                if (rightOp instanceof InvokeExpr) {
                    invokeExprs.add((InvokeExpr) rightOp);
                }
            }
        }
        
        return invokeExprs;
    }
    
    /**
     * 提取方法的所有字段访问
     */
    public List<FieldRef> extractFieldReferences(SootMethod method) {
        List<FieldRef> fieldRefs = new ArrayList<>();
        
        if (!method.hasActiveBody()) return fieldRefs;
        
        Body body = method.getActiveBody();
        for (Unit unit : body.getUnits()) {
            for (ValueBox valueBox : unit.getUseAndDefBoxes()) {
                Value value = valueBox.getValue();
                if (value instanceof FieldRef) {
                    fieldRefs.add((FieldRef) value);
                }
            }
        }
        
        return fieldRefs;
    }
    
    /**
     * 提取方法的所有局部变量
     */
    public List<Local> extractLocalVariables(SootMethod method) {
        List<Local> locals = new ArrayList<>();
        
        if (!method.hasActiveBody()) return locals;
        
        Body body = method.getActiveBody();
        locals.addAll(body.getLocals());
        
        return locals;
    }
    
    /**
     * 查找特定模式的语句
     */
    public List<Unit> findUnitsOfType(SootMethod method, Class<? extends Unit> unitType) {
        List<Unit> matchingUnits = new ArrayList<>();
        
        if (!method.hasActiveBody()) return matchingUnits;
        
        Body body = method.getActiveBody();
        for (Unit unit : body.getUnits()) {
            if (unitType.isInstance(unit)) {
                matchingUnits.add(unit);
            }
        }
        
        return matchingUnits;
    }
    
    /**
     * 查找特定模式的值
     */
    public List<Value> findValuesOfType(SootMethod method, Class<? extends Value> valueType) {
        List<Value> matchingValues = new ArrayList<>();
        
        if (!method.hasActiveBody()) return matchingValues;
        
        Body body = method.getActiveBody();
        for (Unit unit : body.getUnits()) {
            for (ValueBox valueBox : unit.getUseAndDefBoxes()) {
                Value value = valueBox.getValue();
                if (valueType.isInstance(value)) {
                    matchingValues.add(value);
                }
            }
        }
        
        return matchingValues;
    }
    
    /**
     * 检查方法是否包含特定类型的操作
     */
    public boolean containsOperation(SootMethod method, Class<? extends Unit> operationType) {
        return !findUnitsOfType(method, operationType).isEmpty();
    }
    
    /**
     * 获取方法的复杂度指标
     */
    public MethodComplexity getMethodComplexity(SootMethod method) {
        if (!method.hasActiveBody()) {
            return new MethodComplexity(0, 0, 0, 0);
        }
        
        Body body = method.getActiveBody();
        int unitCount = body.getUnits().size();
        int localCount = body.getLocals().size();
        int invokeCount = extractInvokeExpressions(method).size();
        int fieldAccessCount = extractFieldReferences(method).size();
        
        return new MethodComplexity(unitCount, localCount, invokeCount, fieldAccessCount);
    }
    
    /**
     * 方法复杂度信息
     */
    public static class MethodComplexity {
        private final int unitCount;
        private final int localCount;
        private final int invokeCount;
        private final int fieldAccessCount;
        
        public MethodComplexity(int unitCount, int localCount, int invokeCount, int fieldAccessCount) {
            this.unitCount = unitCount;
            this.localCount = localCount;
            this.invokeCount = invokeCount;
            this.fieldAccessCount = fieldAccessCount;
        }
        
        public int getUnitCount() { return unitCount; }
        public int getLocalCount() { return localCount; }
        public int getInvokeCount() { return invokeCount; }
        public int getFieldAccessCount() { return fieldAccessCount; }
        
        public int getTotalComplexity() {
            return unitCount + invokeCount * 2 + fieldAccessCount;
        }
        
        @Override
        public String toString() {
            return String.format("Complexity{units=%d, locals=%d, invokes=%d, fields=%d, total=%d}", 
                               unitCount, localCount, invokeCount, fieldAccessCount, getTotalComplexity());
        }
    }
} 