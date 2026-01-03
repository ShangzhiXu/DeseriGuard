package com.squirtle.core.callgraph;

import soot.*;
import soot.jimple.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * 纯函数过滤器 - 通用设计，不依赖特定gadget知识
 * 
 * 设计原则：
 * 1. 基于方法特征，不基于gadget知识
 * 2. 保守策略：不确定的都保留
 * 3. 完全普适，适用于任何漏洞检测
 * 
 * @author BugTurtle Team
 */
public class PureFunctionFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(PureFunctionFilter.class);
    
    // 统计信息
    private int level1FilterCount = 0;  // JDK不可变类
    private int level2FilterCount = 0;  // 简单equals/hashCode
    private int level3FilterCount = 0;  // 其他纯函数类别
    private int totalChecked = 0;
    
    // 缓存（避免重复分析）
    private final Map<SootMethod, Boolean> cache = new HashMap<>();
    
    /**
     * 判断方法是否可以安全过滤
     * 
     * @param method 要检查的方法
     * @return true表示可以安全过滤（是纯函数），false表示应该保留
     */
    public boolean canSafelyFilter(SootMethod method) {
        totalChecked++;
        
        // 缓存查询
        if (cache.containsKey(method)) {
            return cache.get(method);
        }
        
        boolean result = canSafelyFilterInternal(method);
        cache.put(method, result);
        return result;
    }
    
    private boolean canSafelyFilterInternal(SootMethod method) {
        // Level 1: JDK不可变类（100%安全）
        if (isImmutableJDKClass(method.getDeclaringClass())) {
            level1FilterCount++;
            return true;
        }
        
        String methodName = method.getName();
        
        // Level 2: equals/hashCode且简单（不调用其他方法）
        if (methodName.equals("equals") || methodName.equals("hashCode")) {
            if (isSimplePureFunction(method)) {
                level2FilterCount++;
                return true;
            }
        }
        
        // Level 3: 已知的纯函数类别
        if (isKnownPureFunctionCategory(method)) {
            level3FilterCount++;
            return true;
        }
        
        // 默认：保留（保守策略）
        return false;
    }
    
    /**
     * Level 1: 判断是否是JDK不可变类
     * 
     * 这些类根据Java语言规范是不可变的，它们的所有方法都是纯函数
     */
    private boolean isImmutableJDKClass(SootClass cls) {
        String className = cls.getName();
        
        // Java基础不可变类型
        return className.equals("java.lang.String") ||
               className.equals("java.lang.Integer") ||
               className.equals("java.lang.Long") ||
               className.equals("java.lang.Double") ||
               className.equals("java.lang.Float") ||
               className.equals("java.lang.Boolean") ||
               className.equals("java.lang.Character") ||
               className.equals("java.lang.Byte") ||
               className.equals("java.lang.Short") ||
               className.equals("java.math.BigInteger") ||
               className.equals("java.math.BigDecimal") ||
               // 不可变集合视图
               className.equals("java.util.Collections$UnmodifiableCollection") ||
               className.equals("java.util.Collections$UnmodifiableSet") ||
               className.equals("java.util.Collections$UnmodifiableList") ||
               className.equals("java.util.Collections$UnmodifiableMap");
    }
    
    /**
     * Level 2: 判断是否是简单纯函数（放宽版本）
     * 
     * 标准：
     * 1. equals/hashCode可以调用同类方法和JDK不可变类方法（纯组合）
     * 2. 无字段写入
     * 3. 无数组写入
     */
    private boolean isSimplePureFunction(SootMethod method) {
        if (!method.hasActiveBody()) {
            return false;  // 保守：无body，不确定
        }
        
        try {
            Body body = method.getActiveBody();
            String methodName = method.getName();
            
            for (Unit unit : body.getUnits()) {
                // 检查1: 有字段写入？
                if (unit instanceof AssignStmt) {
                    AssignStmt assign = (AssignStmt) unit;
                    Value leftOp = assign.getLeftOp();
                    
                    if (leftOp instanceof FieldRef || 
                        leftOp instanceof StaticFieldRef ||
                        leftOp instanceof ArrayRef) {
                        // 有副作用
                        return false;
                    }
                }
                
                // 检查2: 有方法调用？
                if (unit instanceof Stmt) {
                    Stmt stmt = (Stmt) unit;
                    if (stmt.containsInvokeExpr()) {
                        InvokeExpr invoke = stmt.getInvokeExpr();
                        SootMethod target = invoke.getMethod();
                        
                        // 🔥 关键：允许"纯组合"
                        if (!isAllowedCallInPureFunction(target, methodName)) {
                            // 调用了不允许的方法
                            return false;
                        }
                    }
                }
            }
            
            // 通过所有检查，是简单纯函数
            return true;
            
        } catch (Exception e) {
            // 异常情况，保守处理
            logger.debug("分析方法时出错: {}, 保守保留", method.getSignature());
            return false;
        }
    }
    
    /**
     * 判断在纯函数中是否允许调用目标方法
     * 
     * 允许调用：
     * 1. 同类方法（equals调用equals, hashCode调用hashCode）
     * 2. JDK不可变类的方法
     * 3. 已知的纯函数方法
     */
    private boolean isAllowedCallInPureFunction(SootMethod target, String callerMethodName) {
        String targetMethodName = target.getName();
        
        // 1. 允许equals调用其他equals
        if (callerMethodName.equals("equals") && targetMethodName.equals("equals")) {
            return true;
        }
        
        // 2. 允许hashCode调用其他hashCode
        if (callerMethodName.equals("hashCode") && targetMethodName.equals("hashCode")) {
            return true;
        }
        
        // 3. 允许调用JDK不可变类的方法
        if (isImmutableJDKClass(target.getDeclaringClass())) {
            return true;
        }
        
        // 4. 允许调用已知的纯函数
        String targetSig = target.getSignature();
        if (targetSig.startsWith("<java.lang.Math:") ||
            targetSig.startsWith("<java.lang.StrictMath:")) {
            return true;
        }
        
        // 5. 允许调用包装类的getter方法
        if (targetMethodName.equals("intValue") || 
            targetMethodName.equals("longValue") ||
            targetMethodName.equals("doubleValue") ||
            targetMethodName.equals("floatValue") ||
            targetMethodName.equals("booleanValue")) {
            return true;
        }
        
        // 其他调用不允许
        return false;
    }
    
    /**
     * Level 3: 已知的纯函数类别
     * 
     * 这些类的方法通常是纯函数（基于常识和文档）
     */
    private boolean isKnownPureFunctionCategory(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        
        // 1. 数学运算类
        if (className.equals("java.lang.Math") ||
            className.equals("java.lang.StrictMath")) {
            return true;
        }
        
        // 2. 正则表达式匹配（只读）
        if (className.equals("java.util.regex.Pattern") && 
            (methodName.equals("matches") || methodName.equals("matcher"))) {
            return true;
        }
        
        // 3. 不可变的时间日期类（只读操作）
        if (className.startsWith("java.time.") && !methodName.startsWith("set")) {
            return true;
        }
        
        // 4. Arrays工具类的只读方法
        if (className.equals("java.util.Arrays") &&
            (methodName.equals("equals") || 
             methodName.equals("hashCode") ||
             methodName.equals("toString") ||
             methodName.equals("binarySearch"))) {
            return true;
        }
        
        // 5. Objects工具类的纯函数方法
        if (className.equals("java.util.Objects") &&
            (methodName.equals("equals") ||
             methodName.equals("hash") ||
             methodName.equals("hashCode") ||
             methodName.equals("toString") ||
             methodName.equals("compare"))) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 获取统计信息
     */
    public FilterStatistics getStatistics() {
        return new FilterStatistics(
            totalChecked,
            level1FilterCount,
            level2FilterCount,
            level3FilterCount,
            level1FilterCount + level2FilterCount + level3FilterCount
        );
    }
    
    /**
     * 重置统计
     */
    public void resetStatistics() {
        totalChecked = 0;
        level1FilterCount = 0;
        level2FilterCount = 0;
        level3FilterCount = 0;
    }
    
    /**
     * 清空缓存
     */
    public void clearCache() {
        cache.clear();
    }
    
    /**
     * 统计信息
     */
    public static class FilterStatistics {
        public final int totalChecked;
        public final int level1Filtered;  // JDK不可变类
        public final int level2Filtered;  // 简单equals/hashCode
        public final int level3Filtered;  // 其他纯函数类别
        public final int totalFiltered;
        
        public FilterStatistics(int totalChecked, int level1, int level2, int level3, int total) {
            this.totalChecked = totalChecked;
            this.level1Filtered = level1;
            this.level2Filtered = level2;
            this.level3Filtered = level3;
            this.totalFiltered = total;
        }
        
        public double getFilterRate() {
            return totalChecked > 0 ? (totalFiltered * 100.0 / totalChecked) : 0.0;
        }
        
        @Override
        public String toString() {
            return String.format(
                "PureFunction过滤统计: 检查=%d, 过滤=%d (%.2f%%), " +
                "L1(JDK)=%d, L2(简单)=%d, L3(类别)=%d",
                totalChecked, totalFiltered, getFilterRate(),
                level1Filtered, level2Filtered, level3Filtered
            );
        }
    }
}
