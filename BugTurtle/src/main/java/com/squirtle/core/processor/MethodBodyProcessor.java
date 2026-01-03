package com.squirtle.core.processor;

import soot.*;


import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * 方法体处理器
 * 
 * 负责方法体的收集、预处理和管理，包括：
 * 1. 方法体收集和Jimple单元获取
 * 2. 类和方法的分析条件判断
 * 3. 方法解析级别管理
 * 
 * @author BugTurtle
 * @version 1.0
 */
public class MethodBodyProcessor {
    
    private static final Logger logger = Logger.getLogger(MethodBodyProcessor.class.getName());
    
    private final Map<SootMethod, List<Unit>> methodUnits = new ConcurrentHashMap<>();
    
    /**
     * 收集指定类集合中所有方法的方法体
     */
    public Map<SootMethod, List<Unit>> collectMethodBodies(Collection<SootClass> targetClasses) {
        Map<SootMethod, List<Unit>> methodBodies = new ConcurrentHashMap<>();
        
        logger.info("开始收集方法体...");
        int classCount = 0;
        int methodCount = 0;
        
        for (SootClass sootClass : targetClasses) {
            if (!shouldAnalyzeClass(sootClass)) continue;
            
            classCount++;
            
            // 🔍 特殊日志：追踪EqualsBean类
            String className = sootClass.getName();
            if (className.equals("com.sun.syndication.feed.impl.EqualsBean")) {
                logger.info("🔍 收集EqualsBean类的方法体，方法数: " + sootClass.getMethodCount());
            }
            
            for (SootMethod method : sootClass.getMethods()) {
                if (!shouldAnalyzeMethod(method)) {
                    if (className.equals("com.sun.syndication.feed.impl.EqualsBean")) {
                        logger.info("   ⏭ 跳过EqualsBean方法: " + method.getName() + " (不满足分析条件)");
                    }
                    continue;
                }
                
                try {
                    List<Unit> units = getOrAnalyzeMethodUnits(method);
                    if (units != null && !units.isEmpty()) {
                        methodBodies.put(method, units);
                        methodCount++;
                        if (className.equals("com.sun.syndication.feed.impl.EqualsBean")) {
                            logger.info("   ✅ 收集EqualsBean方法: " + method.getName() + " (" + units.size() + " units)");
                        }
                    } else {
                        if (className.equals("com.sun.syndication.feed.impl.EqualsBean")) {
                            logger.warning("   ❌ EqualsBean方法无units: " + method.getName());
                        }
                    }
                } catch (Exception e) {
                    logger.warning("收集方法体失败: " + method.getSignature() + " - " + e.getMessage());
                }
            }
        }
        
        logger.info("方法体收集完成: " + classCount + " 个类，" + methodCount + " 个方法");
        return methodBodies;
    }
    
    /**
     * 获取或分析方法的Jimple单元
     */
    public List<Unit> getOrAnalyzeMethodUnits(SootMethod method) {
        // 先检查缓存
        if (methodUnits.containsKey(method)) {
            return methodUnits.get(method);
        }
        
        List<Unit> units = null;
        
        try {
            // 确保方法有方法体
            if (!method.hasActiveBody()) {
                if (method.isConcrete()) {
                    method.retrieveActiveBody();
                } else {
                    methodUnits.put(method, null);
                    return null;
                }
            }
            
            // 获取Jimple单元
            Body body = method.getActiveBody();
            if (body != null) {
                units = new ArrayList<>();
                for (Unit unit : body.getUnits()) {
                    units.add(unit);
                }
            }
            
        } catch (Exception e) {
            logger.fine("获取方法单元失败: " + method.getSignature() + " - " + e.getMessage());
        }
        
        // 缓存结果（包括null）
        methodUnits.put(method, units);
        return units;
    }
    
    /**
     * 判断是否应该分析这个类
     */
    public boolean shouldAnalyzeClass(SootClass sootClass) {
        if (sootClass == null) return false;
        
        try {
            String className = sootClass.getName();
            
            // 排除基础系统类，但保留重要的JDK gadget类
            if (className.startsWith("sun.") || 
                className.startsWith("jdk.") ||
                className.startsWith("java.lang.invoke.") ||
                className.startsWith("java.util.concurrent.locks.") ||
                className.startsWith("java.security.")) {
                
                // 🎭 特殊处理：保留 AnnotationInvocationHandler（CC1 链关键类）
                if (className.equals("sun.reflect.annotation.AnnotationInvocationHandler")) {
                    return true;
                }
                
                return false;
            }
            
            // 特殊处理：com.sun.* 包下的类大部分要排除，但保留重要的JDK gadget类
            if (className.startsWith("com.sun.")) {
                // 保留重要的XSLT gadget类
                if (className.startsWith("com.sun.org.apache.xalan.internal.xsltc.trax.") ||
                    className.startsWith("com.sun.org.apache.xalan.internal.xsltc.runtime.")) {
                    return true;  // 🎯 强制包含JDK内部gadget类
                }
                // 🎯 保留Rome RSS/Atom库类
                if (className.startsWith("com.sun.syndication.")) {
                    return true;  // 🎯 强制包含Rome第三方库类
                }
                return false;  // 其他com.sun.*类排除
            }
            
            // 只分析具体类（非抽象、非接口，除非是重要的序列化类）
            if (sootClass.isAbstract() || sootClass.isInterface()) {
                return isImportantSerializationClass(sootClass);
            }
            
            return true;
            
        } catch (Exception e) {
            logger.warning("检查类分析条件时出错: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 判断是否应该分析这个方法
     */
    public boolean shouldAnalyzeMethod(SootMethod method) {
        if (method == null) return false;
        
        try {
            // 跳过原生方法和抽象方法
            if (method.isNative() || method.isAbstract()) {
                return false;
            }
            
            // 排除系统生成的方法
            String methodName = method.getName();
            if (methodName.startsWith("access$") || 
                methodName.contains("$")) {
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            logger.warning("检查方法分析条件时出错: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 判断是否是用户代码类
     */
    public boolean isUserClass(SootClass sootClass) {
        if (sootClass == null) return false;
        
        String className = sootClass.getName();
        return !className.startsWith("java.") && 
               !className.startsWith("javax.") && 
               !className.startsWith("sun.") && 
               !className.startsWith("com.sun.") &&
               !className.startsWith("jdk.");
    }
    
    /**
     * 判断是否是重要的序列化相关类
     */
    public boolean isImportantSerializationClass(SootClass sootClass) {
        try {
            String className = sootClass.getName();
            
            // 重要的集合类（包括抽象基类）
            if (className.equals("java.util.HashMap") ||
                className.equals("java.util.ArrayList") ||
                className.equals("java.util.LinkedList") ||
                className.equals("java.util.HashSet") ||
                className.equals("java.util.TreeSet") ||
                className.equals("java.util.TreeMap") ||
                className.equals("java.util.Vector") ||
                className.equals("java.util.concurrent.ConcurrentHashMap") ||
                className.equals("java.util.AbstractMap") ||
                className.equals("java.util.AbstractCollection") ||
                className.equals("java.util.AbstractList") ||
                className.equals("java.util.AbstractSet") ||
                className.equals("java.util.Hashtable") ||
                className.equals("java.util.PriorityQueue")) {
                return true;
            }
            
            // 重要的字符串类
            if (className.equals("java.lang.String") ||
                className.equals("java.lang.StringBuffer") ||
                className.equals("java.lang.StringBuilder")) {
                return true;
            }
            
            // 重要的网络类
            if (className.equals("java.net.URL") ||
                className.equals("java.io.File")) {
                return true;
            }
            
            // 检查是否实现了Serializable
            return implementsSerializable(sootClass);
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 检查类是否实现了Serializable接口
     */
    private boolean implementsSerializable(SootClass sootClass) {
        try {
            // 检查直接实现的接口
            for (SootClass interfaceClass : sootClass.getInterfaces()) {
                if ("java.io.Serializable".equals(interfaceClass.getName())) {
                    return true;
                }
                // 递归检查接口继承
                if (implementsSerializable(interfaceClass)) {
                    return true;
                }
            }
            
            // 检查父类
            if (sootClass.hasSuperclass()) {
                return implementsSerializable(sootClass.getSuperclass());
            }
        } catch (Exception e) {
            // 忽略异常
        }
        
        return false;
    }
    
    /**
     * 获取方法单元缓存的统计信息
     */
    public void printCacheStatistics() {
        int totalMethods = methodUnits.size();
        int validBodies = (int) methodUnits.values().stream().filter(Objects::nonNull).count();
        
        logger.info("方法单元缓存统计：");
        logger.info("  - 缓存方法总数: " + totalMethods);
        logger.info("  - 有效方法体数: " + validBodies);
        logger.info("  - 无效方法体数: " + (totalMethods - validBodies));
    }
    
    /**
     * 清理缓存
     */
    public void clearCache() {
        methodUnits.clear();
        logger.info("方法单元缓存已清理");
    }
}
