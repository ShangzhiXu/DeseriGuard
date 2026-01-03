package com.squirtle.core.resolver;

import soot.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * 桥接方法检测器
 * 
 * 用于识别Java泛型擦除产生的桥接方法，并追踪到实际的实现方法。
 * 这是解决静态分析中泛型擦除导致调用图不完整问题的核心组件。
 * 
 * @author BugTurtle
 * @version 1.0
 */
public class BridgeMethodDetector {
    
    private static final Logger logger = Logger.getLogger(BridgeMethodDetector.class.getName());
    
    /**
     * 检测方法是否为桥接方法
     * 
     * 桥接方法的特征：
     * 1. 参数类型更泛化（如Object而不是具体类型）
     * 2. 在同一类中存在同名但参数类型更具体的方法
     * 3. 通常由编译器自动生成以保持泛型擦除后的接口兼容性
     * 
     * @param method 待检测的方法
     * @return 如果是桥接方法返回true，否则返回false
     */
    public static boolean isBridgeMethod(SootMethod method) {
        if (method == null || method.getParameterCount() == 0) {
            return false;
        }
        
        try {
            SootClass declaringClass = method.getDeclaringClass();
            String methodName = method.getName();
            int paramCount = method.getParameterCount();
            
            // 查找同名但参数类型更具体的方法
            for (SootMethod otherMethod : declaringClass.getMethods()) {
                if (otherMethod != method && 
                    methodName.equals(otherMethod.getName()) &&
                    paramCount == otherMethod.getParameterCount()) {
                    
                    // 比较参数类型的具体性
                    boolean isMoreGeneric = checkParameterGenericity(method, otherMethod);
                    if (isMoreGeneric) {
                        logger.fine("🔍 检测到桥接方法: " + method.getSignature() + 
                                   " -> " + otherMethod.getSignature());
                        return true;
                    }
                }
            }
            
            return false;
        } catch (Exception e) {
            logger.warning("检测桥接方法时出错: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 比较两个方法的参数类型泛化程度
     * 
     * @param method1 方法1
     * @param method2 方法2  
     * @return 如果method1的参数类型比method2更泛化，返回true
     */
    private static boolean checkParameterGenericity(SootMethod method1, SootMethod method2) {
        for (int i = 0; i < method1.getParameterCount(); i++) {
            Type type1 = method1.getParameterType(i);
            Type type2 = method2.getParameterType(i);
            
            // 如果method1的参数是Object，而method2是更具体的类型
            if (isMoreGeneric(type1, type2)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 判断type1是否比type2更泛化
     * 
     * @param type1 类型1
     * @param type2 类型2
     * @return 如果type1比type2更泛化，返回true
     */
    private static boolean isMoreGeneric(Type type1, Type type2) {
        String typeName1 = type1.toString();
        String typeName2 = type2.toString();
        
        // Object是最泛化的类型
        if ("java.lang.Object".equals(typeName1) && 
            !"java.lang.Object".equals(typeName2)) {
            return true;
        }
        
        // 检查其他常见的泛化情况
        return isGenericTypeErasure(typeName1, typeName2);
    }
    
    /**
     * 检查是否为常见的泛型擦除情况
     * 
     * @param genericType 泛化类型
     * @param specificType 具体类型
     * @return 如果是泛型擦除情况，返回true
     */
    private static boolean isGenericTypeErasure(String genericType, String specificType) {
        // 常见的泛型擦除模式
        Map<String, Set<String>> erasurePatterns = new HashMap<>();
        
        // Object -> 具体类型
        Set<String> objectTargets = new HashSet<>();
        objectTargets.add("java.lang.Class");
        objectTargets.add("java.lang.String");
        objectTargets.add("java.util.Collection");
        objectTargets.add("java.util.Map");
        objectTargets.add("java.util.List");
        erasurePatterns.put("java.lang.Object", objectTargets);
        
        // Collection -> 具体集合类型
        Set<String> collectionTargets = new HashSet<>();
        collectionTargets.add("java.util.List");
        collectionTargets.add("java.util.Set");
        collectionTargets.add("java.util.Queue");
        erasurePatterns.put("java.util.Collection", collectionTargets);
        
        Set<String> possibleSpecificTypes = erasurePatterns.get(genericType);
        if (possibleSpecificTypes != null) {
            if (possibleSpecificTypes.contains(specificType)) {
                return true;
            }
            // 检查前缀匹配
            for (String pattern : possibleSpecificTypes) {
                if (specificType.startsWith(pattern)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * 查找桥接方法对应的实际实现方法
     * 
     * @param bridgeMethod 桥接方法
     * @return 实际实现方法，如果找不到返回null
     */
    public static SootMethod findActualImplementation(SootMethod bridgeMethod) {
        if (bridgeMethod == null || !isBridgeMethod(bridgeMethod)) {
            return null;
        }
        
        try {
            SootClass declaringClass = bridgeMethod.getDeclaringClass();
            String methodName = bridgeMethod.getName();
            int paramCount = bridgeMethod.getParameterCount();
            
            // 查找同名但参数类型更具体的方法
            for (SootMethod candidate : declaringClass.getMethods()) {
                if (candidate != bridgeMethod && 
                    methodName.equals(candidate.getName()) &&
                    paramCount == candidate.getParameterCount()) {
                    
                    // 检查是否为更具体的实现
                    if (checkParameterGenericity(bridgeMethod, candidate)) {
                        logger.info("🎯 找到桥接方法的实际实现: " + 
                                   bridgeMethod.getSignature() + " -> " + candidate.getSignature());
                        return candidate;
                    }
                }
            }
            
            logger.fine("未找到桥接方法的实际实现: " + bridgeMethod.getSignature());
            return null;
        } catch (Exception e) {
            logger.warning("查找实际实现方法时出错: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 获取方法的所有桥接方法
     * 
     * @param actualMethod 实际实现方法
     * @return 该方法的所有桥接方法集合
     */
    public static Set<SootMethod> findBridgeMethodsFor(SootMethod actualMethod) {
        Set<SootMethod> bridgeMethods = new HashSet<>();
        
        if (actualMethod == null) {
            return bridgeMethods;
        }
        
        try {
            SootClass declaringClass = actualMethod.getDeclaringClass();
            String methodName = actualMethod.getName();
            int paramCount = actualMethod.getParameterCount();
            
            // 查找同名但参数类型更泛化的方法
            for (SootMethod candidate : declaringClass.getMethods()) {
                if (candidate != actualMethod && 
                    methodName.equals(candidate.getName()) &&
                    paramCount == candidate.getParameterCount()) {
                    
                    // 检查是否为桥接方法
                    if (checkParameterGenericity(candidate, actualMethod)) {
                        bridgeMethods.add(candidate);
                        logger.fine("🔗 找到桥接方法: " + candidate.getSignature() + 
                                   " -> " + actualMethod.getSignature());
                    }
                }
            }
            
        } catch (Exception e) {
            logger.warning("查找桥接方法时出错: " + e.getMessage());
        }
        
        return bridgeMethods;
    }
    
    /**
     * 分析类中的所有桥接方法关系
     * 
     * @param clazz 要分析的类
     * @return 桥接方法到实际方法的映射
     */
    public static Map<SootMethod, SootMethod> analyzeBridgeMethodsInClass(SootClass clazz) {
        Map<SootMethod, SootMethod> bridgeToActual = new HashMap<>();
        
        if (clazz == null) {
            return bridgeToActual;
        }
        
        try {
            for (SootMethod method : clazz.getMethods()) {
                if (isBridgeMethod(method)) {
                    SootMethod actualMethod = findActualImplementation(method);
                    if (actualMethod != null) {
                        bridgeToActual.put(method, actualMethod);
                    }
                }
            }
            
            if (!bridgeToActual.isEmpty()) {
                logger.info("📊 类 " + clazz.getName() + " 中发现 " + 
                           bridgeToActual.size() + " 个桥接方法");
            }
            
        } catch (Exception e) {
            logger.warning("分析类的桥接方法时出错: " + e.getMessage());
        }
        
        return bridgeToActual;
    }
}
