package com.squirtle.core.resolver;

import soot.*;
import soot.jimple.InvokeExpr;

import java.util.*;
import java.util.logging.Logger;

/**
 * CHA（Class Hierarchy Analysis）解析器
 * 
 * 负责所有的类层次分析逻辑，包括：
 * 1. 虚拟方法调用的目标解析
 * 2. 接口方法调用的目标解析
 * 3. 带类型提示的精确解析
 * 4. 类层次关系判断
 * 
 * @author BugTurtle
 * @version 1.0
 */
public class CHAResolver {
    
    private static final Logger logger = Logger.getLogger(CHAResolver.class.getName());
    
    private final Set<SootClass> analysisClasses;
    
    public CHAResolver(Set<SootClass> analysisClasses) {
        this.analysisClasses = analysisClasses;
    }
    
    /**
     * 使用CHA解析虚拟方法调用的可能目标
     */
    public Set<SootMethod> resolveVirtualCall(SootMethod method, InvokeExpr invokeExpr) {
        Set<SootMethod> targets = new HashSet<>();
        
        // 添加调试日志
        String methodName = method.getName();
        String declaringClassName = method.getDeclaringClass().getName();
        if ("equals".equals(methodName)) {
            logger.info("CHA解析equals调用: " + declaringClassName + "." + methodName);
            logger.info("   分析类集合大小: " + analysisClasses.size());
        }
        
        // 调试：检查lookup调用
        if ("lookup".equals(methodName)) {
            logger.info("CHA解析虚拟调用: " + declaringClassName + "." + methodName);
            logger.info("   isKeyJndiMethod: " + isKeyJndiMethod(declaringClassName, methodName));
        }
        
        // 1. 添加声明的方法（如果不是抽象的）
        if (!method.isAbstract()) {
            targets.add(method);
        }
        
        // 2. CHA分析：查找所有可能的重写方法
        SootClass declaringClass = method.getDeclaringClass();
        String methodSubSignature = method.getSubSignature();
        
        // 在所有分析类中查找子类的重写方法（包括JDK类）
        int candidateClassCount = 0;
        int equalsOverrideCount = 0;
        
        for (SootClass analysisClass : analysisClasses) {
            if (isSubclassOf(analysisClass, declaringClass) && !analysisClass.isAbstract()) {
                candidateClassCount++;
                
                // 查找最具体的重写方法
                SootMethod concreteMethod = findMostSpecificMethod(analysisClass, methodSubSignature);
                if (concreteMethod != null && !concreteMethod.isAbstract()) {
                    targets.add(concreteMethod);
                    equalsOverrideCount++;
                }
            }
        }
        
        if ("equals".equals(methodName)) {
            logger.info("   CHA统计: 候选类数=" + candidateClassCount + 
                       ", equals重写数=" + equalsOverrideCount + 
                       ", 总目标数=" + targets.size());
        }
        
        // 特殊处理：对于JNDI lookup等关键方法，扩展搜索范围到Scene中的所有类
        // InitialContext.lookup()是虚拟调用，但我们需要找到所有Context接口的实现
        if (isKeyJndiMethod(declaringClassName, methodName)) {
            logger.info("检测到关键JNDI虚拟调用，扩展搜索到Scene: " + method.getSignature());
            int sceneTargets = 0;
            
            // 获取Context接口
            SootClass contextInterface = null;
            try {
                if (Scene.v().containsClass("javax.naming.Context")) {
                    contextInterface = Scene.v().getSootClass("javax.naming.Context");
                }
            } catch (Exception e) {
                logger.warning("无法获取Context接口: " + e.getMessage());
            }
            
            for (SootClass sootClass : Scene.v().getClasses()) {
                // 跳过已经在analysisClasses中的类
                if (analysisClasses.contains(sootClass)) continue;
                
                if (!sootClass.isAbstract() && !sootClass.isPhantom()) {
                    boolean shouldCheck = false;
                    
                    // 检查是否是子类或实现了Context接口
                    if (isSubclassOf(sootClass, declaringClass)) {
                        shouldCheck = true;
                    } else if (contextInterface != null && implementsInterface(sootClass, contextInterface)) {
                        shouldCheck = true;  // 也检查Context接口的实现
                    }
                    
                    if (shouldCheck) {
                        SootMethod concreteMethod = findMostSpecificMethod(sootClass, methodSubSignature);
                        if (concreteMethod != null && !concreteMethod.isAbstract()) {
                            targets.add(concreteMethod);
                            sceneTargets++;
                            logger.info("   从Scene找到实现: " + sootClass.getName() + "." + methodName);
                        }
                    }
                }
            }
            logger.info("   从Scene额外找到 " + sceneTargets + " 个实现");
        }
        
        // 3. 如果没有找到任何具体实现，但原方法不是抽象的，至少包含原方法
        if (targets.isEmpty() && !method.isAbstract()) {
            targets.add(method);
        }
        
        return targets;
    }
    
    /**
     * 使用CHA解析接口方法调用的可能目标（支持桥接方法追踪）
     */
    public Set<SootMethod> resolveInterfaceCall(SootMethod interfaceMethod) {
        Set<SootMethod> targets = new HashSet<>();
        
        SootClass interfaceClass = interfaceMethod.getDeclaringClass();
        String methodSubSignature = interfaceMethod.getSubSignature();
        String methodName = interfaceMethod.getName();
        
        // 调试：检查是否为JNDI方法
        if ("lookup".equals(methodName) && interfaceClass.getName().contains("naming")) {
            logger.info("解析接口调用: " + interfaceClass.getName() + "." + methodName);
            logger.info("   isKeyJndiMethod: " + isKeyJndiMethod(interfaceClass.getName(), methodName));
        }
        
        // 遍历所有分析类，查找接口的实现
        for (SootClass analysisClass : analysisClasses) {
            if (!analysisClass.isAbstract() && implementsInterface(analysisClass, interfaceClass)) {
                // 查找接口方法的具体实现（会自动追踪桥接方法）
                SootMethod implementation = findInterfaceImplementation(analysisClass, methodSubSignature);
                if (implementation != null && !implementation.isAbstract()) {
                    targets.add(implementation);
                }
            }
        }
        
        // 同时检查抽象类中的部分实现
        for (SootClass analysisClass : analysisClasses) {
            if (analysisClass.isAbstract() && implementsInterface(analysisClass, interfaceClass)) {
                if (analysisClass.declaresMethod(methodSubSignature)) {
                    SootMethod abstractImpl = analysisClass.getMethod(methodSubSignature);
                    if (!abstractImpl.isAbstract()) {
                        // 检查抽象类中的桥接方法
                        if (BridgeMethodDetector.isBridgeMethod(abstractImpl)) {
                            SootMethod actualMethod = BridgeMethodDetector.findActualImplementation(abstractImpl);
                            if (actualMethod != null) {
                                targets.add(actualMethod);
                            } else {
                                targets.add(abstractImpl);
                            }
                        } else {
                            targets.add(abstractImpl);
                        }
                    }
                }
            }
        }
        
        // 特殊处理：对于JNDI lookup等关键接口方法，扩展搜索范围到Scene中的所有类
        // 这是为了找到JDK内部的实现类（如RegistryContext），它们可能不在analysisClasses中
        if (isKeyJndiMethod(interfaceClass.getName(), methodName)) {
            logger.info("检测到关键JNDI方法，扩展搜索到Scene: " + interfaceMethod.getSignature());
            int sceneTargets = 0;
            for (SootClass sootClass : Scene.v().getClasses()) {
                // 跳过已经在analysisClasses中的类
                if (analysisClasses.contains(sootClass)) continue;
                
                if (!sootClass.isAbstract() && !sootClass.isPhantom() && 
                    implementsInterface(sootClass, interfaceClass)) {
                    SootMethod implementation = findInterfaceImplementation(sootClass, methodSubSignature);
                    if (implementation != null && !implementation.isAbstract()) {
                        targets.add(implementation);
                        sceneTargets++;
                        logger.info("   从Scene找到实现: " + sootClass.getName() + "." + methodName);
                    }
                }
            }
            logger.info("   从Scene额外找到 " + sceneTargets + " 个实现");
        }
        
        return targets;
    }
    
    /**
     * 解析接口调用并返回桥接方法映射（用于双边建立）
     * 
     * @param interfaceMethod 接口方法
     * @return 桥接方法到实际方法的映射，如果没有桥接方法则返回空映射
     */
    public Map<SootMethod, SootMethod> resolveInterfaceCallWithBridgeMapping(SootMethod interfaceMethod) {
        Map<SootMethod, SootMethod> bridgeToActual = new HashMap<>();
        
        SootClass interfaceClass = interfaceMethod.getDeclaringClass();
        String methodSubSignature = interfaceMethod.getSubSignature();
        
        // 遍历所有分析类，查找接口的实现
        for (SootClass analysisClass : analysisClasses) {
            if (!analysisClass.isAbstract() && implementsInterface(analysisClass, interfaceClass)) {
                // 先找到桥接方法
                SootMethod bridgeMethod = findInterfaceImplementationWithBridge(analysisClass, methodSubSignature);
                if (bridgeMethod != null && !bridgeMethod.isAbstract()) {
                    // 检查是否为桥接方法
                    if (BridgeMethodDetector.isBridgeMethod(bridgeMethod)) {
                        SootMethod actualMethod = BridgeMethodDetector.findActualImplementation(bridgeMethod);
                        if (actualMethod != null) {
                            bridgeToActual.put(bridgeMethod, actualMethod);
                            logger.info("接口调用桥接映射: " + bridgeMethod.getSignature() + 
                                       " -> " + actualMethod.getSignature());
                        }
                    }
                }
            }
        }
        
        return bridgeToActual;
    }
    
    /**
     * 使用CHA解析虚拟调用，但在有类型推断提示时将搜索范围限制到该类型及其子类
     */
    public Set<SootMethod> resolveVirtualCallWithHint(SootMethod method, SootClass hintedReceiverType) {
        Set<SootMethod> targets = new HashSet<>();

        if (method == null || hintedReceiverType == null) {
            return resolveVirtualCall(method, null);
        }

        try {
            SootClass declaringClass = method.getDeclaringClass();
            String methodSubSignature = method.getSubSignature();

            // 1) 在提示类型上获取最具体实现
            SootMethod onHint = findMostSpecificMethod(hintedReceiverType, methodSubSignature);
            if (onHint != null && !onHint.isAbstract()) {
                targets.add(onHint);
            }

            // 2) 在所有分析类中查找同时是 hintedReceiverType 的子类 且 声明类的子类
            for (SootClass analysisClass : analysisClasses) {
                if (!analysisClass.isAbstract()
                    && isSubclassOf(analysisClass, hintedReceiverType)
                    && isSubclassOf(analysisClass, declaringClass)) {
                    SootMethod concreteMethod = findMostSpecificMethod(analysisClass, methodSubSignature);
                    if (concreteMethod != null && !concreteMethod.isAbstract()) {
                        targets.add(concreteMethod);
                    }
                }
            }

            if (targets.isEmpty()) {
                return resolveVirtualCall(method, null);
            }
        } catch (Exception ignored) {}

        targets.removeIf(Objects::isNull);
        return targets;
    }

    /**
     * 使用CHA解析接口调用，但在有类型推断提示时将搜索范围限制到该类型（若为类则其子类，若为接口则其实现）
     */
    public Set<SootMethod> resolveInterfaceCallWithHint(SootMethod interfaceMethod, SootClass hintedReceiverType) {
        Set<SootMethod> targets = new HashSet<>();

        if (interfaceMethod == null || hintedReceiverType == null) {
            return resolveInterfaceCall(interfaceMethod);
        }

        try {
            SootClass interfaceClass = interfaceMethod.getDeclaringClass();
            String methodSubSignature = interfaceMethod.getSubSignature();

            for (SootClass analysisClass : analysisClasses) {
                if (!analysisClass.isAbstract()
                    && implementsInterface(analysisClass, interfaceClass)
                    && isSubtypeOrImplements(analysisClass, hintedReceiverType)) {
                    SootMethod implementation = findInterfaceImplementation(analysisClass, methodSubSignature);
                    if (implementation != null && !implementation.isAbstract()) {
                        targets.add(implementation);
                    }
                }
            }

            if (targets.isEmpty()) {
                return resolveInterfaceCall(interfaceMethod);
            }
        } catch (Exception ignored) {}

        return targets;
    }
    
    /**
     * 判断是否为关键JNDI方法，需要扩展搜索范围
     */
    private boolean isKeyJndiMethod(String className, String methodName) {
        // javax.naming.Context接口及其实现类的关键方法
        if (className.equals("javax.naming.Context") || 
            className.equals("javax.naming.InitialContext") ||
            className.equals("javax.naming.spi.ContinuationContext") ||
            className.contains("Context")) {  // 包含Context的类也检查
            return methodName.equals("lookup") || 
                   methodName.equals("bind") || 
                   methodName.equals("rebind") ||
                   methodName.equals("unbind");
        }
        return false;
    }
    
    /**
     * 查找类中最具体的方法实现
     */
    public SootMethod findMostSpecificMethod(SootClass clazz, String methodSubSignature) {
        // 首先检查当前类是否声明了该方法
        if (clazz.declaresMethod(methodSubSignature)) {
            return clazz.getMethod(methodSubSignature);
        }
        
        // 如果当前类没有声明，向上查找父类
        SootClass current = clazz;
        while (current.hasSuperclass()) {
            current = current.getSuperclass();
            if (current.declaresMethod(methodSubSignature)) {
                return current.getMethod(methodSubSignature);
            }
        }
        
        return null;
    }
    
    /**
     * 查找接口方法在类中的具体实现（增强版：支持桥接方法追踪）
     */
    public SootMethod findInterfaceImplementation(SootClass clazz, String methodSubSignature) {
        // 首先检查当前类是否直接实现了该方法
        if (clazz.declaresMethod(methodSubSignature)) {
            SootMethod method = clazz.getMethod(methodSubSignature);
            if (!method.isAbstract()) {
                // 检查是否为桥接方法，如果是则追踪到实际实现
                if (BridgeMethodDetector.isBridgeMethod(method)) {
                    SootMethod actualMethod = BridgeMethodDetector.findActualImplementation(method);
                    if (actualMethod != null) {
                        logger.info("接口实现桥接方法追踪: " + method.getSignature() + 
                                   " -> " + actualMethod.getSignature());
                        return actualMethod;
                    }
                }
                return method;
            }
        }
        
        // 向上查找父类中的实现
        SootClass current = clazz;
        while (current.hasSuperclass()) {
            current = current.getSuperclass();
            if (current.declaresMethod(methodSubSignature)) {
                SootMethod method = current.getMethod(methodSubSignature);
                if (!method.isAbstract()) {
                    // 同样检查父类中的桥接方法
                    if (BridgeMethodDetector.isBridgeMethod(method)) {
                        SootMethod actualMethod = BridgeMethodDetector.findActualImplementation(method);
                        if (actualMethod != null) {
                            logger.info("父类接口实现桥接方法追踪: " + method.getSignature() + 
                                       " -> " + actualMethod.getSignature());
                            return actualMethod;
                        }
                    }
                    return method;
                }
            }
        }
        
        return null;
    }
    
    /**
     * 查找接口方法在类中的具体实现（返回桥接方法，用于双边建立）
     */
    public SootMethod findInterfaceImplementationWithBridge(SootClass clazz, String methodSubSignature) {
        // 首先检查当前类是否直接实现了该方法
        if (clazz.declaresMethod(methodSubSignature)) {
            SootMethod method = clazz.getMethod(methodSubSignature);
            if (!method.isAbstract()) {
                return method; // 返回桥接方法本身
            }
        }
        
        // 向上查找父类中的实现
        SootClass current = clazz;
        while (current.hasSuperclass()) {
            current = current.getSuperclass();
            if (current.declaresMethod(methodSubSignature)) {
                SootMethod method = current.getMethod(methodSubSignature);
                if (!method.isAbstract()) {
                    return method; // 返回桥接方法本身
                }
            }
        }
        
        return null;
    }
    
    /**
     * 判断 clazz 是否是 hinted 的子类型，或在 hinted 为接口时是否实现了该接口
     */
    public boolean isSubtypeOrImplements(SootClass clazz, SootClass hinted) {
        try {
            if (hinted.isInterface()) {
                return implementsInterface(clazz, hinted);
            }
            return isSubclassOf(clazz, hinted);
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * 判断引用类型是否过于泛化（如 java.lang.Object），用于避免退化为大范围 CHA
     */
    public boolean isTooGenericRefType(SootClass refType) {
        try {
            String n = refType.getName();
            if ("java.lang.Object".equals(n)) return true;
            return false;
        } catch (Exception ignored) {}
        return false;
    }
    
    /**
     * 检查类A是否是类B的子类
     */
    public boolean isSubclassOf(SootClass subClass, SootClass superClass) {
        if (subClass.equals(superClass)) return true;
        
        SootClass current = subClass;
        while (current.hasSuperclass()) {
            current = current.getSuperclass();
            if (current.equals(superClass)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 检查类是否实现了指定接口
     */
    public boolean implementsInterface(SootClass clazz, SootClass interfaceClass) {
        try {
            // 检查直接实现的接口
            for (SootClass directInterface : clazz.getInterfaces()) {
                if (directInterface.equals(interfaceClass)) {
                    return true;
                }
                // 递归检查接口的父接口
                if (implementsInterface(directInterface, interfaceClass)) {
                    return true;
                }
            }
            
            // 检查父类是否实现了该接口
            if (clazz.hasSuperclass()) {
                return implementsInterface(clazz.getSuperclass(), interfaceClass);
            }
        } catch (Exception e) {
            // 忽略接口分析异常
        }
        
        return false;
    }
}




