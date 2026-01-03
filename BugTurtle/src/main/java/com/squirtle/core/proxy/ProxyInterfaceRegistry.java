package com.squirtle.core.proxy;

import soot.*;
import soot.jimple.*;

import java.util.*;
import java.util.logging.Logger;

/**
 * 全局 Proxy 接口注册表（优化版）
 * 
 * 功能：
 * 1. 记录哪些接口在程序中被用作动态代理
 * 2. 提供改进的启发式规则识别可疑的 Proxy 接口
 * 3. 支持调用图构建时查询接口是否可能是 Proxy
 * 
 * 优化内容：
 * 1. 更智能的接口识别规则
 * 2. 分析接口方法的危险性
 * 3. 检查readObject中实际使用的字段
 * 
 * @author BugTurtle
 * @version 3.0 - 改进的启发式规则
 */
public class ProxyInterfaceRegistry {
    
    private static final Logger logger = Logger.getLogger(ProxyInterfaceRegistry.class.getName());
    
    /** 已确认的 Proxy 接口（通过 Proxy.newProxyInstance 识别） */
    private final Set<SootClass> confirmedProxyInterfaces;
    
    /** 可疑的 Proxy 接口（通过启发式规则识别） */
    private final Set<SootClass> suspectedProxyInterfaces;
    
    /** 所有 InvocationHandler 实现类（用于建立桥接边） */
    private final Set<SootClass> invocationHandlerClasses;
    
    /** 🆕 可疑接口的评分映射 */
    private final Map<SootClass, Integer> interfaceSuspicionScores;
    
    /**
     * 构造器
     */
    public ProxyInterfaceRegistry() {
        this.confirmedProxyInterfaces = new HashSet<>();
        this.suspectedProxyInterfaces = new HashSet<>();
        this.invocationHandlerClasses = new HashSet<>();
        this.interfaceSuspicionScores = new HashMap<>();
    }
    
    /**
     * 注册一个确认的 Proxy 接口
     * 
     * @param interfaceClass 接口类
     */
    public void registerConfirmedInterface(SootClass interfaceClass) {
        if (interfaceClass != null && interfaceClass.isInterface()) {
            confirmedProxyInterfaces.add(interfaceClass);
            logger.fine("✅ 注册确认的 Proxy 接口: " + interfaceClass.getName());
        }
    }
    
    /**
     * 注册多个确认的 Proxy 接口
     */
    public void registerConfirmedInterfaces(Set<SootClass> interfaces) {
        for (SootClass iface : interfaces) {
            registerConfirmedInterface(iface);
        }
    }
    
    /**
     * 🆕 注册一个可疑的 Proxy 接口（带评分）
     */
    public void registerSuspectedInterface(SootClass interfaceClass, int suspicionScore) {
        if (interfaceClass != null && interfaceClass.isInterface()) {
            suspectedProxyInterfaces.add(interfaceClass);
            
            // 累加可疑度评分
            int currentScore = interfaceSuspicionScores.getOrDefault(interfaceClass, 0);
            interfaceSuspicionScores.put(interfaceClass, currentScore + suspicionScore);
            
            logger.fine("🔍 注册可疑的 Proxy 接口: " + interfaceClass.getName() + 
                       " (评分: " + interfaceSuspicionScores.get(interfaceClass) + ")");
        }
    }
    
    /**
     * 注册一个可疑的 Proxy 接口（兼容旧版本）
     */
    public void registerSuspectedInterface(SootClass interfaceClass) {
        registerSuspectedInterface(interfaceClass, 1);
    }
    
    /**
     * 注册一个 InvocationHandler 实现类
     */
    public void registerInvocationHandler(SootClass handlerClass) {
        if (handlerClass != null && !handlerClass.isInterface()) {
            invocationHandlerClasses.add(handlerClass);
            logger.fine("📝 注册 InvocationHandler: " + handlerClass.getName());
        }
    }
    
    /**
     * 检查一个接口是否可能是 Proxy
     * 
     * @param interfaceClass 接口类
     * @return true 如果是确认的或可疑的 Proxy 接口
     */
    public boolean isPotentialProxyInterface(SootClass interfaceClass) {
        return confirmedProxyInterfaces.contains(interfaceClass) ||
               suspectedProxyInterfaces.contains(interfaceClass);
    }
    
    /**
     * 🆕 检查接口是否是高可疑度的Proxy接口
     */
    public boolean isHighSuspicionProxyInterface(SootClass interfaceClass) {
        return interfaceSuspicionScores.getOrDefault(interfaceClass, 0) >= 3;
    }
    
    /**
     * 获取所有 InvocationHandler 实现类
     */
    public Set<SootClass> getInvocationHandlerClasses() {
        return Collections.unmodifiableSet(invocationHandlerClasses);
    }
    
    /**
     * 扫描并注册所有 InvocationHandler 实现类
     */
    public void scanInvocationHandlers(Collection<SootClass> analysisClasses) {
        logger.info("🔍 扫描 InvocationHandler 实现类...");
        
        int count = 0;
        for (SootClass cls : analysisClasses) {
            if (implementsInvocationHandler(cls)) {
                registerInvocationHandler(cls);
                count++;
            }
        }
        
        logger.info("✅ 发现 " + count + " 个 InvocationHandler 实现类");
    }
    
    /**
     * 🆕 应用改进的启发式规则识别可疑的 Proxy 接口
     */
    public void applyHeuristicRules(Collection<SootClass> analysisClasses) {
        logger.info("🔍 应用改进的启发式规则...");
        
        int ruleCount = 0;
        
        for (SootClass cls : analysisClasses) {
            try {
                // 规则 1: readObject 方法中实际使用的接口字段
                if (cls.declaresMethodByName("readObject")) {
                    ruleCount += applyReadObjectRule(cls);
                }
                
                // 规则 2: Serializable 类的接口类型字段（过滤后）
                if (implementsSerializable(cls)) {
                    ruleCount += applySerializableFieldRule(cls);
                }
                
                // 🆕 规则 3: 检查包含Proxy.newProxyInstance调用的类
                ruleCount += applyProxyCreationRule(cls);
                
            } catch (Exception e) {
                logger.fine("应用规则失败: " + cls.getName() + " - " + e.getMessage());
            }
        }
        
        logger.info("✅ 启发式规则识别了 " + ruleCount + " 个可疑 Proxy 接口");
        
        // 🆕 打印高可疑度接口
        printHighSuspicionInterfaces();
    }
    
    /**
     * 🆕 规则 1: readObject方法中实际使用的接口字段（改进版）
     */
    private int applyReadObjectRule(SootClass cls) {
        int count = 0;
        
        try {
            SootMethod readObject = cls.getMethodByNameUnsafe("readObject");
            if (readObject == null || !readObject.hasActiveBody()) {
                return 0;
            }
            
            // 🆕 分析readObject中实际使用的字段
            Set<SootField> usedFields = analyzeUsedFields(readObject);
            
            for (SootField field : cls.getFields()) {
                // 只考虑实际使用的字段
                if (!usedFields.contains(field)) {
                    continue;
                }
                
                Type fieldType = field.getType();
                if (!(fieldType instanceof RefType)) {
                    continue;
                }
                
                SootClass fieldClass = ((RefType) fieldType).getSootClass();
                
                if (!fieldClass.isInterface()) {
                    continue;
                }
                
                // 🆕 检查接口是否有可疑方法
                int suspicionScore = calculateInterfaceSuspicionScore(fieldClass);
                
                if (suspicionScore > 0) {
                    registerSuspectedInterface(fieldClass, suspicionScore);
                    count++;
                    logger.fine("  规则1: " + fieldClass.getName() + 
                               " (评分: " + suspicionScore + ", 在 " + cls.getName() + ".readObject 中使用)");
                }
            }
        } catch (Exception e) {
            logger.fine("应用readObject规则失败: " + e.getMessage());
        }
        
        return count;
    }
    
    /**
     * 🆕 分析方法中实际使用的字段
     */
    private Set<SootField> analyzeUsedFields(SootMethod method) {
        Set<SootField> usedFields = new HashSet<>();
        
        if (!method.hasActiveBody()) {
            return usedFields;
        }
        
        Body body = method.getActiveBody();
        for (Unit unit : body.getUnits()) {
            if (unit instanceof Stmt) {
                Stmt stmt = (Stmt) unit;
                
                // 检查语句中的所有值
                for (ValueBox valueBox : stmt.getUseAndDefBoxes()) {
                    Value value = valueBox.getValue();
                    
                    if (value instanceof InstanceFieldRef) {
                        InstanceFieldRef fieldRef = (InstanceFieldRef) value;
                        try {
                            SootField field = fieldRef.getField();
                            usedFields.add(field);
                        } catch (Exception e) {
                            // 忽略解析失败
                        }
                    }
                }
            }
        }
        
        return usedFields;
    }
    
    /**
     * 🆕 计算接口的可疑度评分
     */
    private int calculateInterfaceSuspicionScore(SootClass interfaceClass) {
        int score = 0;
        
        try {
            // 检查接口方法
            for (SootMethod method : interfaceClass.getMethods()) {
                String methodName = method.getName().toLowerCase();
                
                // 危险方法名
                if (methodName.contains("invoke") || 
                    methodName.contains("execute") ||
                    methodName.contains("eval")) {
                    score += 3;  // 高危
                }
                
                // 可疑方法名
                if (methodName.contains("get") || 
                    methodName.contains("set") ||
                    methodName.contains("call")) {
                    score += 2;  // 中危
                }
                
                // 常见的对象方法（可能被利用）
                if (methodName.equals("tostring") || 
                    methodName.equals("hashcode") ||
                    methodName.equals("equals")) {
                    score += 1;  // 低危
                }
            }
            
            // 🆕 检查接口名称
            String interfaceName = interfaceClass.getShortName().toLowerCase();
            if (interfaceName.contains("map") || 
                interfaceName.contains("list") ||
                interfaceName.contains("collection") ||
                interfaceName.contains("comparable")) {
                score += 2;  // 常见的集合接口更可疑
            }
            
        } catch (Exception e) {
            logger.fine("计算接口可疑度失败: " + e.getMessage());
        }
        
        return score;
    }
    
    /**
     * 🆕 规则 2: Serializable类的接口字段（改进版）
     */
    private int applySerializableFieldRule(SootClass cls) {
        int count = 0;
        
        try {
            for (SootField field : cls.getFields()) {
                // 🆕 排除transient字段（不会被序列化）
                if (soot.Modifier.isTransient(field.getModifiers())) {
                    continue;
                }
                
                Type fieldType = field.getType();
                if (!(fieldType instanceof RefType)) {
                    continue;
                }
                
                SootClass fieldClass = ((RefType) fieldType).getSootClass();
                
                if (!fieldClass.isInterface()) {
                    continue;
                }
                
                // 🆕 只标记常见的集合接口
                if (isCommonCollectionInterface(fieldClass)) {
                    int suspicionScore = calculateInterfaceSuspicionScore(fieldClass);
                    
                    if (suspicionScore > 0) {
                        registerSuspectedInterface(fieldClass, suspicionScore);
                        count++;
                        logger.fine("  规则2: " + fieldClass.getName() + 
                                   " (评分: " + suspicionScore + ", 在 Serializable 类 " + cls.getName() + " 中)");
                    }
                }
            }
        } catch (Exception e) {
            logger.fine("应用Serializable字段规则失败: " + e.getMessage());
        }
        
        return count;
    }
    
    /**
     * 🆕 规则 3: 检查包含Proxy.newProxyInstance调用的类
     */
    private int applyProxyCreationRule(SootClass cls) {
        int count = 0;
        
        try {
            for (SootMethod method : cls.getMethods()) {
                if (!method.hasActiveBody()) {
                    continue;
                }
                
                Body body = method.getActiveBody();
                for (Unit unit : body.getUnits()) {
                    if (!(unit instanceof Stmt)) {
                        continue;
                    }
                    
                    Stmt stmt = (Stmt) unit;
                    if (!stmt.containsInvokeExpr()) {
                        continue;
                    }
                    
                    InvokeExpr invokeExpr = stmt.getInvokeExpr();
                    SootMethod calledMethod = invokeExpr.getMethod();
                    
                    // 检查是否是Proxy.newProxyInstance
                    if (calledMethod.getName().equals("newProxyInstance") &&
                        calledMethod.getDeclaringClass().getName().equals("java.lang.reflect.Proxy")) {
                        
                        // 🆕 尝试提取接口参数
                        Set<SootClass> interfaces = extractProxyInterfaces(invokeExpr);
                        for (SootClass iface : interfaces) {
                            registerConfirmedInterface(iface);  // 这是确认的Proxy接口
                            count++;
                            logger.info("  规则3: 确认 Proxy 接口 " + iface.getName() + 
                                       " (来自 Proxy.newProxyInstance)");
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.fine("应用Proxy创建规则失败: " + e.getMessage());
        }
        
        return count;
    }
    
    /**
     * 🆕 从Proxy.newProxyInstance调用中提取接口
     */
    private Set<SootClass> extractProxyInterfaces(InvokeExpr invokeExpr) {
        Set<SootClass> interfaces = new HashSet<>();
        
        // Proxy.newProxyInstance的第二个参数是Class[]数组
        if (invokeExpr.getArgCount() >= 2) {
            Value interfacesArg = invokeExpr.getArg(1);
            
            // 简化处理：如果是常见的单接口场景
            // 完整实现需要数组分析（可以复用ConstructorReflectionAnalyzer的方法）
            
            // 暂时只处理简单情况
            logger.fine("检测到 Proxy.newProxyInstance 调用，需要提取接口参数");
        }
        
        return interfaces;
    }
    
    /**
     * 🆕 打印高可疑度接口
     */
    private void printHighSuspicionInterfaces() {
        List<Map.Entry<SootClass, Integer>> sortedInterfaces = new ArrayList<>(interfaceSuspicionScores.entrySet());
        sortedInterfaces.sort((e1, e2) -> e2.getValue().compareTo(e1.getValue()));
        
        if (!sortedInterfaces.isEmpty()) {
            logger.info("\n🎯 高可疑度 Proxy 接口 (Top 10):");
            int count = 0;
            for (Map.Entry<SootClass, Integer> entry : sortedInterfaces) {
                if (count >= 10) break;
                logger.info("  " + (count + 1) + ". " + entry.getKey().getName() + 
                           " (评分: " + entry.getValue() + ")");
                count++;
            }
        }
    }
    
    /**
     * 检查一个类是否实现了 InvocationHandler
     */
    private boolean implementsInvocationHandler(SootClass cls) {
        try {
            if (cls.isInterface() || cls.isPhantom()) {
                return false;
            }
            
            // 检查直接实现
            for (SootClass iface : cls.getInterfaces()) {
                if ("java.lang.reflect.InvocationHandler".equals(iface.getName())) {
                    return true;
                }
            }
            
            // 检查父类实现
            if (cls.hasSuperclass() && !cls.getSuperclass().getName().equals("java.lang.Object")) {
                return implementsInvocationHandler(cls.getSuperclass());
            }
        } catch (Exception e) {
            // 忽略错误
        }
        
        return false;
    }
    
    /**
     * 检查一个类是否实现了 Serializable
     */
    private boolean implementsSerializable(SootClass cls) {
        try {
            for (SootClass iface : cls.getInterfaces()) {
                if ("java.io.Serializable".equals(iface.getName())) {
                    return true;
                }
            }
            
            if (cls.hasSuperclass() && !cls.getSuperclass().getName().equals("java.lang.Object")) {
                return implementsSerializable(cls.getSuperclass());
            }
        } catch (Exception e) {
            // 忽略错误
        }
        
        return false;
    }
    
    /**
     * 检查是否是常见的集合接口
     */
    private boolean isCommonCollectionInterface(SootClass cls) {
        String name = cls.getName();
        return name.equals("java.util.Map") ||
               name.equals("java.util.List") ||
               name.equals("java.util.Set") ||
               name.equals("java.util.Collection") ||
               name.equals("java.util.Queue") ||
               name.equals("java.lang.Comparable");
    }
    
    /**
     * 获取统计信息
     */
    public RegistryStatistics getStatistics() {
        return new RegistryStatistics(
            confirmedProxyInterfaces.size(),
            suspectedProxyInterfaces.size(),
            invocationHandlerClasses.size()
        );
    }
    
    /**
     * 打印注册表详细信息（调试用）
     */
    public void printDetails() {
        logger.info("========================================");
        logger.info("ProxyInterfaceRegistry 详细信息:");
        logger.info("========================================");
        
        logger.info("InvocationHandler 实现类 (" + invocationHandlerClasses.size() + " 个):");
        for (SootClass handler : invocationHandlerClasses) {
            logger.info("  - " + handler.getName());
        }
        
        logger.info("\n可疑 Proxy 接口 (" + suspectedProxyInterfaces.size() + " 个):");
        for (SootClass iface : suspectedProxyInterfaces) {
            int score = interfaceSuspicionScores.getOrDefault(iface, 0);
            logger.info("  - " + iface.getName() + " (评分: " + score + ")");
        }
        
        logger.info("\n确认的 Proxy 接口 (" + confirmedProxyInterfaces.size() + " 个):");
        for (SootClass iface : confirmedProxyInterfaces) {
            logger.info("  - " + iface.getName());
        }
        
        logger.info("========================================");
    }
    
    /**
     * 统计信息
     */
    public static class RegistryStatistics {
        private final int confirmedInterfaceCount;
        private final int suspectedInterfaceCount;
        private final int handlerCount;
        
        public RegistryStatistics(int confirmedInterfaceCount, 
                                 int suspectedInterfaceCount,
                                 int handlerCount) {
            this.confirmedInterfaceCount = confirmedInterfaceCount;
            this.suspectedInterfaceCount = suspectedInterfaceCount;
            this.handlerCount = handlerCount;
        }
        
        public int getConfirmedInterfaceCount() { return confirmedInterfaceCount; }
        public int getSuspectedInterfaceCount() { return suspectedInterfaceCount; }
        public int getHandlerCount() { return handlerCount; }
        
        @Override
        public String toString() {
            return String.format("ProxyRegistry{confirmed=%d, suspected=%d, handlers=%d}",
                               confirmedInterfaceCount, suspectedInterfaceCount, handlerCount);
        }
    }
}
