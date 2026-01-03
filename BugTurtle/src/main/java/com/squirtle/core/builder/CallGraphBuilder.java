package com.squirtle.core.builder;

import soot.*;
import soot.jimple.*;
import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.resolver.CHAResolver;
import com.squirtle.core.resolver.TypeInferenceEngine;
import com.squirtle.core.resolver.BridgeMethodDetector;
import com.squirtle.core.proxy.ProxyInterfaceRegistry;
import com.squirtle.core.reflection.resolver.ReflectionCallResolver;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

/**
 * 调用图构建器
 * 
 * 负责调用图的构建，包括：
 * 1. 工作列表驱动的调用图构建
 * 2. 多态调用处理
 * 3. 各种invoke表达式分析
 * 4. 性能优化（Final、Private、Constructor、Library边界控制）
 * 
 * @author BugTurtle
 * @version 1.0
 */
public class CallGraphBuilder {
    
    private static final Logger logger = Logger.getLogger(CallGraphBuilder.class.getName());
    
    private final CHAResolver chaResolver;
    private final TypeInferenceEngine typeInference;
    
    // 分析相关
    private Set<SootClass> analysisClasses;
    private Map<SootMethod, List<Unit>> methodBodies;
    private Set<SootMethod> readObjectMethods;
    
    // 调用图和工作列表
    private CallGraph callGraph;
    private Queue<SootMethod> methodWorkList;
    private Set<SootMethod> processedMethods;
    
    // 🎭 动态代理分析
    private ProxyInterfaceRegistry proxyRegistry;
    private int proxyBridgeEdgeCount = 0;
    
    // 🔮 反射调用分析
    private ReflectionCallResolver reflectionResolver;
    private int reflectionBridgeEdgeCount = 0;
    
    public CallGraphBuilder(CHAResolver chaResolver, TypeInferenceEngine typeInference) {
        this.chaResolver = chaResolver;
        this.typeInference = typeInference;
        this.callGraph = new CallGraph();
        this.methodWorkList = new LinkedBlockingQueue<>();
        this.processedMethods = ConcurrentHashMap.newKeySet();
        this.reflectionResolver = new ReflectionCallResolver();
    }
    
    /**
     * 设置 ProxyInterfaceRegistry
     */
    public void setProxyInterfaceRegistry(ProxyInterfaceRegistry proxyRegistry) {
        this.proxyRegistry = proxyRegistry;
        logger.info("✅ ProxyInterfaceRegistry 已注入到 CallGraphBuilder");
    }
    
    /**
     * 获取 Proxy 桥接边数量
     */
    public int getProxyBridgeEdgeCount() {
        return proxyBridgeEdgeCount;
    }
    
    /**
     * 获取 Reflection 桥接边数量
     */
    public int getReflectionBridgeEdgeCount() {
        return reflectionBridgeEdgeCount;
    }
    
    /**
     * 构建自定义调用图
     */
    public CallGraph buildCallGraph(Set<SootClass> analysisClasses, 
                                    Map<SootMethod, List<Unit>> methodBodies,
                                    Set<SootMethod> readObjectMethods) {
        this.analysisClasses = analysisClasses;
        this.methodBodies = methodBodies;
        this.readObjectMethods = readObjectMethods;
        
        logger.info("第二阶段：构建自定义调用图（工作列表驱动）");
        
        // 1. 添加入口方法到工作列表
        addEntryMethodsToWorklist(analysisClasses);
        
        // 2. 使用工作列表驱动的分析
        int totalCallSites = analyzeCallSitesWithWorklist();
        
        logger.info("调用图构建完成，共分析 " + totalCallSites + " 个调用点，分析了 " + processedMethods.size() + " 个方法");
        
        return callGraph;
    }
    
    /**
     * 添加入口方法到工作列表
     */
    private void addEntryMethodsToWorklist(Set<SootClass> analysisClasses) {
        for (SootClass sootClass : analysisClasses) {
            for (SootMethod method : sootClass.getMethods()) {
                // 添加main方法作为入口点
                if ("main".equals(method.getName()) && method.isStatic()) {
                    methodWorkList.offer(method);
                    logger.info("✅ 添加入口方法: " + method.getSignature());
                }
                
                // 添加所有readObject方法作为入口点
                if (readObjectMethods.contains(method)) {
                    methodWorkList.offer(method);
                    //logger.fine("✅ 添加readObject入口: " + method.getSignature());
                }
            }
        }
    }
    
    /**
     * 工作列表驱动的调用点分析
     */
    private int analyzeCallSitesWithWorklist() {
        int totalCallSites = 0;
        
        while (!methodWorkList.isEmpty()) {
            SootMethod currentMethod = methodWorkList.poll();
            
            // 避免重复处理
            if (processedMethods.contains(currentMethod)) {
                continue;
            }
            processedMethods.add(currentMethod);
            
            // 获取方法体（优先从缓存，如果没有则现场提取）
            List<Unit> units = methodBodies.get(currentMethod);
            if (units == null && currentMethod.hasActiveBody()) {
                // 🔧 关键修复：对于不在初始集合但在工作列表中的方法（如JDK方法），现场提取方法体
                try {
                    units = new ArrayList<>();
                    for (Unit unit : currentMethod.getActiveBody().getUnits()) {
                        units.add(unit);
                    }
                    methodBodies.put(currentMethod, units);
                    logger.info("🔧 现场提取方法体: " + currentMethod.getSignature() + 
                               " (units: " + units.size() + ")");
                } catch (Exception e) {
                    logger.warning("现场提取方法体失败: " + currentMethod.getSignature());
                }
            }
            
            if (units == null) {
                logger.fine("⏭ 跳过无方法体的方法: " + currentMethod.getSignature());
                continue;
            }
            
            // 分析当前方法中的所有调用
            for (Unit unit : units) {
                totalCallSites += analyzeInvokeExpressionWithWorklist(currentMethod, unit);
            }
            
            // 🔮 分析当前方法中的反射调用
            int reflectionEdges = reflectionResolver.processMethod(
                callGraph, currentMethod, units, 
                methodWorkList, processedMethods, 
                this::shouldAnalyzeLibraryMethod);
            if (reflectionEdges > 0) {
                reflectionBridgeEdgeCount += reflectionEdges;
                logger.info("🔮 反射桥接: " + currentMethod.getName() + " → " + reflectionEdges + " 条边");
            }
        }
        
        return totalCallSites;
    }
    
    /**
     * 分析调用表达式（工作列表版本）
     */
    private int analyzeInvokeExpressionWithWorklist(SootMethod caller, Unit unit) {
        int callSiteCount = 0;
        
        if (unit instanceof InvokeStmt) {
            InvokeExpr invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
            callSiteCount += analyzeInvokeExpression(caller, invokeExpr, unit);
            
        } else if (unit instanceof AssignStmt) {
            AssignStmt assignStmt = (AssignStmt) unit;
            if (assignStmt.getRightOp() instanceof InvokeExpr) {
                InvokeExpr invokeExpr = (InvokeExpr) assignStmt.getRightOp();
                callSiteCount += analyzeInvokeExpression(caller, invokeExpr, unit);
            }
        }
        
        return callSiteCount;
    }
    
    /**
     * 分析具体的调用表达式
     */
    private int analyzeInvokeExpression(SootMethod caller, InvokeExpr invokeExpr, Unit unit) {
        try {
            SootMethod targetMethod = invokeExpr.getMethod();
            
            // **特殊处理：ObjectInputStream.readObject()调用**
            if (isReadObjectCall(targetMethod)) {
                return handleDeserializationCall(caller, invokeExpr, unit);
            }
            
            // 🔮 **注意：反射调用会继续添加普通边，同时在后续由 ReflectionCallResolver 添加桥接边**
            // 不跳过，因为测试需要看到对 Constructor.newInstance() 的普通调用
            // 反射桥接边会在 analyzeCallSitesWithWorklist() 中额外添加
            
            if (invokeExpr instanceof StaticInvokeExpr) {
                // 静态调用：直接确定目标
                handleDirectCall(caller, targetMethod, unit);
                return 1;
                
            } else if (invokeExpr instanceof SpecialInvokeExpr) {
                // 特殊调用（构造函数、super调用、private方法）
                handleDirectCall(caller, targetMethod, unit);
                return 1;
                
            } else if (invokeExpr instanceof VirtualInvokeExpr || invokeExpr instanceof InterfaceInvokeExpr) {
                // 多态调用
                return handlePolymorphicCall(caller, invokeExpr, unit);
                
            } else if (invokeExpr instanceof DynamicInvokeExpr) {
                // 动态调用（Lambda表达式等）
                logger.fine("跳过动态调用: " + invokeExpr);
                return 0;
            }
        } catch (Exception e) {
            logger.warning("分析调用表达式失败: " + e.getMessage());
        }
        
        return 0;
    }
    
    /**
     * 🔮 检查是否为反射调用
     */
    private boolean isReflectionCall(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        
        // Constructor.newInstance()
        if (className.equals("java.lang.reflect.Constructor") && 
            methodName.equals("newInstance")) {
            return true;
        }
        
        // Method.invoke()
        if (className.equals("java.lang.reflect.Method") && 
            methodName.equals("invoke")) {
            return true;
        }
        
        // Class.newInstance()
        if (className.equals("java.lang.Class") && 
            methodName.equals("newInstance")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 处理直接调用（静态、特殊调用）
     */
    private void handleDirectCall(SootMethod caller, SootMethod target, Unit unit) {
        // 添加调用边
        callGraph.addCall(caller, target, unit, CallGraph.CallType.STATIC);
        
        // 将目标方法添加到工作列表（如果尚未处理）
        if (!processedMethods.contains(target) && shouldAnalyzeLibraryMethod(target)) {
            methodWorkList.offer(target);
        }
    }
    
    /**
     * 处理多态调用（虚拟调用、接口调用）
     */
    private int handlePolymorphicCall(SootMethod caller, InvokeExpr invokeExpr, Unit unit) {
        SootMethod declaredMethod = invokeExpr.getMethod();
        SootClass declaringClass = declaredMethod.getDeclaringClass();
        
        // 🎭 **优先检查：Proxy 接口桥接**
        if (proxyRegistry != null && 
            declaringClass.isInterface() && 
            proxyRegistry.isPotentialProxyInterface(declaringClass)) {
            
            // 建立到 InvocationHandler.invoke() 的桥接边
            int bridgeEdges = addProxyBridgeEdges(caller, invokeExpr, unit, declaringClass);
            
            if (bridgeEdges > 0) {
                logger.fine("🎭 Proxy 桥接: " + declaredMethod.getName() + 
                           " on " + declaringClass.getName() + 
                           " → " + bridgeEdges + " InvocationHandler(s)");
            }
            // 注意：仍然继续正常的 CHA 分析，因为可能既是 Proxy 又有正常实现
        }
        
        // **Final优化**：Final类的方法调用可以直接确定目标
        if (declaredMethod.getDeclaringClass().isFinal()) {
            handleDirectCall(caller, declaredMethod, unit);
            return 1;
        }
        
        // **Private方法优化**：Private方法不能被重写
        if (declaredMethod.isPrivate()) {
            handleDirectCall(caller, declaredMethod, unit);
            return 1;
        }
        
        // **构造函数优化**：构造函数不能被重写
        if ("<init>".equals(declaredMethod.getName())) {
            handleDirectCall(caller, declaredMethod, unit);
            return 1;
        }
        
        // 进行CHA分析
        Set<SootMethod> possibleTargets;
        InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) invokeExpr;
        
        // **先尝试类型推断**：在库边界控制之前进行类型推断
        SootClass inferredType = typeInference.inferReceiverType(caller, unit, instanceInvoke);
        
        // **智能库边界控制**：如果类型推断成功且目标不是库方法，则继续分析
        if (inferredType == null && !shouldAnalyzeLibraryMethod(declaredMethod)) {
            handleDirectCall(caller, declaredMethod, unit);
            return 1;
        }
        
        if (invokeExpr instanceof VirtualInvokeExpr) {
            if (inferredType != null) {
                possibleTargets = chaResolver.resolveVirtualCallWithHint(declaredMethod, inferredType);
            } else {
                possibleTargets = chaResolver.resolveVirtualCall(declaredMethod, invokeExpr);
            }
        } else { // InterfaceInvokeExpr
            if (inferredType != null) {
                possibleTargets = chaResolver.resolveInterfaceCallWithHint(declaredMethod, inferredType);
            } else {
                possibleTargets = chaResolver.resolveInterfaceCall(declaredMethod);
                
                // 🎯 处理泛型擦除：为接口调用建立双边桥接调用图
                handleGenericErasureBridgeCalls(caller, declaredMethod, unit, invokeExpr);
            }
        }
        
        // 添加所有可能的调用边
        for (SootMethod target : possibleTargets) {
            CallGraph.CallType callType = (invokeExpr instanceof VirtualInvokeExpr) ? 
                CallGraph.CallType.VIRTUAL : CallGraph.CallType.INTERFACE;
            callGraph.addCall(caller, target, unit, callType);
            
            // 将目标方法添加到工作列表（如果尚未处理）
            if (!processedMethods.contains(target) && shouldAnalyzeLibraryMethod(target)) {
                methodWorkList.offer(target);
            }
        }
        
        return possibleTargets.size();
    }
    
    /**
     * 🎭 建立 Proxy 桥接边：接口调用 → InvocationHandler.invoke()
     */
    private int addProxyBridgeEdges(SootMethod caller, InvokeExpr invokeExpr, 
                                    Unit unit, SootClass proxyInterface) {
        if (proxyRegistry == null) {
            return 0;
        }
        
        int edgeCount = 0;
        
        // 获取所有 InvocationHandler 实现类
        Set<SootClass> handlerClasses = proxyRegistry.getInvocationHandlerClasses();
        
        if (handlerClasses.isEmpty()) {
            logger.fine("⚠️ 未找到任何 InvocationHandler 实现类");
            return 0;
        }
        
        // InvocationHandler.invoke() 方法签名
        String invokeSig = "java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])";
        
        // 为每个 InvocationHandler 实现类建立桥接边
        for (SootClass handlerClass : handlerClasses) {
            try {
                if (handlerClass.declaresMethod(invokeSig)) {
                    SootMethod invokeMethod = handlerClass.getMethod(invokeSig);
                    
                    // 建立 PROXY 类型的调用边
                    callGraph.addCall(caller, invokeMethod, unit, CallGraph.CallType.PROXY);
                    
                    // 将 invoke() 方法添加到工作列表
                    if (!processedMethods.contains(invokeMethod) && 
                        shouldAnalyzeLibraryMethod(invokeMethod)) {
                        methodWorkList.offer(invokeMethod);
                    }
                    
                    edgeCount++;
                    proxyBridgeEdgeCount++;
                    
                    logger.finer("  → " + handlerClass.getName() + ".invoke()");
                }
            } catch (Exception e) {
                logger.fine("建立 Proxy 桥接边失败: " + handlerClass.getName() + " - " + e.getMessage());
            }
        }
        
        return edgeCount;
    }
    
    /**
     * 处理泛型擦除产生的桥接方法调用
     * 建立双边调用图：接口调用 -> 桥接方法 -> 实际实现
     */
    private void handleGenericErasureBridgeCalls(SootMethod caller, SootMethod interfaceMethod, 
                                                Unit unit, InvokeExpr invokeExpr) {
        try {
            // 获取桥接方法映射
            Map<SootMethod, SootMethod> bridgeMapping = chaResolver.resolveInterfaceCallWithBridgeMapping(interfaceMethod);
            
            if (bridgeMapping.isEmpty()) {
                return; // 没有桥接方法
            }
            
            logger.info("🎯 处理泛型擦除桥接调用: " + interfaceMethod.getSignature() + 
                       " (发现 " + bridgeMapping.size() + " 个桥接方法)");
            
            // 为每个桥接方法建立双边调用图
            for (Map.Entry<SootMethod, SootMethod> entry : bridgeMapping.entrySet()) {
                SootMethod bridgeMethod = entry.getKey();
                SootMethod actualMethod = entry.getValue();
                
                // 1. 建立 caller -> bridgeMethod 的接口调用边
                callGraph.addCall(caller, bridgeMethod, unit, CallGraph.CallType.INTERFACE);
                logger.info("🔗 建立接口调用边: " + caller.getSignature() + 
                           " -> " + bridgeMethod.getSignature());
                
                // 2. 建立 bridgeMethod -> actualMethod 的桥接调用边
                callGraph.addCall(bridgeMethod, actualMethod, unit, CallGraph.CallType.BRIDGE);
                logger.info("🔗 建立桥接调用边: " + bridgeMethod.getSignature() + 
                           " -> " + actualMethod.getSignature());
                
                // 3. 将桥接方法和实际方法都添加到工作列表
                if (!processedMethods.contains(bridgeMethod) && shouldAnalyzeLibraryMethod(bridgeMethod)) {
                    methodWorkList.offer(bridgeMethod);
                    logger.fine("📝 桥接方法加入工作列表: " + bridgeMethod.getSignature());
                }
                
                if (!processedMethods.contains(actualMethod) && shouldAnalyzeLibraryMethod(actualMethod)) {
                    methodWorkList.offer(actualMethod);
                    logger.fine("📝 实际方法加入工作列表: " + actualMethod.getSignature());
                }
            }
            
        } catch (Exception e) {
            logger.warning("处理桥接方法调用时出错: " + e.getMessage());
        }
    }
    
    /**
     * 库边界控制：判断是否应该分析库方法
     * 
     * 🔧 Flash风格：所有Scene中的类都可以被分析，不在运行时过滤
     * - Soot classpath配置已经控制了哪些类被加载（目标JAR + rt.jar）
     * - 初始targetClasses已经控制了哪些类是起点
     * - 工作列表应该无限制地扩展到所有可达方法
     * - 后续通过污点分析和controllability pruning剪枝
     */
    private boolean shouldAnalyzeLibraryMethod(SootMethod method) {
        if (method == null) return false;
        
        try {
            String className = method.getDeclaringClass().getName();
            
            // 🔧 修改：所有非系统内部类都分析
            // 只排除JDK内部实现类和编译器生成的类
            if (className.startsWith("jdk.internal.") ||
                className.startsWith("sun.reflect.Generated") ||
                className.startsWith("apple.laf.")) {
                return false;  // 这些是真正的内部实现，不参与gadget链
            }
            
            // 🎯 其他所有类（包括java.*、javax.*等）都分析
            // Flash的做法：让CHA自由扩展，后续通过污点分析剪枝
            return true;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 判断是否是关键的JDK方法
     */
    private boolean isKeyJDKMethod(String className, String methodName) {
        // 重要的序列化方法
        if ("readObject".equals(methodName) || "writeObject".equals(methodName) ||
            "readResolve".equals(methodName) || "writeReplace".equals(methodName)) {
            return true;
        }
        
        // 重要的Object方法
        if ("java.lang.Object".equals(className) && 
            ("clone".equals(methodName) || "finalize".equals(methodName))) {
            return true;
        }
        
        // 重要的通用getter方法（常见于第三方库和JDK内部类）
        if ("getValue".equals(methodName) || "getKey".equals(methodName) || 
            "getName".equals(methodName) || "getType".equals(methodName) ||
            "getClass".equals(methodName) || "getMethod".equals(methodName)) {
            return true;
        }
        
        // 🎯 Scriptable接口的关键方法（JavaScript引擎相关）
        if ("get".equals(methodName) || "put".equals(methodName) || 
            "has".equals(methodName) || "delete".equals(methodName) ||
            "getIds".equals(methodName) || "getPrototype".equals(methodName) ||
            "setPrototype".equals(methodName) || "getParentScope".equals(methodName) ||
            "setParentScope".equals(methodName) || "getDefaultValue".equals(methodName)) {
            return true;
        }
        
        // 重要的集合操作
        if ((className.startsWith("java.util.") || className.startsWith("java.util.concurrent.")) &&
            ("put".equals(methodName) || "get".equals(methodName) || "add".equals(methodName) || 
             "remove".equals(methodName) || "clear".equals(methodName) || "size".equals(methodName) ||
             "isEmpty".equals(methodName) || "contains".equals(methodName) || "iterator".equals(methodName))) {
            return true;
        }

        // PriorityQueue反序列化gadget关键方法
        if ("java.util.PriorityQueue".equals(className) &&
            ("heapify".equals(methodName) || "siftDown".equals(methodName) || "siftUp".equals(methodName) ||
             "siftDownComparable".equals(methodName) || "siftUpComparable".equals(methodName) ||
             "siftDownUsingComparator".equals(methodName) || "siftUpUsingComparator".equals(methodName))) {
            return true;
        }

        // HashMap反序列化gadget关键方法
        if ("java.util.HashMap".equals(className) &&
            ("putVal".equals(methodName) || "hash".equals(methodName) || "resize".equals(methodName) ||
             "treeifyBin".equals(methodName) || "untreeify".equals(methodName))) {
            return true;
        }

        // TreeMap反序列化gadget关键方法
        if ("java.util.TreeMap".equals(className) &&
            ("compare".equals(methodName) || "compareComparator".equals(methodName) ||
             "fixAfterInsertion".equals(methodName) || "fixAfterDeletion".equals(methodName))) {
            return true;
        }

        // Hashtable反序列化gadget关键方法
        if ("java.util.Hashtable".equals(className) &&
            ("reconstitutionPut".equals(methodName) || "addEntry".equals(methodName))) {
            return true;
        }

        // 重要的字符串方法
        if ("java.lang.String".equals(className) &&
            ("length".equals(methodName) || "charAt".equals(methodName) || "substring".equals(methodName) ||
             "indexOf".equals(methodName) || "toString".equals(methodName) || "equals".equals(methodName) ||
             "hashCode".equals(methodName))) {
            return true;
        }
        
        // 重要的包装类方法
        if ((className.equals("java.lang.Integer") || className.equals("java.lang.Long") ||
             className.equals("java.lang.Double") || className.equals("java.lang.Float")) &&
            ("intValue".equals(methodName) || "longValue".equals(methodName) || 
             "doubleValue".equals(methodName) || "floatValue".equals(methodName) ||
             "toString".equals(methodName) || "valueOf".equals(methodName))) {
            return true;
        }
        
        // 重要的IO方法
        if (className.startsWith("java.io.") &&
            ("read".equals(methodName) || "write".equals(methodName) || "close".equals(methodName) ||
             "flush".equals(methodName) || "available".equals(methodName))) {
            return true;
        }

        // 重要的Comparator相关方法（PriorityQueue gadget关键）
        if (className.startsWith("java.util.") &&
            ("compare".equals(methodName) || "compareTo".equals(methodName))) {
            return true;
        }

        // 重要的序列化流方法
        if (("java.io.ObjectInputStream".equals(className) || "java.io.ObjectOutputStream".equals(className)) &&
            ("readStreamHeader".equals(methodName) || "writeStreamHeader".equals(methodName) ||
             "readClassDescriptor".equals(methodName) || "writeClassDescriptor".equals(methodName))) {
            return true;
        }

        // 重要的URL相关方法（常见gadget）
        if ("java.net.URL".equals(className) &&
            ("openConnection".equals(methodName) || "openStream".equals(methodName) ||
             "getContent".equals(methodName) || "hashCode".equals(methodName))) {
            return true;
        }

        // 重要的Runtime执行方法
        if ("java.lang.Runtime".equals(className) &&
            ("exec".equals(methodName) || "getRuntime".equals(methodName))) {
            return true;
        }

        // 重要的ProcessBuilder方法
        if ("java.lang.ProcessBuilder".equals(className) &&
            ("start".equals(methodName) || "command".equals(methodName))) {
            return true;
        }

        // 重要的反射方法
        if ("java.lang.Class".equals(className) &&
            ("forName".equals(methodName) || "newInstance".equals(methodName) ||
             "getMethod".equals(methodName) || "getDeclaredMethod".equals(methodName) ||
             "getField".equals(methodName) || "getDeclaredField".equals(methodName))) {
            return true;
        }

        // 🎯 XSLT Gadget 关键方法（TrAXFilter、TemplatesImpl）
        if (className.startsWith("com.sun.org.apache.xalan.internal.xsltc.trax.")) {
            if ("newTransformer".equals(methodName) || "getTransletInstance".equals(methodName) ||
                "defineTransletClasses".equals(methodName) || "getOutputProperties".equals(methodName) ||
                "<init>".equals(methodName)) {  // 构造函数也需要分析
                return true;
            }
        }

        return false;
    }

    /**
     * 判断是否是关键的第三方库方法（反序列化gadget相关）
     */
    private boolean isKeyThirdPartyMethod(String className, String methodName) {
        // C3P0相关gadget（JNDI注入）
        if ("com.mchange.v2.naming.ReferenceIndirector".equals(className) &&
            "getObject".equals(methodName)) {
            return true;
        }

        // C3P0数据源相关
        if (className.startsWith("com.mchange.v2.c3p0.") &&
            ("getConnection".equals(methodName) || "getObject".equals(methodName) ||
             "getReference".equals(methodName) || "setJndiName".equals(methodName))) {
            return true;
        }

        // Apache Commons Collections相关gadget
        if (className.startsWith("org.apache.commons.collections.") &&
            ("transform".equals(methodName) || "get".equals(methodName) ||
             "invoke".equals(methodName) || "execute".equals(methodName) ||
             "newTransformer".equals(methodName) || "getOutputProperties".equals(methodName))) {
            return true;
        }

        // Commons BeanUtils相关gadget
        if (className.startsWith("org.apache.commons.beanutils.") &&
            ("getProperty".equals(methodName) || "setProperty".equals(methodName) ||
             "invoke".equals(methodName) || "newInstance".equals(methodName))) {
            return true;
        }

        // Spring相关gadget
        if (className.startsWith("org.springframework.") &&
            ("getObject".equals(methodName) || "afterPropertiesSet".equals(methodName) ||
             "setBeanFactory".equals(methodName) || "setTargetSource".equals(methodName) ||
             "invoke".equals(methodName) || "proceed".equals(methodName))) {
            return true;
        }

        // Fastjson相关gadget
        if (className.startsWith("com.alibaba.fastjson.") &&
            ("parseObject".equals(methodName) || "toJSONString".equals(methodName) ||
             "getObject".equals(methodName) || "setValue".equals(methodName))) {
            return true;
        }

        // Jackson相关gadget
        if (className.startsWith("com.fasterxml.jackson.") &&
            ("readValue".equals(methodName) || "writeValueAsString".equals(methodName) ||
             "getObject".equals(methodName) || "setValue".equals(methodName))) {
            return true;
        }

        // Rome相关gadget
        if (className.startsWith("com.sun.syndication.") &&
            ("getObject".equals(methodName) || "toString".equals(methodName) ||
             "equals".equals(methodName) || "hashCode".equals(methodName))) {
            return true;
        }

        // Hibernate相关gadget
        if (className.startsWith("org.hibernate.") &&
            ("getObject".equals(methodName) || "invoke".equals(methodName) ||
             "intercept".equals(methodName) || "writeReplace".equals(methodName) ||
             "getValue".equals(methodName) || "getType".equals(methodName) ||
             "initialize".equals(methodName) || "hashCode".equals(methodName) ||
             "equals".equals(methodName) || "toString".equals(methodName))) {
            return true;
        }

        // AspectJ相关gadget
        if (className.startsWith("org.aspectj.") &&
            ("getObject".equals(methodName) || "proceed".equals(methodName) ||
             "invoke".equals(methodName) || "around".equals(methodName))) {
            return true;
        }

        // Groovy相关gadget
        if (className.startsWith("groovy.") &&
            ("invokeMethod".equals(methodName) || "call".equals(methodName) ||
             "getObject".equals(methodName) || "execute".equals(methodName))) {
            return true;
        }

        // 🎭 动态代理相关方法（InvocationHandler.invoke()）
        if ((className.equals("sun.reflect.annotation.AnnotationInvocationHandler") ||
             className.equals("java.lang.reflect.InvocationHandler")) &&
            "invoke".equals(methodName)) {
            return true;
        }
        
        // JNDI相关方法
        if (className.startsWith("javax.naming.") &&
            ("lookup".equals(methodName) || "getObject".equals(methodName) ||
             "getObjectInstance".equals(methodName) || "bind".equals(methodName))) {
            return true;
        }

        // RMI相关方法
        if (className.startsWith("java.rmi.") &&
            ("lookup".equals(methodName) || "bind".equals(methodName) ||
             "invoke".equals(methodName) || "getObject".equals(methodName))) {
            return true;
        }

        // LDAP相关方法
        if (className.startsWith("javax.naming.ldap.") &&
            ("getObject".equals(methodName) || "getObjectInstance".equals(methodName))) {
            return true;
        }
        
        // 🎯 通用getter方法（适用于所有第三方库）
        // 这些方法在反序列化和字段访问模式中非常常见
        if ("getValue".equals(methodName) || "getKey".equals(methodName) || 
            "getName".equals(methodName) || "getType".equals(methodName) ||
            "getObject".equals(methodName) || "get".equals(methodName) ||
            "initialize".equals(methodName) || "init".equals(methodName) ||
            "hashCode".equals(methodName) || "equals".equals(methodName) ||
            "toString".equals(methodName) || "clone".equals(methodName)) {
            return true;
        }
        
        // 🎯 JavaScript引擎相关方法（Rhino、Nashorn等）
        if (className.startsWith("org.mozilla.javascript.") ||
            className.startsWith("jdk.nashorn.") ||
            className.startsWith("org.openjdk.nashorn.")) {
            
            if ("get".equals(methodName) || "put".equals(methodName) || 
                "has".equals(methodName) || "delete".equals(methodName) ||
                "getIds".equals(methodName) || "getPrototype".equals(methodName) ||
                "setPrototype".equals(methodName) || "getParentScope".equals(methodName) ||
                "setParentScope".equals(methodName) || "getDefaultValue".equals(methodName) ||
                "call".equals(methodName) || "construct".equals(methodName) ||
                "getClassName".equals(methodName) || "hasInstance".equals(methodName)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 获取构建的调用图
     */
    public CallGraph getCallGraph() {
        return callGraph;
    }
    
    /**
     * 重置构建器状态
     */
    public void reset() {
        this.callGraph = new CallGraph();
        this.methodWorkList.clear();
        this.processedMethods.clear();
    }
    
    /**
     * 判断是否为ObjectInputStream.readObject()调用
     */
    private boolean isReadObjectCall(SootMethod method) {
        if (method == null) return false;
        
        // 检查是否为ObjectInputStream.readObject()调用
        return method.getName().equals("readObject") && 
               method.getDeclaringClass().getName().equals("java.io.ObjectInputStream");
    }
    
    /**
     * 处理反序列化调用，建立虚拟调用图
     */
    private int handleDeserializationCall(SootMethod caller, InvokeExpr invokeExpr, Unit unit) {
        logger.info("🎯 发现readObject调用: " + caller.getSignature() + " -> ObjectInputStream.readObject()");
        
        // 对readObject()的返回值进行完整类型推断
        SootClass narrowedType = null;
        if (unit instanceof AssignStmt && ((AssignStmt) unit).getLeftOp() instanceof Local) {
            Local resultLocal = (Local) ((AssignStmt) unit).getLeftOp();
            
            // 使用完整的5规则类型推断系统推断返回值类型
            narrowedType = typeInference.inferLocalType(caller, unit, resultLocal);
            
            if (narrowedType != null) {
                logger.info("🎯 反序列化完整类型推断成功: " + narrowedType.getName());
            } else {
                logger.fine("ℹ️ 反序列化类型推断未找到精确类型，将连接所有readObject方法");
            }
        }
        
        int addedEdges = 0;
        
        if (narrowedType != null) {
            logger.info("🎯 反序列化类型推断成功: " + narrowedType.getName());
            
            // 只为推断类型的readObject方法建立调用边
            for (SootMethod readObjectMethod : readObjectMethods) {
                if (readObjectMethod != null && 
                    readObjectMethod.isConcrete() &&
                    isSubclassOf(readObjectMethod.getDeclaringClass(), narrowedType)) {
                    
                    callGraph.addCall(caller, readObjectMethod, unit, CallGraph.CallType.VIRTUAL);
                    
                    // 将目标方法添加到工作列表
                    if (!processedMethods.contains(readObjectMethod)) {
                        methodWorkList.offer(readObjectMethod);
                    }
                    
                    logger.info("➤ 添加精确反序列化调用边: " + caller.getName() + " -> " + 
                               readObjectMethod.getDeclaringClass().getShortName() + ".readObject()");
                    addedEdges++;
                }
            }
        } else {
            // 没有类型推断信息，为所有序列化类的readObject方法建立虚拟调用关系
            logger.info("🔍 反序列化类型推断失败，使用全量CHA分析");
            
            for (SootMethod readObjectMethod : readObjectMethods) {
                if (readObjectMethod != null && readObjectMethod.isConcrete()) {
                    callGraph.addCall(caller, readObjectMethod, unit, CallGraph.CallType.VIRTUAL);
                    
                    // 将目标方法添加到工作列表
                    if (!processedMethods.contains(readObjectMethod)) {
                        methodWorkList.offer(readObjectMethod);
                    }
                    
                    logger.fine("➤ 添加反序列化调用边: " + caller.getName() + " -> " + 
                               readObjectMethod.getDeclaringClass().getShortName() + ".readObject()");
                    addedEdges++;
                }
            }
        }
        
        logger.info("✅ 反序列化检测完成，添加了 " + addedEdges + " 条虚拟调用边");
        return addedEdges;
    }
    
    /**
     * 检查类A是否是类B的子类
     */
    private boolean isSubclassOf(SootClass subClass, SootClass superClass) {
        if (subClass == null || superClass == null) return false;
        if (subClass.equals(superClass)) return true;
        
        try {
            // 检查直接父类
            if (subClass.hasSuperclass()) {
                SootClass parent = subClass.getSuperclass();
                if (parent.equals(superClass) || isSubclassOf(parent, superClass)) {
                    return true;
                }
            }
            
            // 检查接口
            for (SootClass interfaceClass : subClass.getInterfaces()) {
                if (interfaceClass.equals(superClass) || isSubclassOf(interfaceClass, superClass)) {
                    return true;
                }
            }
        } catch (Exception e) {
            // 忽略类层次分析异常
        }
        
        return false;
    }
}
