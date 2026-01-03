package com.squirtle.core.reflection.resolver;

import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.reflection.analyzer.ConstructorReflectionAnalyzer;
import com.squirtle.core.reflection.analyzer.MethodReflectionAnalyzer;
import com.squirtle.core.reflection.core.GlobalReflectionFlowMap;
import com.squirtle.core.reflection.core.ReflectionCallSite;
import com.squirtle.core.reflection.core.ReflectionTargetInfo;
import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

import java.util.*;
import java.util.logging.Logger;

/**
 * 反射调用解析器
 * 
 * 在调用图构建过程中识别并解析反射调用，建立反射桥接边
 */
public class ReflectionCallResolver {
    
    private static final Logger logger = Logger.getLogger(ReflectionCallResolver.class.getName());
    
    private final GlobalReflectionFlowMap reflectionFlowMap;
    private final ConstructorReflectionAnalyzer constructorAnalyzer;
    private final MethodReflectionAnalyzer methodAnalyzer;
    
    // 统计信息
    private int reflectionBridgeEdgeCount = 0;
    
    public ReflectionCallResolver() {
        this.reflectionFlowMap = new GlobalReflectionFlowMap();
        this.constructorAnalyzer = new ConstructorReflectionAnalyzer(reflectionFlowMap);
        this.methodAnalyzer = new MethodReflectionAnalyzer(reflectionFlowMap);
    }
    
    /**
     * 扫描方法体中的反射调用
     * 
     * @param method 方法
     * @param units 方法体的 units（已预处理）
     * @return 反射调用点列表
     */
    public List<ReflectionCallSite> scanReflectionCalls(SootMethod method, List<Unit> units) {
        List<ReflectionCallSite> callSites = new ArrayList<>();
        
        if (units == null || units.isEmpty()) {
            return callSites;
        }
        
        for (Unit unit : units) {
            if (!(unit instanceof Stmt)) {
                continue;
            }
            
            Stmt stmt = (Stmt) unit;
            if (!stmt.containsInvokeExpr()) {
                continue;
            }
            
            InvokeExpr invokeExpr = stmt.getInvokeExpr();
            SootMethod calledMethod = invokeExpr.getMethod();
            
            // 识别反射调用
            ReflectionCallSite.ReflectionType reflectionType = identifyReflectionCall(calledMethod);
            
            if (reflectionType != null) {
                ReflectionCallSite callSite = new ReflectionCallSite(
                    method, unit, invokeExpr, reflectionType
                );
                callSites.add(callSite);
                
                logger.info("🔮 发现反射调用: " + reflectionType + " in " + method.getName());
            }
        }
        
        return callSites;
    }
    
    /**
     * 识别是否为反射调用
     */
    private ReflectionCallSite.ReflectionType identifyReflectionCall(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        
        // Constructor.newInstance()
        if (className.equals("java.lang.reflect.Constructor") && 
            methodName.equals("newInstance")) {
            return ReflectionCallSite.ReflectionType.CONSTRUCTOR_NEW_INSTANCE;
        }
        
        // Method.invoke()
        if (className.equals("java.lang.reflect.Method") && 
            methodName.equals("invoke")) {
            return ReflectionCallSite.ReflectionType.METHOD_INVOKE;
        }
        
        // Class.newInstance() (已废弃但仍常用)
        if (className.equals("java.lang.Class") && 
            methodName.equals("newInstance")) {
            return ReflectionCallSite.ReflectionType.CLASS_NEW_INSTANCE;
        }
        
        return null;
    }
    
    /**
     * 解析反射调用并建立桥接边
     * 
     * @param callGraph 调用图
     * @param caller 调用者方法
     * @param callSite 反射调用点
     * @param methodWorkList 工作列表
     * @param processedMethods 已处理方法集合
     * @param shouldAnalyze 判断是否应该分析方法的函数
     * @return 建立的桥接边数量
     */
    public int resolveAndAddBridgeEdges(CallGraph callGraph, SootMethod caller, 
                                        ReflectionCallSite callSite,
                                        java.util.Queue<SootMethod> methodWorkList,
                                        java.util.Set<SootMethod> processedMethods,
                                        java.util.function.Predicate<SootMethod> shouldAnalyze) {
        int edgeCount = 0;
        
        List<ReflectionTargetInfo> targets = null;
        
        switch (callSite.getType()) {
            case CONSTRUCTOR_NEW_INSTANCE:
                targets = constructorAnalyzer.analyze(callSite);
                break;
                
            case METHOD_INVOKE:
                targets = methodAnalyzer.analyze(callSite);
                break;
                
            case CLASS_NEW_INSTANCE:
                // TODO: 实现 Class.newInstance() 分析
                logger.fine("⚠️ Class.newInstance() 暂未完整实现");
                targets = new ArrayList<>();
                break;
        }
        
        if (targets == null || targets.isEmpty()) {
            logger.info("⚠️ 未能推断反射目标: " + callSite);
            return 0;
        }
        
        logger.info("✅ 推断出 " + targets.size() + " 个反射目标");
        
        // 为每个目标建立桥接边
        for (ReflectionTargetInfo target : targets) {
            try {
                SootMethod targetMethod = target.getTargetMethod();
                
                callGraph.addCall(
                    caller, 
                    targetMethod, 
                    callSite.getCallSite(), 
                    CallGraph.CallType.REFLECTION
                );
                edgeCount++;
                reflectionBridgeEdgeCount++;
                
                String strategyMark = target.isPrecise() ? "🎯" : "🔍";
                logger.info(strategyMark + " 反射桥接: " + 
                           callSite.getType() + " → " + 
                           targetMethod.getSignature());
                
                // 🔧 关键修复：将反射目标添加到工作列表
                if (!processedMethods.contains(targetMethod) && shouldAnalyze.test(targetMethod)) {
                    methodWorkList.offer(targetMethod);
                    logger.info("  ✅ 将反射目标添加到工作列表: " + targetMethod.getName());
                }
                
            } catch (Exception e) {
                logger.fine("建立反射桥接边失败: " + target + " - " + e.getMessage());
            }
        }
        
        return edgeCount;
    }
    
    /**
     * 批量处理一个方法中的所有反射调用
     * 
     * @param callGraph 调用图
     * @param method 方法
     * @param units 方法体的 units（已预处理）
     * @param methodWorkList 工作列表（用于添加反射目标）
     * @param processedMethods 已处理方法集合
     * @param shouldAnalyze 判断是否应该分析方法的函数
     * @return 建立的桥接边数量
     */
    public int processMethod(CallGraph callGraph, SootMethod method, List<Unit> units,
                            java.util.Queue<SootMethod> methodWorkList,
                            java.util.Set<SootMethod> processedMethods,
                            java.util.function.Predicate<SootMethod> shouldAnalyze) {
        List<ReflectionCallSite> callSites = scanReflectionCalls(method, units);
        
        if (callSites.isEmpty()) {
            return 0;
        }
        
        int totalEdges = 0;
        
        for (ReflectionCallSite callSite : callSites) {
            int edges = resolveAndAddBridgeEdges(callGraph, method, callSite, 
                                                methodWorkList, processedMethods, shouldAnalyze);
            totalEdges += edges;
        }
        
        return totalEdges;
    }
    
    /**
     * 获取统计信息
     */
    public int getReflectionBridgeEdgeCount() {
        return reflectionBridgeEdgeCount;
    }
    
    /**
     * 重置统计信息
     */
    public void reset() {
        reflectionBridgeEdgeCount = 0;
        reflectionFlowMap.clear();
    }
}

