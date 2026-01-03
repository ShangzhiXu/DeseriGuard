package com.squirtle.core.callgraph;

import soot.SootMethod;
import soot.Unit;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 自定义调用图实现
 * 
 * 设计特点：
 * 1. 完全独立于Soot的CallGraph实现
 * 2. 支持多种调用类型的精确建模
 * 3. 提供高效的查询和遍历接口
 * 4. 支持增量构建和动态更新
 * 
 * @author BugTurtle
 * @version 1.0
 */
public class CallGraph {
    
    /**
     * 调用类型枚举
     */
    public enum CallType {
        STATIC,      // 静态调用
        VIRTUAL,     // 虚拟调用
        INTERFACE,   // 接口调用
        SPECIAL,     // 特殊调用（构造函数、super调用等）
        DYNAMIC,     // 动态调用（反射等）
        BRIDGE,      // 🎯 桥接调用（泛型擦除产生的桥接方法调用）
        PROXY,       // 🎭 代理调用（接口调用 → InvocationHandler.invoke()）
        REFLECTION   // 🔮 反射调用（Constructor.newInstance() / Method.invoke()）
    }
    
    /**
     * 调用边表示
     */
    public static class CallEdge {
        private final SootMethod caller;
        private final SootMethod callee;
        private final Unit callSite;
        private final CallType callType;
        private final long id;
        
        // 🆕 可控性信息（Flash策略核心）
        private final boolean thisControllable;  // this对象是否可控
        private final Map<Integer, Boolean> paramControllable;  // 参数是否可控
        
        private static long nextId = 0;
        
        // 原有构造函数（兼容旧代码）
        public CallEdge(SootMethod caller, SootMethod callee, Unit callSite, CallType callType) {
            this(caller, callee, callSite, callType, false, Collections.emptyMap());
        }
        
        // 🆕 新构造函数（带可控性信息）
        public CallEdge(SootMethod caller, SootMethod callee, Unit callSite, CallType callType,
                       boolean thisControllable, Map<Integer, Boolean> paramControllable) {
            this.caller = caller;
            this.callee = callee;
            this.callSite = callSite;
            this.callType = callType;
            this.thisControllable = thisControllable;
            this.paramControllable = paramControllable != null ? 
                Collections.unmodifiableMap(new HashMap<>(paramControllable)) : 
                Collections.emptyMap();
            this.id = nextId++;
        }
        
        // Getters
        public SootMethod getCaller() { return caller; }
        public SootMethod getCallee() { return callee; }
        public Unit getCallSite() { return callSite; }
        public CallType getCallType() { return callType; }
        public long getId() { return id; }
        
        // 🆕 可控性查询方法
        public boolean isThisControllable() { return thisControllable; }
        public Map<Integer, Boolean> getParamControllable() { return paramControllable; }
        
        /**
         * 检查是否有任何参数可控
         */
        public boolean hasAnyParamControllable() {
            return paramControllable.values().stream().anyMatch(b -> b);
        }
        
        /**
         * 检查边是否可控（this或任意参数可控）
         */
        public boolean isControllable() {
            return thisControllable || hasAnyParamControllable();
        }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof CallEdge)) return false;
            CallEdge other = (CallEdge) obj;
            return Objects.equals(caller, other.caller) &&
                   Objects.equals(callee, other.callee) &&
                   Objects.equals(callSite, other.callSite);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(caller, callee, callSite);
        }
        
        @Override
        public String toString() {
            return String.format("CallEdge{%s -> %s, type=%s, site=%s}", 
                               caller.getSignature(), callee.getSignature(), callType, callSite);
        }
    }
    
    // 核心数据结构
    private final Set<CallEdge> allEdges;
    private final Map<SootMethod, Set<CallEdge>> outgoingEdges;  // 方法 -> 其调用的方法
    private final Map<SootMethod, Set<CallEdge>> incomingEdges;  // 方法 -> 调用它的方法
    private final Map<Unit, Set<CallEdge>> callSiteEdges;       // 调用点 -> 调用边
    private final Map<CallType, Set<CallEdge>> edgesByType;     // 调用类型 -> 调用边
    private final Map<String, CallEdge> edgeCache;              // 快速查找：key = caller+callee+callSite
    
    public CallGraph() {
        this.allEdges = ConcurrentHashMap.newKeySet();
        this.outgoingEdges = new ConcurrentHashMap<>();
        this.incomingEdges = new ConcurrentHashMap<>();
        this.callSiteEdges = new ConcurrentHashMap<>();
        this.edgesByType = new ConcurrentHashMap<>();
        this.edgeCache = new ConcurrentHashMap<>();
        
        // 初始化调用类型映射
        for (CallType type : CallType.values()) {
            edgesByType.put(type, ConcurrentHashMap.newKeySet());
        }
    }
    
    /**
     * 生成边的唯一标识（用于快速查找）
     */
    private String getEdgeKey(SootMethod caller, SootMethod callee, Unit callSite) {
        return caller.getSignature() + "|" + callee.getSignature() + "|" + 
               (callSite != null ? callSite.toString() : "null");
    }
    
    /**
     * 添加调用边（不带可控性信息）
     */
    public boolean addCall(SootMethod caller, SootMethod callee, Unit callSite, CallType callType) {
        return addCall(caller, callee, callSite, callType, false, Collections.emptyMap());
    }
    
    /**
     * 🆕 添加调用边（带可控性信息）- Flash策略核心
     * 
     * @param thisControllable callee的this对象是否可控
     * @param paramControllable callee的参数是否可控（参数索引 -> 是否可控）
     */
    public boolean addCall(SootMethod caller, SootMethod callee, Unit callSite, CallType callType,
                          boolean thisControllable, Map<Integer, Boolean> paramControllable) {
        
        String edgeKey = getEdgeKey(caller, callee, callSite);
        CallEdge existingEdge = edgeCache.get(edgeKey);
        
        if (existingEdge != null) {
            // 边已存在，合并可控性（取 OR）
            boolean mergedThis = existingEdge.thisControllable || thisControllable;
            Map<Integer, Boolean> mergedParams = new HashMap<>(existingEdge.paramControllable);
            for (Map.Entry<Integer, Boolean> entry : paramControllable.entrySet()) {
                mergedParams.merge(entry.getKey(), entry.getValue(), (old, val) -> old || val);
            }
            
            // 只在可控性提升时才更新
            if (mergedThis != existingEdge.thisControllable || !mergedParams.equals(existingEdge.paramControllable)) {
                // 移除旧边
                allEdges.remove(existingEdge);
                outgoingEdges.get(caller).remove(existingEdge);
                incomingEdges.get(callee).remove(existingEdge);
                if (callSite != null) {
                    Set<CallEdge> siteEdges = callSiteEdges.get(callSite);
                    if (siteEdges != null) {
                        siteEdges.remove(existingEdge);
                    }
                }
                edgesByType.get(callType).remove(existingEdge);
                
                // 添加新边
                CallEdge mergedEdge = new CallEdge(caller, callee, callSite, callType, mergedThis, mergedParams);
                allEdges.add(mergedEdge);
                outgoingEdges.computeIfAbsent(caller, k -> ConcurrentHashMap.newKeySet()).add(mergedEdge);
                incomingEdges.computeIfAbsent(callee, k -> ConcurrentHashMap.newKeySet()).add(mergedEdge);
                if (callSite != null) {
                    callSiteEdges.computeIfAbsent(callSite, k -> ConcurrentHashMap.newKeySet()).add(mergedEdge);
                }
                edgesByType.get(callType).add(mergedEdge);
                edgeCache.put(edgeKey, mergedEdge);  // 更新缓存
            }
            return false;  // 边已存在（合并后）
        }
        
        // 边不存在，直接添加
        CallEdge newEdge = new CallEdge(caller, callee, callSite, callType, thisControllable, paramControllable);
        allEdges.add(newEdge);
        outgoingEdges.computeIfAbsent(caller, k -> ConcurrentHashMap.newKeySet()).add(newEdge);
        incomingEdges.computeIfAbsent(callee, k -> ConcurrentHashMap.newKeySet()).add(newEdge);
        if (callSite != null) {
            callSiteEdges.computeIfAbsent(callSite, k -> ConcurrentHashMap.newKeySet()).add(newEdge);
        }
        edgesByType.get(callType).add(newEdge);
        edgeCache.put(edgeKey, newEdge);  // 加入缓存
        
        return true;
    }
    
    /**
     * 删除调用边
     */
    public boolean removeEdge(CallEdge edge) {
        if (allEdges.remove(edge)) {
            // 从各种映射中删除
            Set<CallEdge> out = outgoingEdges.get(edge.getCaller());
            if (out != null) {
                out.remove(edge);
            }
            
            Set<CallEdge> in = incomingEdges.get(edge.getCallee());
            if (in != null) {
                in.remove(edge);
            }
            
            // 🔥 修复：callSite 可能为 null（手动添加的边）
            if (edge.getCallSite() != null) {
                Set<CallEdge> site = callSiteEdges.get(edge.getCallSite());
                if (site != null) {
                    site.remove(edge);
                }
            }
            
            Set<CallEdge> typeEdges = edgesByType.get(edge.getCallType());
            if (typeEdges != null) {
                typeEdges.remove(edge);
            }
            
            // 从缓存中删除
            String edgeKey = getEdgeKey(edge.getCaller(), edge.getCallee(), edge.getCallSite());
            edgeCache.remove(edgeKey);
            
            return true;
        }
        
        return false;
    }
    
    /**
     * 获取方法的所有出边（该方法调用的其他方法）
     */
    public Set<CallEdge> getOutgoingEdges(SootMethod method) {
        return outgoingEdges.getOrDefault(method, Collections.emptySet());
    }
    
    /**
     * 获取方法的所有入边（调用该方法的其他方法）
     */
    public Set<CallEdge> getIncomingEdges(SootMethod method) {
        return incomingEdges.getOrDefault(method, Collections.emptySet());
    }
    
    /**
     * 获取调用点的所有调用边
     */
    public Set<CallEdge> getCallSiteEdges(Unit callSite) {
        return callSiteEdges.getOrDefault(callSite, Collections.emptySet());
    }
    
    /**
     * 获取特定类型的所有调用边
     */
    public Set<CallEdge> getEdgesByType(CallType callType) {
        return edgesByType.getOrDefault(callType, Collections.emptySet());
    }
    
    /**
     * 获取方法直接调用的所有方法
     */
    public Set<SootMethod> getDirectCallees(SootMethod caller) {
        Set<SootMethod> callees = new HashSet<>();
        for (CallEdge edge : getOutgoingEdges(caller)) {
            callees.add(edge.getCallee());
        }
        return callees;
    }
    
    /**
     * 获取直接调用该方法的所有方法
     */
    public Set<SootMethod> getDirectCallers(SootMethod callee) {
        Set<SootMethod> callers = new HashSet<>();
        for (CallEdge edge : getIncomingEdges(callee)) {
            callers.add(edge.getCaller());
        }
        return callers;
    }
    
    /**
     * 获取可达的所有方法（从给定方法开始的传递闭包）
     */
    public Set<SootMethod> getReachableMethods(SootMethod startMethod) {
        Set<SootMethod> reachable = new HashSet<>();
        Queue<SootMethod> worklist = new LinkedList<>();
        
        worklist.offer(startMethod);
        reachable.add(startMethod);
        
        while (!worklist.isEmpty()) {
            SootMethod current = worklist.poll();
            
            for (SootMethod callee : getDirectCallees(current)) {
                if (reachable.add(callee)) {
                    worklist.offer(callee);
                }
            }
        }
        
        return reachable;
    }
    
    /**
     * 获取可以到达指定方法的所有方法（反向传递闭包）
     */
    public Set<SootMethod> getMethodsReaching(SootMethod targetMethod) {
        Set<SootMethod> reaching = new HashSet<>();
        Queue<SootMethod> worklist = new LinkedList<>();
        
        worklist.offer(targetMethod);
        reaching.add(targetMethod);
        
        while (!worklist.isEmpty()) {
            SootMethod current = worklist.poll();
            
            for (SootMethod caller : getDirectCallers(current)) {
                if (reaching.add(caller)) {
                    worklist.offer(caller);
                }
            }
        }
        
        return reaching;
    }
    
    /**
     * 查找两个方法之间的调用路径
     */
    public List<CallPath> findCallPaths(SootMethod from, SootMethod to, int maxDepth) {
        List<CallPath> paths = new ArrayList<>();
        
        findCallPathsRecursive(from, to, new ArrayList<>(), new HashSet<>(), paths, maxDepth);
        
        return paths;
    }
    
    private void findCallPathsRecursive(SootMethod current, SootMethod target, 
                                      List<CallEdge> currentPath, Set<SootMethod> visited,
                                      List<CallPath> allPaths, int remainingDepth) {
        if (remainingDepth <= 0) return;
        
        if (current.equals(target)) {
            allPaths.add(new CallPath(new ArrayList<>(currentPath)));
            return;
        }
        
        if (visited.contains(current)) return;
        visited.add(current);
        
        for (CallEdge edge : getOutgoingEdges(current)) {
            currentPath.add(edge);
            findCallPathsRecursive(edge.getCallee(), target, currentPath, visited, allPaths, remainingDepth - 1);
            currentPath.remove(currentPath.size() - 1);
        }
        
        visited.remove(current);
    }
    
    /**
     * 调用路径表示
     */
    public static class CallPath {
        private final List<CallEdge> edges;
        
        public CallPath(List<CallEdge> edges) {
            this.edges = new ArrayList<>(edges);
        }
        
        public List<CallEdge> getEdges() { return Collections.unmodifiableList(edges); }
        public int getLength() { return edges.size(); }
        public boolean isEmpty() { return edges.isEmpty(); }
        
        public SootMethod getStartMethod() {
            return edges.isEmpty() ? null : edges.get(0).getCaller();
        }
        
        public SootMethod getEndMethod() {
            return edges.isEmpty() ? null : edges.get(edges.size() - 1).getCallee();
        }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("CallPath[");
            for (int i = 0; i < edges.size(); i++) {
                if (i > 0) sb.append(" -> ");
                sb.append(edges.get(i).getCallee().getName());
            }
            sb.append("]");
            return sb.toString();
        }
    }
    
    /**
     * 获取调用图统计信息
     */
    public CallGraphStats getStats() {
        Map<CallType, Integer> edgeCountByType = new EnumMap<>(CallType.class);
        for (CallType type : CallType.values()) {
            Set<CallEdge> edges = edgesByType.get(type);
            edgeCountByType.put(type, edges != null ? edges.size() : 0);
        }
        
        return new CallGraphStats(getAllMethods().size(), allEdges.size(), edgeCountByType);
    }
    
    /**
     * 调用图统计信息
     */
    public static class CallGraphStats {
        private final int methodCount;
        private final int edgeCount;
        private final Map<CallType, Integer> edgeCountByType;
        
        public CallGraphStats(int methodCount, int edgeCount, Map<CallType, Integer> edgeCountByType) {
            this.methodCount = methodCount;
            this.edgeCount = edgeCount;
            this.edgeCountByType = new HashMap<>(edgeCountByType);
        }
        
        public int getMethodCount() { return methodCount; }
        public int getEdgeCount() { return edgeCount; }
        public Map<CallType, Integer> getEdgeCountByType() { return Collections.unmodifiableMap(edgeCountByType); }
        
        @Override
        public String toString() {
            return String.format("CallGraphStats{methods=%d, edges=%d, types=%s}", 
                               methodCount, edgeCount, edgeCountByType);
        }
    }
    
    // 基本查询方法
    public int getEdgeCount() { return allEdges.size(); }
    public Set<CallEdge> getAllEdges() { return Collections.unmodifiableSet(allEdges); }
    public Set<SootMethod> getAllMethods() {
        Set<SootMethod> methods = new HashSet<>();
        for (CallEdge edge : allEdges) {
            methods.add(edge.getCaller());
            methods.add(edge.getCallee());
        }
        return methods;
    }
    
    /**
     * 检查两个方法之间是否存在直接调用关系
     */
    public boolean hasDirectCall(SootMethod caller, SootMethod callee) {
        return getOutgoingEdges(caller).stream()
                .anyMatch(edge -> edge.getCallee().equals(callee));
    }
    
    /**
     * 检查两个方法之间是否存在可达关系
     */
    public boolean isReachable(SootMethod from, SootMethod to) {
        return getReachableMethods(from).contains(to);
    }
    
    /**
     * 删除方法及其所有相关的调用边
     * 
     * @param method 要删除的方法
     * @return 删除的边数
     */
    public int removeMethod(SootMethod method) {
        int removedEdges = 0;
        
        // 收集所有需要删除的边（避免在遍历时修改）
        Set<CallEdge> toRemove = new HashSet<>();
        
        // 收集所有出边
        Set<CallEdge> outEdges = outgoingEdges.get(method);
        if (outEdges != null) {
            toRemove.addAll(outEdges);
        }
        
        // 收集所有入边
        Set<CallEdge> inEdges = incomingEdges.get(method);
        if (inEdges != null) {
            toRemove.addAll(inEdges);
        }
        
        // 删除所有边
        for (CallEdge edge : toRemove) {
            if (removeEdge(edge)) {
                removedEdges++;
            }
        }
        
        // 清理映射表
        outgoingEdges.remove(method);
        incomingEdges.remove(method);
        
        return removedEdges;
    }
} 