package com.squirtle.core.dataflow;

import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 自定义数据流分析引擎
 * 
 * 功能：
 * 1. 方法内变量的定义-使用链分析
 * 2. 数据依赖关系构建
 * 3. 为污点分析提供基础数据流信息
 * 
 * @author BugTurtle
 * @version 1.0
 */
public class DataFlowAnalysis {
    
    /**
     * 数据流事实：变量定义
     */
    public static class Definition {
        private final Local variable;
        private final Unit defSite;
        private final SootMethod method;
        private final Value defValue;
        public Definition(Local variable, Unit defSite, SootMethod method, Value defValue) {
            this.variable = variable;
            this.defSite = defSite;
            this.method = method;
            this.defValue = defValue;
        }
        
        public Local getVariable() { return variable; }
        public Unit getDefSite() { return defSite; }
        public SootMethod getMethod() { return method; }
        public Value getDefValue() { return defValue; }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof Definition)) return false;
            Definition other = (Definition) obj;
            return Objects.equals(variable, other.variable) &&
                   Objects.equals(defSite, other.defSite) &&
                   Objects.equals(method, other.method);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(variable, defSite, method);
        }
        
        @Override
        public String toString() {
            return String.format("Def{%s at %s}", variable.getName(), defSite);
        }
    }
    
    /**
     * 数据流事实：变量使用
     */
    public static class Use {
        private final Local variable;
        private final Unit useSite;
        private final SootMethod method;
        
        public Use(Local variable, Unit useSite, SootMethod method) {
            this.variable = variable;
            this.useSite = useSite;
            this.method = method;
        }
        
        public Local getVariable() { return variable; }
        public Unit getUseSite() { return useSite; }
        public SootMethod getMethod() { return method; }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof Use)) return false;
            Use other = (Use) obj;
            return Objects.equals(variable, other.variable) &&
                   Objects.equals(useSite, other.useSite) &&
                   Objects.equals(method, other.method);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(variable, useSite, method);
        }
        
        @Override
        public String toString() {
            return String.format("Use{%s at %s}", variable.getName(), useSite);
        }
    }
    
    /**
     * 定义-使用链
     */
    public static class DefUseChain {
        private final Definition definition;
        private final Use use;
        
        public DefUseChain(Definition definition, Use use) {
            this.definition = definition;
            this.use = use;
        }
        
        public Definition getDefinition() { return definition; }
        public Use getUse() { return use; }
        
        @Override
        public String toString() {
            return String.format("DefUseChain{%s -> %s}", definition, use);
        }
    }
    
    // 分析结果存储
    private final Map<SootMethod, Set<Definition>> methodDefinitions;
    private final Map<SootMethod, Set<Use>> methodUses;
    private final Map<SootMethod, Set<DefUseChain>> methodDefUseChains;
    private final Map<Local, Set<Definition>> definitionsByVariable;
    private final Map<Local, Set<Use>> usesByVariable;
    
    public DataFlowAnalysis() {
        this.methodDefinitions = new ConcurrentHashMap<>();
        this.methodUses = new ConcurrentHashMap<>();
        this.methodDefUseChains = new ConcurrentHashMap<>();
        this.definitionsByVariable = new ConcurrentHashMap<>();
        this.usesByVariable = new ConcurrentHashMap<>();
    }
    
    /**
     * 分析单个方法的数据流
     */
    public void analyzeMethod(SootMethod method, Body body, List<Unit> units) {
        if (body == null || units == null) return;
        
        // 收集定义和使用
        Set<Definition> definitions = new HashSet<>();
        Set<Use> uses = new HashSet<>();
        
        for (Unit unit : units) {
            // 分析定义
            analyzeDefinitions(method, unit, definitions);
            
            // 分析使用
            analyzeUses(method, unit, uses);
        }
        
        // 构建定义-使用链
        Set<DefUseChain> defUseChains = buildDefUseChains(method, body, definitions, uses);
        
        // 存储结果
        methodDefinitions.put(method, definitions);
        methodUses.put(method, uses);
        methodDefUseChains.put(method, defUseChains);
        
        // 更新全局映射
        updateGlobalMappings(definitions, uses);
    }
    
    /**
     * 分析语句中的变量定义
     */
    private void analyzeDefinitions(SootMethod method, Unit unit, Set<Definition> definitions) {
        if (unit instanceof AssignStmt) {
            AssignStmt assignStmt = (AssignStmt) unit;
            Value leftOp = assignStmt.getLeftOp();
            Value rightOp = assignStmt.getRightOp();
            
            // 左值是局部变量的定义
            if (leftOp instanceof Local) {
                Local var = (Local) leftOp;
                Definition def = new Definition(var, unit, method, rightOp);
                definitions.add(def);
            }
        } else if (unit instanceof IdentityStmt) {
            // 参数和this的定义
            IdentityStmt identityStmt = (IdentityStmt) unit;
            Value leftOp = identityStmt.getLeftOp();
            Value rightOp = identityStmt.getRightOp();
            
            if (leftOp instanceof Local) {
                Local var = (Local) leftOp;
                Definition def = new Definition(var, unit, method, rightOp);
                definitions.add(def);
            }
        }
    }
    
    /**
     * 分析语句中的变量使用
     */
    private void analyzeUses(SootMethod method, Unit unit, Set<Use> uses) {
        // 获取所有使用的值
        for (ValueBox valueBox : unit.getUseBoxes()) {
            Value value = valueBox.getValue();
            if (value instanceof Local) {
                Local var = (Local) value;
                Use use = new Use(var, unit, method);
                uses.add(use);
            }
        }
    }
    
    /**
     * 构建定义-使用链
     */
    private Set<DefUseChain> buildDefUseChains(SootMethod method, Body body, 
                                              Set<Definition> definitions, Set<Use> uses) {
        Set<DefUseChain> defUseChains = new HashSet<>();
        
        // 为每个使用找到可能的定义
        for (Use use : uses) {
            Set<Definition> reachingDefs = findReachingDefinitions(use, definitions, body);
            
            for (Definition def : reachingDefs) {
                if (def.getVariable().equals(use.getVariable())) {
                    defUseChains.add(new DefUseChain(def, use));
                }
            }
        }
        
        return defUseChains;
    }
    
    /**
     * 查找到达特定使用点的定义
     * 简化版本：在同一方法内查找
     */
    private Set<Definition> findReachingDefinitions(Use use, Set<Definition> allDefinitions, Body body) {
        Set<Definition> reachingDefs = new HashSet<>();
        
        // 构建控制流图
        UnitGraph cfg = new BriefUnitGraph(body);
        
        // 简单的向后数据流分析
        Set<Unit> visited = new HashSet<>();
        Queue<Unit> worklist = new LinkedList<>();
        
        // 从使用点开始向前搜索
        worklist.offer(use.getUseSite());
        
        while (!worklist.isEmpty()) {
            Unit current = worklist.poll();
            if (visited.contains(current)) continue;
            visited.add(current);
            
            // 检查当前单元是否定义了该变量
            boolean foundDefinition = false;
            for (Definition def : allDefinitions) {
                if (def.getDefSite().equals(current) && 
                    def.getVariable().equals(use.getVariable())) {
                    reachingDefs.add(def);
                    // 找到定义，不需要继续向前搜索这条路径
                    foundDefinition = true;
                }
            }
            // 如果找到定义，就不继续向前搜索这条路径
            if (foundDefinition) {
                continue;  // 不添加前驱节点
            }
            // 添加前驱节点到工作列表
            for (Unit pred : cfg.getPredsOf(current)) {
                if (!visited.contains(pred)) {
                    worklist.offer(pred);
                }
            }
        }
        
        return reachingDefs;
    }
    
    /**
     * 更新全局变量映射
     */
    private void updateGlobalMappings(Set<Definition> definitions, Set<Use> uses) {
        for (Definition def : definitions) {
            definitionsByVariable.computeIfAbsent(def.getVariable(), k -> ConcurrentHashMap.newKeySet()).add(def);
        }
        
        for (Use use : uses) {
            usesByVariable.computeIfAbsent(use.getVariable(), k -> ConcurrentHashMap.newKeySet()).add(use);
        }
    }
    
    // 查询接口
    
    /**
     * 获取方法的所有定义
     */
    public Set<Definition> getMethodDefinitions(SootMethod method) {
        return methodDefinitions.getOrDefault(method, Collections.emptySet());
    }
    
    /**
     * 获取方法的所有使用
     */
    public Set<Use> getMethodUses(SootMethod method) {
        return methodUses.getOrDefault(method, Collections.emptySet());
    }
    
    /**
     * 获取方法的定义-使用链
     */
    public Set<DefUseChain> getMethodDefUseChains(SootMethod method) {
        return methodDefUseChains.getOrDefault(method, Collections.emptySet());
    }
    
    /**
     * 获取变量的所有定义
     */
    public Set<Definition> getVariableDefinitions(Local variable) {
        return definitionsByVariable.getOrDefault(variable, Collections.emptySet());
    }
    
    /**
     * 获取变量的所有使用
     */
    public Set<Use> getVariableUses(Local variable) {
        return usesByVariable.getOrDefault(variable, Collections.emptySet());
    }
    
    /**
     * 获取分析结果
     */
    public DataFlowResult getResult() {
        return new DataFlowResult(
            new HashMap<>(methodDefinitions),
            new HashMap<>(methodUses),
            new HashMap<>(methodDefUseChains)
        );
    }
    
    /**
     * 数据流分析结果
     */
    public static class DataFlowResult {
        private final Map<SootMethod, Set<Definition>> methodDefinitions;
        private final Map<SootMethod, Set<Use>> methodUses;
        private final Map<SootMethod, Set<DefUseChain>> methodDefUseChains;
        
        public DataFlowResult(Map<SootMethod, Set<Definition>> methodDefinitions,
                             Map<SootMethod, Set<Use>> methodUses,
                             Map<SootMethod, Set<DefUseChain>> methodDefUseChains) {
            this.methodDefinitions = methodDefinitions;
            this.methodUses = methodUses;
            this.methodDefUseChains = methodDefUseChains;
        }
        
        public Map<SootMethod, Set<Definition>> getMethodDefinitions() { return methodDefinitions; }
        public Map<SootMethod, Set<Use>> getMethodUses() { return methodUses; }
        public Map<SootMethod, Set<DefUseChain>> getMethodDefUseChains() { return methodDefUseChains; }
        
        public DataFlowStatistics getStatistics() {
            int totalDefs = methodDefinitions.values().stream().mapToInt(Set::size).sum();
            int totalUses = methodUses.values().stream().mapToInt(Set::size).sum();
            int totalChains = methodDefUseChains.values().stream().mapToInt(Set::size).sum();
            
            return new DataFlowStatistics(
                methodDefinitions.size(),
                totalDefs,
                totalUses,
                totalChains
            );
        }
    }
    
    /**
     * 数据流统计信息
     */
    public static class DataFlowStatistics {
        private final int methodCount;
        private final int totalDefinitions;
        private final int totalUses;
        private final int totalDefUseChains;
        
        public DataFlowStatistics(int methodCount, int totalDefinitions, int totalUses, int totalDefUseChains) {
            this.methodCount = methodCount;
            this.totalDefinitions = totalDefinitions;
            this.totalUses = totalUses;
            this.totalDefUseChains = totalDefUseChains;
        }
        
        public int getMethodCount() { return methodCount; }
        public int getTotalDefinitions() { return totalDefinitions; }
        public int getTotalUses() { return totalUses; }
        public int getTotalDefUseChains() { return totalDefUseChains; }
        
        @Override
        public String toString() {
            return String.format("DataFlowStats{methods=%d, defs=%d, uses=%d, chains=%d}", 
                               methodCount, totalDefinitions, totalUses, totalDefUseChains);
        }
    }
} 