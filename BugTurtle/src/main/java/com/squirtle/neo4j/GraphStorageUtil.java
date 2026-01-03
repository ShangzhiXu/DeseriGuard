package com.squirtle.neo4j;

import com.squirtle.config.Neo4jConfig;
import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.fields.FieldAccessGraph;
import com.squirtle.core.fields.ControllableFieldGraph;
import com.squirtle.core.ir.IRAnalyzer;
import org.neo4j.driver.*;
import org.neo4j.driver.Config;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;

import java.util.*;
import java.util.logging.Logger;

/**
 * 图数据库存储工具类
 * 负责将程序分析结果存储到Neo4j图数据库中
 * 
 * 图模式设计：
 * 节点类型：
 * - Class: 类节点
 * - Method: 方法节点  
 * - Field: 字段节点
 * 
 * 关系类型：
 * - CALLS: 方法调用关系
 * - DIRECT_USE: 字段直接使用关系
 * - PARAMETER_USE: 字段参数传递关系
 * - CONDITION_USE: 字段条件控制关系
 * - INDIRECT_USE: 字段间接影响关系
 * 
 * @author BugTurtle
 * @version 1.0
 */
public class GraphStorageUtil {
    
    private static final Logger logger = Logger.getLogger(GraphStorageUtil.class.getName());
    private final Driver driver;
    
    public GraphStorageUtil() {
        // 配置更长的超时时间
        Config config = Config.builder()
            .withConnectionTimeout(60, java.util.concurrent.TimeUnit.SECONDS)
            .withMaxTransactionRetryTime(60, java.util.concurrent.TimeUnit.SECONDS)
            .build();
            
        this.driver = GraphDatabase.driver(
            Neo4jConfig.getUri(),
            AuthTokens.basic(Neo4jConfig.getUser(), Neo4jConfig.getPassword()),
            config
        );
    }
    
    /**
     * 清空图数据库
     */
    public void clearDatabase() {
        try (Session session = driver.session()) {
            session.writeTransaction(tx -> {
                tx.run("MATCH (n) DETACH DELETE n");
                return null;
            });
            logger.info("数据库已清空");
        }
    }
    
    /**
     * 创建类节点
     */
    public void createClassNode(SootClass sootClass) {
        try (Session session = driver.session()) {
            String query = "CREATE (c:Class {" +
                "name: $name, " +
                "packageName: $packageName, " +
                "isInterface: $isInterface, " +
                "isAbstract: $isAbstract, " +
                "isPublic: $isPublic" +
                "})";
            
            session.writeTransaction(tx -> {
                tx.run(query, Values.parameters(
                    "name", sootClass.getName(),
                    "packageName", sootClass.getPackageName(),
                    "isInterface", sootClass.isInterface(),
                    "isAbstract", sootClass.isAbstract(),
                    "isPublic", sootClass.isPublic()
                ));
                return null;
            });
        }
    }
    
    /**
     * 创建方法节点
     */
    public void createMethodNode(SootMethod method) {
        try (Session session = driver.session()) {
            String query = "CREATE (m:Method {" +
                "signature: $signature, " +
                "name: $name, " +
                "className: $className, " +
                "returnType: $returnType, " +
                "parameterCount: $parameterCount, " +
                "isStatic: $isStatic, " +
                "isPublic: $isPublic, " +
                "isAbstract: $isAbstract, " +
                "hasActiveBody: $hasActiveBody" +
                "})";
            
            session.writeTransaction(tx -> {
                tx.run(query, Values.parameters(
                    "signature", method.getSignature(),
                    "name", method.getName(),
                    "className", method.getDeclaringClass().getName(),
                    "returnType", method.getReturnType().toString(),
                    "parameterCount", method.getParameterCount(),
                    "isStatic", method.isStatic(),
                    "isPublic", method.isPublic(),
                    "isAbstract", method.isAbstract(),
                    "hasActiveBody", method.hasActiveBody()
                ));
                return null;
            });
        }
    }
    
    /**
     * 创建字段节点
     */
    public void createFieldNode(SootField field) {
        try (Session session = driver.session()) {
            String query = "CREATE (f:Field {" +
                "signature: $signature, " +
                "name: $name, " +
                "className: $className, " +
                "type: $type, " +
                "isStatic: $isStatic, " +
                "isPublic: $isPublic, " +
                "isFinal: $isFinal" +
                "})";
            
            session.writeTransaction(tx -> {
                tx.run(query, Values.parameters(
                    "signature", field.getSignature(),
                    "name", field.getName(),
                    "className", field.getDeclaringClass().getName(),
                    "type", field.getType().toString(),
                    "isStatic", field.isStatic(),
                    "isPublic", field.isPublic(),
                    "isFinal", field.isFinal()
                ));
                return null;
            });
        }
    }
    
    
    
    /**
     * 创建方法调用关系
     */
    public void createMethodCallRelation(SootMethod caller, SootMethod callee) {
        try (Session session = driver.session()) {
            String query = "MATCH (caller:Method {signature: $callerSignature}), " +
                "(callee:Method {signature: $calleeSignature}) " +
                "CREATE (caller)-[:CALLS]->(callee)";
            
            session.writeTransaction(tx -> {
                tx.run(query, Values.parameters(
                    "callerSignature", caller.getSignature(),
                    "calleeSignature", callee.getSignature()
                ));
                return null;
            });
        }
    }
    
    
    
    /**
     * 存储完整的程序分析结果
     */
    public void storeAnalysisResults(Set<SootClass> classes, CallGraph callGraph, 
                                   FieldAccessGraph fieldGraph, ControllableFieldGraph controllableFieldGraph,
                                   IRAnalyzer.IRStatistics stats) {
        logger.info("🚀 开始批量存储分析结果到Neo4j...");
        long startTime = System.currentTimeMillis();
        
        // 清空数据库
        clearDatabase();
        
        // 🚀 批量优化：先收集所有数据，然后批量创建
        logger.info("📊 收集节点数据...");
        Set<SootMethod> allMethods = new HashSet<>();
        Set<SootField> allFields = new HashSet<>();
        Set<SootClass> allClasses = new HashSet<>(classes);
        Map<SootClass, Set<SootMethod>> classMethods = new HashMap<>();
        Map<SootClass, Set<SootField>> classFields = new HashMap<>();
        
        // 收集分析类的方法和字段
        for (SootClass sootClass : classes) {
            Set<SootMethod> methods = new HashSet<>();
            Set<SootField> fields = new HashSet<>();
            
            // 收集方法
            for (SootMethod method : sootClass.getMethods()) {
                allMethods.add(method);
                methods.add(method);
            }
            
            // 收集字段
            for (SootField field : sootClass.getFields()) {
                allFields.add(field);
                fields.add(field);
            }
            
            classMethods.put(sootClass, methods);
            classFields.put(sootClass, fields);
        }
        
        // 🔧 关键修复：收集调用图中的外部方法（JDK方法等）
        if (callGraph != null) {
            for (CallGraph.CallEdge edge : callGraph.getAllEdges()) {
                SootMethod caller = edge.getCaller();
                SootMethod callee = edge.getCallee();
                
                // 添加调用者和被调用者到方法集合
                if (!allMethods.contains(caller)) {
                    allMethods.add(caller);
                    SootClass callerClass = caller.getDeclaringClass();
                    allClasses.add(callerClass);
                    classMethods.computeIfAbsent(callerClass, k -> new HashSet<>()).add(caller);
                }
                
                if (!allMethods.contains(callee)) {
                    allMethods.add(callee);
                    SootClass calleeClass = callee.getDeclaringClass();
                    allClasses.add(calleeClass);
                    classMethods.computeIfAbsent(calleeClass, k -> new HashSet<>()).add(callee);
                }
            }
        }
        
        logger.info("📊 数据收集完成: " + allClasses.size() + " 个类（含外部类）, " + 
                   allMethods.size() + " 个方法（含外部方法）, " + allFields.size() + " 个字段");
        
        // 🚀 创建索引
        createIndexesIfNotExists();
        
        // 🚀 批量创建节点和关系（包含调用图中的外部方法）
        createClassNodesBatch(allClasses);
        createMethodNodesBatch(allMethods);
        createFieldNodesBatch(allFields);
        // 不再创建CONTAINS关系，简化图结构
        
        // 存储调用图关系
        storeCallGraphRelations(callGraph);
        
        // 存储可控字段图关系
        if (controllableFieldGraph != null) {
            storeControllableFieldRelations(controllableFieldGraph);
        }
        
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        
        logger.info("✅ 批量存储完成! 耗时: " + duration + "ms (" + (duration/1000.0) + "秒)");
    }
    
    /**
     * 🚀 批量存储调用图关系 - 性能优化版（去重）
     */
    private void storeCallGraphRelations(CallGraph callGraph) {
        Set<CallGraph.CallEdge> allEdges = callGraph.getAllEdges();
        if (allEdges.isEmpty()) {
            logger.info("没有调用关系需要存储");
            return;
        }
        
        logger.info("🚀 开始处理 " + allEdges.size() + " 条调用边（去重后存储）...");
        long startTime = System.currentTimeMillis();
        
        // 去重：每对方法之间只保留一条调用关系
        Map<String, Map<String, Object>> uniqueRelations = new LinkedHashMap<>();
        int duplicateCount = 0;
        
        for (CallGraph.CallEdge edge : allEdges) {
            String callerSig = edge.getCaller().getSignature();
            String calleeSig = edge.getCallee().getSignature();
            String relationKey = callerSig + " -> " + calleeSig;
            
            if (!uniqueRelations.containsKey(relationKey)) {
                // 第一次遇到这个方法对，保存调用关系
                Map<String, Object> data = new HashMap<>();
                data.put("callerSig", callerSig);
                data.put("calleeSig", calleeSig);
                data.put("callType", edge.getCallType() != null ? edge.getCallType().toString() : "UNKNOWN");
                data.put("site", edge.getCallSite() != null ? edge.getCallSite().toString() : "unknown");
                uniqueRelations.put(relationKey, data);
            } else {
                // 重复的调用关系，跳过
                duplicateCount++;
            }
        }
        
        int uniqueCount = uniqueRelations.size();
        logger.info("📊 去重统计: 原始边数=" + allEdges.size() + ", 唯一边数=" + uniqueCount + ", 重复边数=" + duplicateCount);
        
        try (Session session = driver.session()) {
            session.writeTransaction(tx -> {
                String query = "UNWIND $relations as rel " +
                              "MATCH (caller:Method {signature: rel.callerSig}) " +
                              "MATCH (callee:Method {signature: rel.calleeSig}) " +
                              "CREATE (caller)-[:CALLS {" +
                              "  callType: rel.callType, " +
                              "  site: rel.site" +
                              "}]->(callee)";
                
                List<Map<String, Object>> relationData = new ArrayList<>(uniqueRelations.values());
                tx.run(query, Values.parameters("relations", relationData));
                return null;
            });
        }
        
        long duration = System.currentTimeMillis() - startTime;
        logger.info("✅ 调用关系批量创建完成! 存储了 " + uniqueCount + " 条唯一调用关系，耗时: " + duration + "ms");
    }
    
    /**
     * 查询统计信息
     */
    public void printGraphStatistics() {
        try (Session session = driver.session()) {
            // 统计各类型节点数量
            Result classResult = session.run("MATCH (c:Class) RETURN count(c) as count");
            Result methodResult = session.run("MATCH (m:Method) RETURN count(m) as count");
            Result fieldResult = session.run("MATCH (f:Field) RETURN count(f) as count");
            
            // 统计内部和外部节点
            Result internalClassResult = session.run("MATCH (c:Class) WHERE NOT c.isExternal = true RETURN count(c) as count");
            Result externalClassResult = session.run("MATCH (c:Class) WHERE c.isExternal = true RETURN count(c) as count");
            Result internalMethodResult = session.run("MATCH (m:Method) WHERE NOT m.isExternal = true RETURN count(m) as count");
            Result externalMethodResult = session.run("MATCH (m:Method) WHERE m.isExternal = true RETURN count(m) as count");
            
            // 统计各类型关系数量
            Result callsResult = session.run("MATCH ()-[r:CALLS]->() RETURN count(r) as count");
            
            // 统计4种字段影响关系
            Result directUseResult = session.run("MATCH ()-[r:DIRECT_USE]->() RETURN count(r) as count");
            Result parameterUseResult = session.run("MATCH ()-[r:PARAMETER_USE]->() RETURN count(r) as count");
            Result conditionUseResult = session.run("MATCH ()-[r:CONDITION_USE]->() RETURN count(r) as count");
            Result indirectUseResult = session.run("MATCH ()-[r:INDIRECT_USE]->() RETURN count(r) as count");
            
            System.out.println("\n=== Neo4j 数据库存储统计 ===");
            System.out.println("📊 存储的节点统计:");
            System.out.println("  类节点: " + classResult.single().get("count").asInt() + 
                             " (内部: " + internalClassResult.single().get("count").asInt() + 
                             ", 外部: " + externalClassResult.single().get("count").asInt() + ")");
            System.out.println("  方法节点: " + methodResult.single().get("count").asInt() + 
                             " (内部: " + internalMethodResult.single().get("count").asInt() + 
                             ", 外部: " + externalMethodResult.single().get("count").asInt() + ")");
            System.out.println("  字段节点: " + fieldResult.single().get("count").asInt());
            
            System.out.println("🔗 存储的关系统计:");
            System.out.println("  调用关系: " + callsResult.single().get("count").asInt() + " (已去重，每对方法间只有一条边)");
            System.out.println("  字段影响关系:");
            System.out.println("    直接使用(DIRECT_USE): " + directUseResult.single().get("count").asInt());
            System.out.println("    参数传递(PARAMETER_USE): " + parameterUseResult.single().get("count").asInt());
            System.out.println("    条件控制(CONDITION_USE): " + conditionUseResult.single().get("count").asInt());
            System.out.println("    间接影响(INDIRECT_USE): " + indirectUseResult.single().get("count").asInt());
            System.out.println("💡 注意：方法节点数量包含所有类的所有方法（包括未参与调用的方法）");
            System.out.println("========================");
        }
    }
    
    /**
     * 关闭数据库连接
     */
    public void close() {
        driver.close();
    }
    
    // ============== 🚀 批量优化辅助方法 ==============
    
    /**
     * 创建索引（如果不存在）
     */
    private void createIndexesIfNotExists() {
        try (Session session = driver.session()) {
            session.writeTransaction(tx -> {
                try {
                    tx.run("CREATE INDEX class_name_index IF NOT EXISTS FOR (c:Class) ON (c.name)");
                    tx.run("CREATE INDEX method_signature_index IF NOT EXISTS FOR (m:Method) ON (m.signature)");
                    tx.run("CREATE INDEX field_signature_index IF NOT EXISTS FOR (f:Field) ON (f.signature)");
                    logger.info("✅ Neo4j索引创建完成");
                } catch (Exception e) {
                    logger.warning("索引创建失败（可能已存在）: " + e.getMessage());
                }
                return null;
            });
        }
    }
    
    /**
     * 批量创建类节点
     */
    private void createClassNodesBatch(Collection<SootClass> classes) {
        if (classes.isEmpty()) return;
        
        logger.info("🚀 批量创建 " + classes.size() + " 个类节点...");
        
        try (Session session = driver.session()) {
            session.writeTransaction(tx -> {
                String query = "UNWIND $classes as cls " +
                              "CREATE (c:Class {" +
                              "name: cls.name, " +
                              "packageName: cls.packageName, " +
                              "isInterface: cls.isInterface, " +
                              "isAbstract: cls.isAbstract, " +
                              "isPublic: cls.isPublic" +
                              "})";
                
                List<Map<String, Object>> classData = new ArrayList<>();
                for (SootClass sootClass : classes) {
                    Map<String, Object> data = new HashMap<>();
                    data.put("name", sootClass.getName());
                    data.put("packageName", sootClass.getPackageName());
                    data.put("isInterface", sootClass.isInterface());
                    data.put("isAbstract", sootClass.isAbstract());
                    data.put("isPublic", sootClass.isPublic());
                    classData.add(data);
                }
                
                tx.run(query, Values.parameters("classes", classData));
                return null;
            });
        }
        
        logger.info("✅ 类节点批量创建完成");
    }
    
    /**
     * 批量创建方法节点
     */
    private void createMethodNodesBatch(Collection<SootMethod> methods) {
        if (methods.isEmpty()) return;
        
        logger.info("🚀 批量创建 " + methods.size() + " 个方法节点...");
        
        try (Session session = driver.session()) {
            session.writeTransaction(tx -> {
                String query = "UNWIND $methods as method " +
                              "CREATE (m:Method {" +
                              "signature: method.signature, " +
                              "name: method.name, " +
                              "className: method.className, " +
                              "returnType: method.returnType, " +
                              "parameterCount: method.parameterCount, " +
                              "isStatic: method.isStatic, " +
                              "isPublic: method.isPublic, " +
                              "isAbstract: method.isAbstract, " +
                              "hasActiveBody: method.hasActiveBody" +
                              "})";
                
                List<Map<String, Object>> methodData = new ArrayList<>();
                for (SootMethod method : methods) {
                    Map<String, Object> data = new HashMap<>();
                    data.put("signature", method.getSignature());
                    data.put("name", method.getName());
                    data.put("className", method.getDeclaringClass().getName());
                    data.put("returnType", method.getReturnType().toString());
                    data.put("parameterCount", method.getParameterCount());
                    data.put("isStatic", method.isStatic());
                    data.put("isPublic", method.isPublic());
                    data.put("isAbstract", method.isAbstract());
                    data.put("hasActiveBody", method.hasActiveBody());
                    methodData.add(data);
                }
                
                tx.run(query, Values.parameters("methods", methodData));
                return null;
            });
        }
        
        logger.info("✅ 方法节点批量创建完成");
    }
    
    /**
     * 批量创建字段节点
     */
    private void createFieldNodesBatch(Collection<SootField> fields) {
        if (fields.isEmpty()) return;
        
        logger.info("🚀 批量创建 " + fields.size() + " 个字段节点...");
        
        try (Session session = driver.session()) {
            session.writeTransaction(tx -> {
                String query = "UNWIND $fields as field " +
                              "CREATE (f:Field {" +
                              "signature: field.signature, " +
                              "name: field.name, " +
                              "className: field.className, " +
                              "type: field.type, " +
                              "isStatic: field.isStatic, " +
                              "isPublic: field.isPublic, " +
                              "isFinal: field.isFinal" +
                              "})";
                
                List<Map<String, Object>> fieldData = new ArrayList<>();
                for (SootField field : fields) {
                    Map<String, Object> data = new HashMap<>();
                    data.put("signature", field.getSignature());
                    data.put("name", field.getName());
                    data.put("className", field.getDeclaringClass().getName());
                    data.put("type", field.getType().toString());
                    data.put("isStatic", field.isStatic());
                    data.put("isPublic", field.isPublic());
                    data.put("isFinal", field.isFinal());
                    fieldData.add(data);
                }
                
                tx.run(query, Values.parameters("fields", fieldData));
                return null;
            });
        }
        
        logger.info("✅ 字段节点批量创建完成");
    }
    
    
    /**
     * 🚀 批量存储可控字段图关系 - 性能优化版
     */
    private void storeControllableFieldRelations(ControllableFieldGraph controllableFieldGraph) {
        logger.info("📊 批量存储可控字段图关系...");
        long startTime = System.currentTimeMillis();
        
        try (Session session = driver.session()) {
            Set<SootField> controllableFields = controllableFieldGraph.getAllControllableFields();
            if (controllableFields.isEmpty()) {
                logger.info("没有可控字段需要存储");
                return;
            }
            
            // 1. 🚀 批量标记可控字段
            session.writeTransaction(tx -> {
                List<String> fieldSigs = new ArrayList<>();
                for (SootField field : controllableFields) {
                    fieldSigs.add(field.getSignature());
                }
                
                tx.run("UNWIND $sigs as sig " +
                       "MATCH (f:Field {signature: sig}) " +
                       "SET f.controllable = true, f.attackerControllable = true",
                       Values.parameters("sigs", fieldSigs));
                return null;
            });
            logger.info("✅ 批量标记了 " + controllableFields.size() + " 个可控字段");
            
            // 2. 按类统计可控字段（简化版存储）
            Map<SootClass, Integer> classFieldCount = new HashMap<>();
            for (SootField field : controllableFields) {
                SootClass clazz = field.getDeclaringClass();
                classFieldCount.put(clazz, classFieldCount.getOrDefault(clazz, 0) + 1);
            }
            
            logger.info("✅ 涉及 " + classFieldCount.size() + " 个类的可控字段");
            
            // 打印每个类的可控字段统计
            for (Map.Entry<SootClass, Integer> entry : classFieldCount.entrySet()) {
                logger.fine("  " + entry.getKey().getShortName() + ": " + entry.getValue() + " 个可控字段");
            }
            
        } catch (Exception e) {
            logger.severe("可控字段图存储过程中出现错误: " + e.getMessage());
            e.printStackTrace();
        }
        
        long duration = System.currentTimeMillis() - startTime;
        logger.info("✅ 可控字段图批量存储完成! 耗时: " + duration + "ms (" + (duration/1000.0) + "秒)");
    }
}