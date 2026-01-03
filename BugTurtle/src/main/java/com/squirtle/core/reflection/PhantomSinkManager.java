package com.squirtle.core.reflection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;

import java.util.*;

/**
 * 管理Phantom类的sink方法
 * 学习Flash的策略：通过配置主动创建Phantom类的方法引用
 */
public class PhantomSinkManager {
    private static final Logger logger = LoggerFactory.getLogger(PhantomSinkManager.class);
    
    /**
     * Phantom Sink方法配置
     * 格式：{类名, 方法名, 参数签名, 返回类型, 类别}
     */
    private static final String[][] PHANTOM_SINK_CONFIGS = {
        // JNDI Injection (4个 Phantom sink)
        {"javax.naming.InitialContext", "lookup", "java.lang.String", "java.lang.Object"},
        {"javax.naming.InitialContext", "lookup", "javax.naming.Name", "java.lang.Object"},
        {"com.sun.jndi.ldap.LdapCtx", "c_lookup", "javax.naming.Name,com.sun.jndi.toolkit.ctx.Continuation", "java.lang.Object"},
        {"javax.naming.spi.NamingManager", "getObjectFactoryFromReference", "javax.naming.Reference,java.lang.String", "javax.naming.spi.ObjectFactory"},
        
        // SQL Injection (1个 Phantom sink - 仅DriverManager，Statement/Connection不可序列化)
        {"java.sql.DriverManager", "getConnection", "java.lang.String,java.util.Properties,java.lang.Class", "java.sql.Connection"},
    };
    
    private final Set<SootMethod> phantomSinkMethods;
    private final Map<String, List<SootMethod>> methodsByName;
    
    public PhantomSinkManager() {
        this.phantomSinkMethods = new HashSet<>();
        this.methodsByName = new HashMap<>();
        createPhantomSinkMethods();
    }
    
    /**
     * 创建所有配置的Phantom sink方法
     */
    private void createPhantomSinkMethods() {
        logger.info("开始创建Phantom sink方法...");
        int successCount = 0;
        int failCount = 0;
        
        for (String[] config : PHANTOM_SINK_CONFIGS) {
            String className = config[0];
            String methodName = config[1];
            String paramSig = config[2];
            String returnTypeName = config[3];
            
            try {
                SootMethod method = createPhantomMethod(className, methodName, paramSig, returnTypeName);
                if (method != null) {
                    phantomSinkMethods.add(method);
                    methodsByName.computeIfAbsent(methodName, k -> new ArrayList<>()).add(method);
                    successCount++;
                    logger.debug("✅ 成功创建Phantom sink: {}", method.getSignature());
                }
            } catch (Exception e) {
                failCount++;
                logger.debug("❌ 无法创建Phantom sink: {}.{} - {}", 
                    className, methodName, e.getMessage());
            }
        }
        
        logger.info("Phantom sink创建完成: 成功{}个, 失败{}个", successCount, failCount);
    }
    
    /**
     * 创建单个Phantom方法引用
     * 学习Flash的makeMethodRef策略
     */
    private SootMethod createPhantomMethod(String className, String methodName, 
                                          String paramSig, String returnTypeName) {
        try {
            // 1. 获取或创建类（允许Phantom）
            SootClass declaringClass = getOrCreatePhantomClass(className);
            
            // 2. 解析参数类型
            List<Type> paramTypes = parseParameterTypes(paramSig);
            
            // 3. 解析返回类型
            Type returnType = parseType(returnTypeName);
            
            // 4. 创建方法引用（关键：使用makeMethodRef）
            SootMethodRef methodRef = Scene.v().makeMethodRef(
                declaringClass,
                methodName,
                paramTypes,
                returnType,
                false  // isStatic
            );
            
            // 5. 尝试解析方法
            // 如果方法不存在，Soot会自动创建一个Phantom方法
            SootMethod method = methodRef.resolve();
            
            return method;
            
        } catch (Exception e) {
            logger.debug("创建Phantom方法失败: {}.{} - {}", 
                className, methodName, e.getMessage());
            return null;
        }
    }
    
    /**
     * 获取或创建Phantom类
     */
    private SootClass getOrCreatePhantomClass(String className) {
        if (Scene.v().containsClass(className)) {
            return Scene.v().getSootClass(className);
        }
        
        // 创建新的Phantom类
        SootClass phantomClass = new SootClass(className);
        phantomClass.setPhantomClass();
        Scene.v().addClass(phantomClass);
        
        logger.debug("创建Phantom类: {}", className);
        return phantomClass;
    }
    
    /**
     * 解析参数类型字符串
     * 例如: "java.lang.String,int" -> [StringType, IntType]
     */
    private List<Type> parseParameterTypes(String paramSig) {
        List<Type> paramTypes = new ArrayList<>();
        
        if (paramSig == null || paramSig.trim().isEmpty()) {
            return paramTypes;
        }
        
        String[] typeNames = paramSig.split(",");
        for (String typeName : typeNames) {
            typeName = typeName.trim();
            if (!typeName.isEmpty()) {
                Type type = parseType(typeName);
                paramTypes.add(type);
            }
        }
        
        return paramTypes;
    }
    
    /**
     * 解析类型名称为Soot Type
     */
    private Type parseType(String typeName) {
        typeName = typeName.trim();
        
        // 处理基本类型
        switch (typeName) {
            case "void": return VoidType.v();
            case "boolean": return BooleanType.v();
            case "byte": return ByteType.v();
            case "char": return CharType.v();
            case "short": return ShortType.v();
            case "int": return IntType.v();
            case "long": return LongType.v();
            case "float": return FloatType.v();
            case "double": return DoubleType.v();
        }
        
        // 处理数组类型
        if (typeName.endsWith("[]")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 2);
            Type baseType = parseType(baseTypeName);
            return ArrayType.v(baseType, 1);
        }
        
        // 引用类型
        return RefType.v(typeName);
    }
    
    /**
     * 获取所有Phantom sink方法
     */
    public Set<SootMethod> getAllPhantomSinks() {
        return Collections.unmodifiableSet(phantomSinkMethods);
    }
    
    /**
     * 根据方法名查找Phantom sink方法
     */
    public List<SootMethod> findPhantomSinksByName(String methodName) {
        return methodsByName.getOrDefault(methodName, Collections.emptyList());
    }
    
    /**
     * 检查是否是Phantom sink
     */
    public boolean isPhantomSink(SootMethod method) {
        return phantomSinkMethods.contains(method);
    }
    
    /**
     * 获取统计信息
     */
    public void printStatistics() {
        logger.info("═══════════════════════════════════════════");
        logger.info("Phantom Sink统计:");
        logger.info("  总数: {} 个", phantomSinkMethods.size());
        logger.info("  唯一方法名: {} 个", methodsByName.size());
        logger.info("═══════════════════════════════════════════");
        
        for (SootMethod method : phantomSinkMethods) {
            logger.info("  - {}", method.getSignature());
        }
    }
}



