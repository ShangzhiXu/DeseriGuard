package com.squirtle.core.sink;

import com.squirtle.core.taint.guided.model.MethodLevelTaint;
import soot.Scene;
import soot.SootMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Flash对齐的Sink注册表
 * 
 * <p>管理30个Flash预定义的危险方法（sinks）及其可控性约束。
 * 
 * <p><b>Sink分类</b>（共30个）：
 * <ul>
 *   <li>命令执行 (5个): Runtime.exec, ProcessBuilder.start, etc.</li>
 *   <li>JNDI注入 (4个): InitialContext.lookup, etc.</li>
 *   <li>类加载 (6个): ClassLoader.loadClass, Class.newInstance, etc.</li>
 *   <li>脚本执行 (4个): ScriptEngine.eval, ValueExpression.getValue, etc.</li>
 *   <li>文件操作 (5-6个): FileOutputStream.write, File.delete, etc.</li>
 *   <li>网络/数据库 (2个): URL.openConnection, DriverManager.getConnection</li>
 *   <li>RMI/RPC (1个): TCPTransport.listen</li>
 * </ul>
 * 
 * @author BugTurtle
 */
public class FlashAlignedSinkRegistry {
    private static final Logger logger = LoggerFactory.getLogger(FlashAlignedSinkRegistry.class);
    
    /** Sink定义列表（按签名索引） */
    private final Map<String, SinkDefinition> sinksBySignature;
    
    /** 已解析的Soot方法（按签名索引） */
    private final Map<String, SootMethod> sinkMethods;
    
    /**
     * 构造函数：初始化30个Flash预定义sink
     */
    public FlashAlignedSinkRegistry() {
        this.sinksBySignature = new ConcurrentHashMap<>();
        this.sinkMethods = new ConcurrentHashMap<>();
        initializeFlashSinks();
    }
    
    /**
     * 初始化Flash的30个预定义sink
     */
    private void initializeFlashSinks() {
        List<SinkDefinition> sinks = new ArrayList<>();
        
        // 1. 命令执行 (5个)
        sinks.add(new SinkDefinition(
            "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.COMMAND_EXECUTION
        ));
        sinks.add(new SinkDefinition(
            "<java.lang.Runtime: java.lang.Process exec(java.lang.String[])>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.COMMAND_EXECUTION
        ));
        sinks.add(new SinkDefinition(
            "<java.lang.ProcessBuilder: java.lang.Process start()>",
            Arrays.asList(-1),
            SinkDefinition.SinkCategory.COMMAND_EXECUTION
        ));
        sinks.add(new SinkDefinition(
            "<java.lang.ProcessBuilder: java.lang.ProcessBuilder command(java.lang.String[])>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.COMMAND_EXECUTION
        ));
        sinks.add(new SinkDefinition(
            "<java.lang.ProcessImpl: java.lang.Process start(java.lang.String[],java.util.Map,java.lang.String,java.lang.ProcessBuilder$Redirect[],boolean)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.COMMAND_EXECUTION
        ));
        
        // 2. JNDI注入 (4个)
        sinks.add(new SinkDefinition(
            "<javax.naming.InitialContext: java.lang.Object lookup(java.lang.String)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.JNDI_INJECTION
        ));
        sinks.add(new SinkDefinition(
            "<javax.naming.InitialContext: java.lang.Object lookup(javax.naming.Name)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.JNDI_INJECTION
        ));
        sinks.add(new SinkDefinition(
            "<javax.naming.spi.ContinuationDirContext: java.lang.Object lookup(javax.naming.Name)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.JNDI_INJECTION
        ));
        sinks.add(new SinkDefinition(
            "<com.sun.jndi.rmi.registry.RegistryContext: java.lang.Object lookup(javax.naming.Name)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.JNDI_INJECTION
        ));
        
        // 3. 类加载 (6个)
        sinks.add(new SinkDefinition(
            "<java.lang.ClassLoader: java.lang.Class loadClass(java.lang.String)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.CLASS_LOADING
        ));
        sinks.add(new SinkDefinition(
            "<java.lang.Class: java.lang.Class forName(java.lang.String)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.CLASS_LOADING
        ));
        sinks.add(new SinkDefinition(
            "<java.lang.Class: java.lang.Object newInstance()>",
            Arrays.asList(-1),
            SinkDefinition.SinkCategory.CLASS_LOADING
        ));
        sinks.add(new SinkDefinition(
            "<java.net.URLClassLoader: java.lang.Class defineClass(java.lang.String,byte[],int,int)>",
            Arrays.asList(1),
            SinkDefinition.SinkCategory.CLASS_LOADING
        ));
        sinks.add(new SinkDefinition(
            "<java.security.SecureClassLoader: java.lang.Class defineClass(java.lang.String,byte[],int,int,java.security.CodeSource)>",
            Arrays.asList(1),
            SinkDefinition.SinkCategory.CLASS_LOADING
        ));
        sinks.add(new SinkDefinition(
            "<javax.management.loading.MLet: java.lang.Class loadClass(java.lang.String,java.lang.ClassLoaderRepository)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.CLASS_LOADING
        ));
        
        // 4. 脚本执行 (4个)
        sinks.add(new SinkDefinition(
            "<javax.script.ScriptEngine: java.lang.Object eval(java.lang.String)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.SCRIPT_EXECUTION
        ));
        sinks.add(new SinkDefinition(
            "<javax.el.ValueExpression: java.lang.Object getValue(javax.el.ELContext)>",
            Arrays.asList(-1),
            SinkDefinition.SinkCategory.SCRIPT_EXECUTION
        ));
        sinks.add(new SinkDefinition(
            "<javax.el.MethodExpression: java.lang.Object invoke(javax.el.ELContext,java.lang.Object[])>",
            Arrays.asList(-1),
            SinkDefinition.SinkCategory.SCRIPT_EXECUTION
        ));
        sinks.add(new SinkDefinition(
            "<org.springframework.expression.Expression: java.lang.Object getValue()>",
            Arrays.asList(-1),
            SinkDefinition.SinkCategory.SCRIPT_EXECUTION
        ));
        
        // 5. 文件操作 (6个)
        sinks.add(new SinkDefinition(
            "<java.io.FileOutputStream: void write(byte[])>",
            Arrays.asList(-1, 0),
            SinkDefinition.SinkCategory.FILE_OPERATION
        ));
        sinks.add(new SinkDefinition(
            "<java.io.FileOutputStream: void write(byte[],int,int)>",
            Arrays.asList(-1, 0),
            SinkDefinition.SinkCategory.FILE_OPERATION
        ));
        sinks.add(new SinkDefinition(
            "<java.io.File: boolean delete()>",
            Arrays.asList(-1),
            SinkDefinition.SinkCategory.FILE_OPERATION
        ));
        sinks.add(new SinkDefinition(
            "<java.io.File: boolean renameTo(java.io.File)>",
            Arrays.asList(-1, 0),
            SinkDefinition.SinkCategory.FILE_OPERATION
        ));
        sinks.add(new SinkDefinition(
            "<java.nio.file.Files: java.nio.file.Path write(java.nio.file.Path,byte[],java.nio.file.OpenOption[])>",
            Arrays.asList(0, 1),
            SinkDefinition.SinkCategory.FILE_OPERATION
        ));
        sinks.add(new SinkDefinition(
            "<java.nio.file.Files: void delete(java.nio.file.Path)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.FILE_OPERATION
        ));
        
        // 6. 网络/数据库 (2个)
        sinks.add(new SinkDefinition(
            "<java.net.URL: java.net.URLConnection openConnection()>",
            Arrays.asList(-1),
            SinkDefinition.SinkCategory.NETWORK_DATABASE
        ));
        sinks.add(new SinkDefinition(
            "<java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String)>",
            Arrays.asList(0),
            SinkDefinition.SinkCategory.NETWORK_DATABASE
        ));
        
        // 7. RMI/RPC (1个)
        sinks.add(new SinkDefinition(
            "<sun.rmi.transport.tcp.TCPTransport: void listen()>",
            Arrays.asList(-1),
            SinkDefinition.SinkCategory.RMI_RPC
        ));
        
        // 8. XSLT字节码执行 (2个) - TemplatesImpl RCE
        sinks.add(new SinkDefinition(
            "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer()>",
            Arrays.asList(-1),  // this (TemplatesImpl实例) 必须可控
            SinkDefinition.SinkCategory.XSLT_BYTECODE
        ));
        sinks.add(new SinkDefinition(
            "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: java.util.Properties getOutputProperties()>",
            Arrays.asList(-1),  // this 必须可控
            SinkDefinition.SinkCategory.XSLT_BYTECODE
        ));
        
        // 注册所有sink
        for (SinkDefinition sink : sinks) {
            sinksBySignature.put(sink.getSignature(), sink);
        }
        
        logger.info("FlashAlignedSinkRegistry 初始化完成。已加载 {} 个sink定义.", sinksBySignature.size());
    }
    
    /**
     * 检查方法是否是sink（带可控性约束检查）
     * 
     * @param method Soot方法
     * @param taint 方法级污点
     * @return true如果是sink且满足可控性约束
     */
    public boolean isSinkWithTaint(SootMethod method, MethodLevelTaint taint) {
        String signature = method.getSignature();
        SinkDefinition definition = sinksBySignature.get(signature);

        // 特殊跟踪Runtime.exec（用于诊断）
        boolean isExecMethod = method.getName().equals("exec");
        boolean isRuntimeClass = method.getDeclaringClass().getName().equals("java.lang.Runtime");

        if (isExecMethod && isRuntimeClass) {
            if (definition != null) {
                FlashAlignedSinkRegistry.lastRuntimeExecIsTaintSatisfied = definition.isTaintSatisfied(taint);
            } else {
                FlashAlignedSinkRegistry.lastRuntimeExecIsTaintSatisfied = false;
            }
        }

        return definition != null && definition.isTaintSatisfied(taint);
    }
    
    /**
     * 获取所有sink方法（用于反射兜底）
     * 
     * @return Sink方法集合
     */
    public Set<SootMethod> getAllSinkMethods() {
        if (!sinkMethods.isEmpty()) {
            return new HashSet<>(sinkMethods.values());
        }
        
        // 懒加载：从Scene中解析所有sink方法
        Set<SootMethod> methods = new HashSet<>();
        for (String signature : sinksBySignature.keySet()) {
            try {
                SootMethod method = Scene.v().getMethod(signature);
                
                // 诊断Sink解析：检查Runtime.exec是否是Phantom方法
                if (method != null && !method.isPhantom()) {
                    sinkMethods.put(signature, method);
                    methods.add(method);
                }
            } catch (Exception e) {
                logger.warn("无法解析sink方法: {}", signature);
            }
        }
        
        logger.info("已解析 {} / {} 个sink方法", methods.size(), sinksBySignature.size());
        
        return methods;
    }
    
    /**
     * 获取sink定义（用于测试和调试）
     */
    public SinkDefinition getSinkDefinition(String signature) {
        // 诊断：打印查询的签名和结果
        SinkDefinition result = sinksBySignature.get(signature);
        return result;
    }
    
    /**
     * 获取所有sink定义
     */
    public Collection<SinkDefinition> getAllSinkDefinitions() {
        return sinksBySignature.values();
    }

    private static FlashAlignedSinkRegistry instance;

    public static FlashAlignedSinkRegistry v() {
        if (instance == null) {
            synchronized (FlashAlignedSinkRegistry.class) {
                if (instance == null) {
                    instance = new FlashAlignedSinkRegistry();
                }
            }
        }
        return instance;
    }

    /** 存储 Runtime.exec 的 isTaintSatisfied 结果，用于最终诊断 */
    public static Boolean lastRuntimeExecIsTaintSatisfied = null;
}




























