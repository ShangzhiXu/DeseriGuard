package com.squirtle.gadget;

import soot.SootMethod;
import java.util.*;

/**
 * Source和Sink管理器
 * 
 * 基于Flash的source/sink定义
 * 
 * @author BugTurtle
 */
public class SourceSinkManager {
    
    private final Set<SootMethod> sourceMethods = new HashSet<>();
    private final Set<SootMethod> sinkMethods = new HashSet<>();
    private final Map<SootMethod, SinkCategory> sinkCategories = new HashMap<>();
    
    /**
     * Sink分类（Flash定义的7大类）
     */
    public enum SinkCategory {
        COMMAND_EXECUTION,    // 命令执行
        CODE_EXECUTION,       // 代码执行
        JNDI_INJECTION,       // JNDI注入
        FILE_OPERATION,       // 文件操作
        REFLECTION,           // 反射调用
        NETWORK,              // 网络操作
        OTHER                 // 其他
    }
    
    /**
     * 构造函数
     */
    public SourceSinkManager(boolean autoIdentify) {
        if (autoIdentify) {
            // 自动从Scene中识别所有Source和Sink
            autoIdentifyFromScene();
        }
    }
    
    /**
     * 从Soot Scene自动识别Source和Sink
     */
    private void autoIdentifyFromScene() {
        List<SootMethod> allMethods = new ArrayList<>();
        
        // 🔥 修复：获取所有类的所有方法（包括abstract类）
        // 原因：OutputStream是abstract类，但OutputStream.write(byte[])是concrete方法
        // 如果只遍历concrete类，会漏掉OutputStream.write这个重要的sink
        for (soot.SootClass cls : soot.Scene.v().getClasses()) {
            // 🔥 移除 if (cls.isConcrete()) 判断
            for (SootMethod method : cls.getMethods()) {
                allMethods.add(method);
            }
        }
        
        // 识别Sources和Sinks
        identifySources(allMethods);
        identifySinks(allMethods);
    }
    
    /**
     * 识别Source方法
     */
    public void identifySources(Collection<SootMethod> methods) {
        for (SootMethod method : methods) {
            if (isSerializableMethod(method)) {
                sourceMethods.add(method);
            }
        }
    }
    
    /**
     * 识别Sink方法
     */
    public void identifySinks(Collection<SootMethod> methods) {
        for (SootMethod method : methods) {
            SinkCategory category = matchSink(method);
            if (category != null) {
                sinkMethods.add(method);
                sinkCategories.put(method, category);
            }
        }
    }
    
    /**
     * 判断是否为序列化入口方法
     */
    private boolean isSerializableMethod(SootMethod method) {
        String subSig = method.getSubSignature();
        
        // readObject
        if (subSig.equals("void readObject(java.io.ObjectInputStream)")) {
            return true;
        }
        
        // readExternal
        if (subSig.equals("void readExternal(java.io.ObjectInput)")) {
            return true;
        }
        
        // readResolve
        if (subSig.equals("java.lang.Object readResolve()")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 匹配Sink方法（基于Flash priori-knowledge.yml + CC3增强，共34个sink）
     */
    private SinkCategory matchSink(SootMethod method) {
        String sig = method.getSignature();
        String methodName = method.getName();
        String className = method.getDeclaringClass().getName();
        
        // 1. JNDI注入 (5个)
        if (sig.equals("<javax.naming.InitialContext: java.lang.Object lookup(java.lang.String)>")) {
            return SinkCategory.JNDI_INJECTION;
        }
        if (sig.equals("<javax.naming.InitialContext: java.lang.Object lookup(javax.naming.Name)>")) {
            return SinkCategory.JNDI_INJECTION;
        }
        if (sig.equals("<com.sun.jndi.ldap.LdapCtx: java.lang.Object c_lookup(javax.naming.Name,com.sun.jndi.toolkit.ctx.Continuation)>")) {
            return SinkCategory.JNDI_INJECTION;
        }
        if (sig.equals("<org.springframework.jndi.JndiTemplate: java.lang.Object lookup(java.lang.String)>")) {
            return SinkCategory.JNDI_INJECTION;
        }
        if (sig.equals("<javax.naming.spi.NamingManager: javax.naming.spi.ObjectFactory getObjectFactoryFromReference(javax.naming.Reference,java.lang.String)>")) {
            return SinkCategory.JNDI_INJECTION;
        }
        
        // 2. 代码执行 (10个)
        if (sig.equals("<java.lang.Class: java.lang.Object newInstance()>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        if (sig.equals("<java.lang.ClassLoader: java.lang.Class loadClass(java.lang.String)>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        if (sig.equals("<java.lang.ClassLoader: java.lang.Class loadClass(java.lang.String,boolean)>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        if (sig.equals("<java.lang.Class: java.lang.Class forName(java.lang.String,boolean,java.lang.ClassLoader)>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        // 注：单参数版本 forName(String) 不作为 sink，因为它使用默认 ClassLoader，攻击者无法控制从远程加载类
        if (sig.equals("<java.net.URLClassLoader: java.net.URLClassLoader newInstance(java.net.URL[],java.lang.ClassLoader)>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        if (sig.equals("<java.net.URLClassLoader: java.net.URLClassLoader newInstance(java.net.URL[])>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        if (sig.equals("<java.net.URLClassLoader: java.lang.Class findClass(java.lang.String)>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        if (sig.equals("<javax.el.ValueExpression: java.lang.Object getValue(javax.el.ELContext)>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        if (sig.equals("<clojure.lang.Compiler: java.lang.Object eval(java.lang.Object)>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        if (sig.equals("<javax.script.ScriptEngineManager: void <init>(java.lang.ClassLoader)>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        
        // 3. 命令执行 (5个)
        if (sig.equals("<java.lang.ProcessBuilder: java.lang.Process start()>")) {
            return SinkCategory.COMMAND_EXECUTION;
        }
        if (sig.equals("<java.lang.Runtime: java.lang.Process exec(java.lang.String)>")) {
            return SinkCategory.COMMAND_EXECUTION;
        }
        if (sig.equals("<java.lang.Runtime: java.lang.Process exec(java.lang.String[])>")) {
            return SinkCategory.COMMAND_EXECUTION;
        }
        if (sig.equals("<java.lang.Runtime: java.lang.Process exec(java.lang.String,java.lang.String[],java.io.File)>")) {
            return SinkCategory.COMMAND_EXECUTION;
        }
        if (sig.equals("<java.lang.Runtime: java.lang.Process exec(java.lang.String[],java.lang.String[],java.io.File)>")) {
            return SinkCategory.COMMAND_EXECUTION;
        }
        
        // 4. 文件操作 (6个)
        if (sig.equals("<java.io.OutputStream: void write(byte[])>")) {
            return SinkCategory.FILE_OPERATION;
        }
        if (sig.equals("<java.io.OutputStream: void write(byte[],int,int)>")) {
            return SinkCategory.FILE_OPERATION;
        }
        if (sig.equals("<java.io.File: boolean delete()>")) {
            return SinkCategory.FILE_OPERATION;
        }
        if (sig.equals("<java.io.FileOutputStream: void write(byte[])>")) {
            return SinkCategory.FILE_OPERATION;
        }
        if (sig.equals("<java.io.FileInputStream: int read(byte[],int,int)>")) {
            return SinkCategory.FILE_OPERATION;
        }
        if (sig.equals("<java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String,java.util.Properties,java.lang.Class)>")) {
            return SinkCategory.FILE_OPERATION; // SQL相关放在文件操作类
        }
        
        // 5. 反射调用 - 不作为 sink
        // Method.invoke 只是反射桥接点，不是最终 sink
        // CC3 的问题需要从其他角度解决
        
        // 6. 网络操作 (6个)
        if (sig.equals("<java.net.URL: java.net.URLConnection openConnection()>")) {
            return SinkCategory.NETWORK;
        }
        if (sig.equals("<sun.rmi.transport.tcp.TCPTransport: void listen()>")) {
            return SinkCategory.NETWORK;
        }
        // DNS 泄露攻击
        if (sig.equals("<java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>")) {
            return SinkCategory.NETWORK;
        }
        // SSRF 攻击
        if (sig.equals("<javax.swing.JEditorPane: void setPage(java.lang.String)>")) {
            return SinkCategory.NETWORK;
        }
        if (sig.equals("<javax.swing.JEditorPane: void setPage(java.net.URL)>")) {
            return SinkCategory.NETWORK;
        }
        if (sig.equals("<javax.swing.JEditorPane: java.io.InputStream getStream(java.net.URL)>")) {
            return SinkCategory.NETWORK;
        }
        
        // 7. 其他特殊危险方法 (1个)
        if (sig.equals("<org.python.core.PyBaseCode: org.python.core.PyObject call(org.python.core.ThreadState,org.python.core.PyObject[],java.lang.String[],org.python.core.PyObject,org.python.core.PyObject[],org.python.core.PyObject)>")) {
            return SinkCategory.OTHER;
        }
        
        // 8. XSLT字节码执行 - TemplatesImpl RCE (2个)
        if (sig.equals("<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer()>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        if (sig.equals("<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: java.util.Properties getOutputProperties()>")) {
            return SinkCategory.CODE_EXECUTION;
        }
        
        return null;
    }
    
    /**
     * 检查是否为Source
     */
    public boolean isSource(SootMethod method) {
        return sourceMethods.contains(method);
    }
    
    /**
     * 检查是否为Sink
     * 
     * 🔥 关键修复：动态匹配sink模式，而不是只检查预先注册的集合
     * 原因：Runtime.exec等方法通过反射调用动态添加到调用图，不在sinkMethods中
     */
    public boolean isSink(SootMethod method) {
        // 1. 先查缓存（快速路径）
        if (sinkMethods.contains(method)) {
            return true;
        }
        
        // 2. 动态匹配sink模式（慢速路径，但能识别新方法）
        SinkCategory category = matchSink(method);
        if (category != null) {
            // 找到新sink，加入缓存
            sinkMethods.add(method);
            sinkCategories.put(method, category);
            return true;
        }
        
        return false;
    }
    
    /**
     * 获取Sink分类
     */
    public SinkCategory getSinkCategory(SootMethod method) {
        return sinkCategories.getOrDefault(method, SinkCategory.OTHER);
    }
    
    // Getters
    public Set<SootMethod> getSourceMethods() { return new HashSet<>(sourceMethods); }
    public Set<SootMethod> getSinkMethods() { return new HashSet<>(sinkMethods); }
    
    /**
     * 获取统计信息
     */
    public String getStatistics() {
        Map<SinkCategory, Integer> counts = new HashMap<>();
        for (SinkCategory cat : sinkCategories.values()) {
            counts.put(cat, counts.getOrDefault(cat, 0) + 1);
        }
        
        return String.format("Sources=%d, Sinks=%d %s", 
            sourceMethods.size(), sinkMethods.size(), counts);
    }
}



