package com.squirtle.config;

import soot.*;
import soot.options.Options;
import java.io.File;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.Logger;

/**
 * Soot JAR包分析配置工具类（Flash风格全量加载）
 * 
 * 核心设计：
 *   - 采用Flash的whole-program策略，通过soot.Main.run()自动递归加载所有依赖类
 *   - 零业务假设，不预设"重要类"或"危险库"，保证普适性
 *   - 包含JDK Gadget类（JNDI、XSLT等），确保反序列化链完整检测
 * 
 * 主要API：
 *   - initializeSootForLibraryAnalysis(String) - 初始化Soot并加载目标JAR及所有依赖
 *   - getAllLoadedClasses() - 获取所有已加载的类（9000+类，用于全程序分析）
 * 
 * @author BugTurtle Team
 * @version 3.0 (Flash完全一致，极简架构)
 */
public class SootJarAnalysisConfig {
    
    private static final Logger logger = Logger.getLogger(SootJarAnalysisConfig.class.getName());
    
    /**
     * 是否过滤非Serializable类（保留字段，当前版本未使用）
     * 
     * 注：采用Flash全量加载策略后，此过滤逻辑已废弃。
     * 保留此字段仅为向后兼容，实际不影响类加载。
     */
    private static boolean filterNonSerializable = true;
    
    /**
     * 设置是否过滤非Serializable类（已废弃，保留向后兼容）
     * 
     * @param filter 此参数已不生效
     * @deprecated 采用Flash全量加载策略，不再使用过滤逻辑
     */
    @Deprecated
    public static void setFilterNonSerializable(boolean filter) {
        filterNonSerializable = filter;
        logger.info("警告：filterNonSerializable已废弃（设置为" + filter + "但不生效）");
    }
    
    /**
     * 获取当前filterNonSerializable设置（已废弃，保留向后兼容）
     * 
     * @return 过滤设置（实际不生效）
     * @deprecated 采用Flash全量加载策略，不再使用过滤逻辑
     */
    @Deprecated
    public static boolean isFilterNonSerializable() {
        return filterNonSerializable;
    }
    
    /**
     * 为库分析初始化Soot配置（Flash风格全量加载）
     * 
     * 加载策略（完全对齐Flash）：
     *   1. classpath配置：目标JAR + JDK rt.jar
     *   2. whole-program模式：启用Soot的全程序分析，自动递归加载所有依赖类
     *   3. Flash Dependency类：预加载JDK Gadget类（JNDI、XSLT、BadAttributeValueExpException等）
     *   4. soot.Main.run()：通过Soot入口触发自动依赖解析（从JAR中提取所有类名）
     * 
     * 核心优势：加载9000+类（vs Flash的9342类），零手动过滤，完全依赖Soot的依赖分析
     * 
     * @param libDir 库目录路径（例如："libs/target/CC3/"）
     * @throws IllegalArgumentException 如果目录不存在或无效
     */
    public static void initializeSootForLibraryAnalysis(String libDir) {
        if (libDir == null || libDir.trim().isEmpty()) {
            throw new IllegalArgumentException("库目录路径不能为空");
        }
        
        File dir = new File(libDir);
        if (!dir.exists()) {
            throw new IllegalArgumentException("库目录不存在: " + libDir);
        }
        
        if (!dir.isDirectory()) {
            throw new IllegalArgumentException("路径不是目录: " + libDir);
        }
        
        logger.info("==================== Flash风格自动加载 ====================");
        logger.info("开始为库分析初始化Soot配置（Flash模式）: " + libDir);
        
        // 1. 收集目标库的所有JAR
        List<String> targetJars = collectJarsFromDirectory(libDir);
        if (targetJars.isEmpty()) {
            throw new IllegalArgumentException("目录中没有找到JAR文件: " + libDir);
        }
        
        logger.info("找到 " + targetJars.size() + " 个目标JAR:");
        for (String jar : targetJars) {
            logger.info("  - " + new File(jar).getName());
        }
        
        // 2. 重置Soot环境
        G.reset();
        
        // 3. 构建classpath（目标库 + rt.jar）
        String classpath = buildLibraryClassPath(targetJars);
        
        // 4. 配置Soot选项（Flash风格，不设置classpath）
        configureSootOptionsFlashStyle();
        
        // 5. 添加Flash Dependency类中的JDK Gadget类（在soot.Main.run之前）
        addFlashDependencyClasses();
        
        // 6. 提取所有输入类名
        List<String> inputClassNames = extractAllClassNames(targetJars);
        logger.info("提取到 " + inputClassNames.size() + " 个JAR类");
        
        // 7. 构建soot.Main.run()的参数
        List<String> args = new ArrayList<>();
        args.add("-cp");
        args.add(classpath);
        args.addAll(inputClassNames);
        
        // 7. 调用soot.Main.run() - 让Soot自动递归加载所有依赖
        logger.info("调用 soot.Main.run() 自动加载所有依赖...");
        logger.info("   输入类数: " + inputClassNames.size());
        
        try {
            soot.Main.v().run(args.toArray(new String[0]));
        } catch (Exception e) {
            logger.warning("soot.Main.run()执行出错: " + e.getMessage());
            // 即使出错也继续，因为Scene可能已经加载了部分类
        }
        
        // 7.5. 强制解析关键构造函数sink（在whole-program分析完成后）
        forceResolveConstructorSinks();
        
        // 8. 统计加载结果
        logger.info("自动加载完成！");
        logSootStatistics();
    }
    
    /**
     * 收集目录下所有JAR文件
     * 
     * @param dirPath 目录路径
     * @return JAR文件绝对路径列表
     */
    private static List<String> collectJarsFromDirectory(String dirPath) {
        List<String> jars = new ArrayList<>();
        File dir = new File(dirPath);
        
        if (!dir.exists() || !dir.isDirectory()) {
            return jars;
        }
        
        File[] files = dir.listFiles((d, name) -> name.toLowerCase().endsWith(".jar"));
        if (files != null) {
            for (File file : files) {
                jars.add(file.getAbsolutePath());
            }
        }
        
        return jars;
    }
    
    /**
     * 构建库分析的classpath
     * 
     * @param targetJars 目标库JAR列表
     * @return 完整的classpath字符串
     */
    private static String buildLibraryClassPath(List<String> targetJars) {
        StringBuilder classpath = new StringBuilder();
        
        // 1. 添加目标库JARs
        for (int i = 0; i < targetJars.size(); i++) {
            if (i > 0) {
                classpath.append(File.pathSeparator);
            }
            classpath.append(targetJars.get(i));
        }
        
        // 2. 添加rt.jar（必需）
        String rtJar = "libs/JREs/jre1.8/rt.jar";
        File rtFile = new File(rtJar);
        if (!rtFile.exists()) {
            logger.warning("找不到rt.jar: " + rtJar + "，尝试使用系统JDK");
            // 回退到系统JDK
        String javaHome = System.getProperty("java.home");
        if (javaHome != null) {
                File systemRtJar = new File(javaHome, "lib" + File.separator + "rt.jar");
                if (systemRtJar.exists()) {
                    rtJar = systemRtJar.getAbsolutePath();
                    logger.info("使用系统rt.jar: " + rtJar);
                } else {
                    throw new IllegalStateException("无法找到rt.jar，请检查libs/JREs/jre1.8/rt.jar是否存在");
                }
            }
        }
        
        classpath.append(File.pathSeparator).append(rtJar);
        
        logger.info("构建的classpath包含 " + (targetJars.size() + 1) + " 个JAR文件");
        return classpath.toString();
    }
    
    /**
     * 添加关键JDK Gadget类
     * 
     * 这些类是常见的反序列化Gadget，但可能不被目标jar直接引用，
     * 需要在soot.Main.run()之前添加到Scene，让whole-program模式自动处理依赖
     */
    private static void addFlashDependencyClasses() {
        logger.info("添加关键JDK Gadget类...");
        
        String[] flashDependencyClasses = {
            // JNDI相关（JNDI注入链）
            "com.sun.jndi.ldap.LdapCtx",
            "javax.naming.InitialContext",
            
            // XSLT相关（CC3链及变种）
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter",
            "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl",
            "javax.xml.transform.Templates",
            
            // JDBC相关（JDBC反序列化链）
            "com.sun.rowset.JdbcRowSetImpl",
            "java.sql.Driver",
            "java.sql.DriverManager",
            
            // 反序列化Gadget类（CC5链等）
            "javax.management.BadAttributeValueExpException",
            
            // JavaBeans相关
            "java.beans.PropertyDescriptor",
            
            // 脚本引擎（ScriptEngine攻击）
            "javax.script.ScriptEngineManager",
            
            // RMI相关
            "sun.rmi.transport.tcp.TCPTransport",
            
            // Swing相关（SSRF链）
            "javax.swing.JEditorPane",
            
            // 网络相关（DNS泄露链）
            "sun.net.www.protocol.http.HttpCallerInfo",
            
            // 集合类（gadget source）
            "java.util.HashMap",
            "java.util.Hashtable",
            "java.util.HashSet",
            "java.util.PriorityQueue",
            "java.util.TreeMap",
            "java.util.TreeSet",
            "java.util.LinkedHashMap",
            "java.util.LinkedHashSet",
            "java.util.UUID",
            "java.util.Enumeration",
            "java.util.Comparator",
            "java.util.concurrent.ConcurrentSkipListMap",
            "java.util.concurrent.ConcurrentHashMap",
            
            // 动态代理
            "java.lang.reflect.InvocationHandler",
            "java.lang.reflect.Proxy",
            
            // URL/DNS 相关（URLDNS 链）
            "java.net.URL",
            "java.net.URLStreamHandler",
            "java.net.InetAddress"
        };
        
        int loaded = 0;
        for (String className : flashDependencyClasses) {
            try {
                Scene.v().addBasicClass(className, SootClass.SIGNATURES);
                loaded++;
                logger.fine("  添加依赖类: " + className);
            } catch (Exception e) {
                logger.warning("  无法添加依赖类 " + className + ": " + e.getMessage());
            }
        }
        
        logger.info("成功添加 " + loaded + "/" + flashDependencyClasses.length + " 个依赖类");
    }
    
    /**
     * 在soot.Main.run()之后强制解析关键构造函数sink
     * 
     * 某些JDK内部类（如TrAXFilter）可能需要在whole-program分析完成后
     * 才能正确解析其构造函数签名
     */
    public static void forceResolveConstructorSinks() {
        String[] criticalConstructors = {
            "<com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void <init>(javax.xml.transform.Templates)>",
            "<javax.swing.JEditorPane: void <init>(java.lang.String)>",
            "<sun.net.www.protocol.http.HttpCallerInfo: void <init>(java.net.URL)>",
            "<javax.script.ScriptEngineManager: void <init>()>"
        };
        
        int resolved = 0;
        for (String signature : criticalConstructors) {
            try {
                // 提取类名
                String className = signature.substring(signature.indexOf('<') + 1, signature.indexOf(':'));
                
                // 强制解析类（如果还未解析）
                SootClass clazz = Scene.v().forceResolve(className, SootClass.SIGNATURES);
                if (clazz != null) {
                    clazz.setApplicationClass();  // 标记为应用类，确保方法可见
                    
                    // 验证构造函数是否存在
                    try {
                        SootMethod method = Scene.v().getMethod(signature);
                        if (method != null && !method.isPhantom()) {
                            resolved++;
                        }
                    } catch (RuntimeException e) {
                        // 忽略
                    }
                }
            } catch (Exception e) {
                // 忽略
            }
        }
        
        logger.info("成功解析 " + resolved + "/4 个构造函数sink");
    }
    
    /**
     * 配置Soot选项（Flash风格）
     * 注意：不在这里设置classpath，由soot.Main.run()的-cp参数设置
     */
    private static void configureSootOptionsFlashStyle() {
        // Flash风格配置（不设置classpath）
        Options.v().set_prepend_classpath(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);         // 全程序分析，自动递归加载依赖
        Options.v().set_app(true);                   // 应用模式
        Options.v().set_src_prec(Options.src_prec_class);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_keep_line_number(true);
        Options.v().set_verbose(false);
        Options.v().set_no_writeout_body_releasing(true);
        
        // 排除JDK内部类（但仍会加载，只是标记为库类）
        Options.v().set_exclude(Arrays.asList(
            "jdk.*",          // JDK内部实现
            "apple.laf.*"     // macOS平台相关
        ));
        
        // Jimple优化选项
        Options.v().setPhaseOption("jb", "preserve-source-annotations:true");
        Options.v().setPhaseOption("jb", "model-lambdametafactory:false");
        Options.v().setPhaseOption("cg", "enabled:false");  // 禁用调用图构建（我们自己构建CHA）
        
        logger.info("✅ Soot选项配置完成（Flash风格）");
    }
    
    /**
     * 从JAR文件中提取所有类名
     * 
     * @param jarPaths JAR文件路径列表
     * @return 类名列表
     */
    private static List<String> extractAllClassNames(List<String> jarPaths) {
        List<String> classNames = new ArrayList<>();
        
        for (String jarPath : jarPaths) {
            try {
                logger.info("扫描JAR: " + new File(jarPath).getName());
                List<String> names = extractClassNamesFromJar(jarPath);
                classNames.addAll(names);
                logger.info("  找到 " + names.size() + " 个类");
                } catch (Exception e) {
                logger.warning("扫描JAR失败: " + jarPath + ", " + e.getMessage());
            }
        }
        
        return classNames;
    }
    
    /**
     * 从单个JAR文件中提取类名（模仿Flash的ClassNameExtractor）
     * 
     * @param jarPath JAR文件路径
     * @return 类名列表
     */
    private static List<String> extractClassNamesFromJar(String jarPath) throws Exception {
        List<String> classNames = new ArrayList<>();
        
        try (JarFile jar = new JarFile(new File(jarPath))) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                
                // 过滤掉META-INF和非class文件
                if (name.startsWith("META-INF") || !name.endsWith(".class")) {
                    continue;
                }
                
                // 转换为类名：com/example/Foo.class -> com.example.Foo
                String className = name.replaceAll("/", ".")
                                       .substring(0, name.length() - ".class".length());
                classNames.add(className);
            }
        }
        
        return classNames;
    }
    
    /**
     * 打印Soot统计信息
     */
    private static void logSootStatistics() {
        int applicationClassCount = Scene.v().getApplicationClasses().size();
        int totalClassCount = Scene.v().getClasses().size();
        
        logger.info("=== Soot加载统计 ===");
        logger.info("应用程序类数量: " + applicationClassCount);
        logger.info("总类数量: " + totalClassCount);
        
        // 记录前几个应用程序类作为样例
        logger.info("=== 应用程序类样例 ===");
        int count = 0;
        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            if (count < 5) {  // 只记录前5个
                logger.info("应用类: " + sootClass.getName() + " (方法数: " + sootClass.getMethodCount() + ")");
                count++;
            } else {
                logger.info("... 还有 " + (applicationClassCount - 5) + " 个应用程序类");
                break;
            }
        }
        logger.info("==================");
    }
    
    /**
     * 获取Scene中所有已加载的类（Flash全量分析策略）
     * 
     * 返回范围：应用类（~200个）+ 库类（~9000个）= 总计9000+类
     * 
     * 适用场景：
     *   - 反序列化Gadget链全量检测（覆盖所有可能的sink和跳板类）
     *   - 完整的调用图构建（包括JDK内部调用）
     *   - 需要分析JDK类参与的攻击链（JNDI、XSLT、Swing等）
     * 
     * @return 所有类集合（不包含Phantom类）
     */
    public static Set<SootClass> getAllLoadedClasses() {
        Set<SootClass> allClasses = new HashSet<>();
        
        // 添加所有应用类
        allClasses.addAll(Scene.v().getApplicationClasses());
        
        // 添加所有库类
        allClasses.addAll(Scene.v().getLibraryClasses());
        
        logger.info("getAllLoadedClasses: " + allClasses.size() + " 个类 (" +
                    Scene.v().getApplicationClasses().size() + " 应用类 + " +
                    Scene.v().getLibraryClasses().size() + " 库类)");
        
        return allClasses;
    }
    
}