# BugTurtle 测试库说明

## 📁 目录结构

```
libs/
├── target/              # 17个第三方反序列化漏洞库
│   ├── CC3/            # Commons Collections 3.2.1 ⭐ 最常用
│   ├── CC4/            # Commons Collections 4.0
│   ├── CB/             # Commons Beanutils 1.9.3
│   ├── C3P0/           # C3P0连接池
│   ├── BeanShell/      # BeanShell脚本引擎
│   ├── Rome/           # RSS处理库
│   ├── SnakeYaml/      # YAML解析库
│   ├── AspectJweaver/  # AspectJ
│   ├── Click/          # Click框架
│   ├── FileUpload/     # Commons FileUpload
│   ├── JavassistWeld/  # Javassist + Weld
│   ├── JBoss/          # JBoss Interceptor
│   ├── MozillaRhino/   # JavaScript引擎
│   ├── MyFace/         # JSF实现
│   ├── Vaadin/         # Vaadin框架
│   ├── Wicket/         # Wicket框架
│   └── WildFly/        # WildFly连接器
├── JREs/
│   └── jre1.8/         # JDK 1.8基础类（HashMap等）
│       ├── rt.jar      # 核心运行时库 ⭐ 必需
│       ├── jce.jar     # 加密扩展
│       └── ... (其他JDK jar)
└── BasicDependency/    # 辅助类（引用所有JDK gadget类）
    └── Dependency.class

```

## 🎯 使用方式

### 1. 选择要测试的库

```java
// 示例：测试Commons Collections 3
String targetLib = "libs/target/CC3/";

// 示例：测试SnakeYaml
String targetLib = "libs/target/SnakeYaml/";
```

### 2. 配置分析（需要修改SootJarAnalysisConfig.java）

```java
public static void analyzeLibrary(String libDir) {
    // libDir: 例如 "libs/target/CC3/"
    
    // 1. 收集该目录下所有JAR
    List<String> jars = collectJarsFromDir(libDir);
    
    // 2. 添加rt.jar到classpath
    String rtJar = "libs/JREs/jre1.8/rt.jar";
    
    // 3. 添加BasicDependency辅助类
    String basicDep = "libs/BasicDependency/";
    
    // 4. 配置Soot
    Options.v().set_process_dir(jars);
    String cp = String.join(File.pathSeparator, jars) 
              + File.pathSeparator + rtJar
              + File.pathSeparator + basicDep;
    Options.v().set_soot_classpath(cp);
    
    // 5. 运行分析
    // ...
}
```

## 📊 库清单

| 库名 | JAR文件 | 已知Gadget链 | 推荐测试 |
|------|---------|-------------|----------|
| **CC3** | commons-collections-3.2.1.jar | ✅ 多条 | ⭐⭐⭐⭐⭐ |
| **CC4** | commons-collections4-4.0.jar | ✅ 多条 | ⭐⭐⭐⭐ |
| **CB** | commons-beanutils-1.9.3.jar | ✅ 多条 | ⭐⭐⭐⭐ |
| **C3P0** | c3p0-0.9.5.2.jar | ✅ 有 | ⭐⭐⭐ |
| **Rome** | rome-1.0.jar | ✅ 有 | ⭐⭐⭐ |
| **SnakeYaml** | snakeyaml-1.27.jar | ✅ 有 | ⭐⭐⭐ |
| 其他 | ... | 可能有 | ⭐⭐ |

## ⚠️ 重要文件

### rt.jar (必需)
- **路径**: `libs/JREs/jre1.8/rt.jar`
- **作用**: 包含所有JDK核心类（HashMap, HashSet, ObjectInputStream等）
- **大小**: ~60MB
- **必须**: 任何分析都需要它

### Dependency.class (推荐)
- **路径**: `libs/BasicDependency/Dependency.class`
- **作用**: 引用所有重要的JDK gadget类，确保它们被Soot加载
- **包含类**: 
  - TrAXFilter
  - TemplatesImpl
  - JdbcRowSetImpl
  - BadAttributeValueExpException
  - PropertyDescriptor
  - 等等

## 💡 快速开始

推荐从**CC3**开始测试（最经典的gadget库）：

```bash
# 1. 确认文件存在
ls libs/target/CC3/commons-collections-3.2.1.jar
ls libs/JREs/jre1.8/rt.jar
ls libs/BasicDependency/Dependency.class

# 2. 修改你的测试代码，指向这个目录
# 3. 运行BugTurtle分析
```

## 📝 与Flash的区别

| 项目 | Flash | BugTurtle |
|------|-------|-----------|
| **目录结构** | `java-benchmarks/JDV/target/` | `libs/target/` |
| **配置文件** | ✅ 每个库有config.yml | ❌ 不需要yml |
| **使用方式** | YAML配置 | Java代码配置 |
| **JAR包** | ✅ 相同 | ✅ 相同（直接复用） |

## 🔍 下一步

1. ✅ 已完成：复制所有库和JREs
2. ✅ 已完成：删除无用的yml文件
3. ✅ 已完成：保留BasicDependency辅助类
4. ⏭️ 下一步：修改`SootJarAnalysisConfig.java`支持这个目录结构
5. ⏭️ 测试：选择CC3进行第一次测试










