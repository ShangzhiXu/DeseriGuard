package com.squirtle.core.taint;

import soot.SootMethod;
import java.util.HashSet;
import java.util.Set;

/**
 * 🔥 修复问题24：统一的Source方法注册表
 * 
 * 两套污点分析系统（summary包和guided包）都使用这个统一的注册表，
 * 确保Source方法识别逻辑一致，避免漏报。
 * 
 * Source方法定义：
 * - 反序列化入口方法（产生攻击者可控的数据）
 * - 这些方法的返回值或参数应该被标记为污点
 */
public class SourceRegistry {
    
    private static final SourceRegistry INSTANCE = new SourceRegistry();
    
    // Source方法签名模式（支持通配符）
    private final Set<String> sourceSignaturePatterns = new HashSet<>();
    
    // Source类名（这些类的特定方法是Source）
    private final Set<String> sourceClassNames = new HashSet<>();
    
    private SourceRegistry() {
        initializeDefaultSources();
    }
    
    public static SourceRegistry v() {
        return INSTANCE;
    }
    
    /**
     * 初始化默认的Source方法
     */
    private void initializeDefaultSources() {
        // 1. ObjectInputStream的反序列化方法
        sourceSignaturePatterns.add("java.io.ObjectInputStream: java.lang.Object readObject()");
        sourceSignaturePatterns.add("java.io.ObjectInputStream: java.lang.Object readUnshared()");
        sourceSignaturePatterns.add("java.io.ObjectInputStream: java.io.ObjectInputStream$GetField readFields()");
        sourceSignaturePatterns.add("java.io.ObjectInputStream: java.lang.Object readObjectOverride()");
        
        // 2. ObjectInput接口方法
        sourceSignaturePatterns.add("java.io.ObjectInput: java.lang.Object readObject()");
        
        // 3. ObjectInputStream$GetField的字段读取方法
        sourceClassNames.add("java.io.ObjectInputStream$GetField");
        
        // 4. 反序列化入口方法签名模式（用于入口点识别）
        sourceSignaturePatterns.add(": void readObject(java.io.ObjectInputStream)");
        sourceSignaturePatterns.add(": void readExternal(java.io.ObjectInput)");
        sourceSignaturePatterns.add(": java.lang.Object readResolve()");
        sourceSignaturePatterns.add(": void readObjectNoData()");
    }
    
    /**
     * 判断方法是否是Source方法（产生污点的方法）
     * 
     * @param method 待检查的方法
     * @return true if 是Source方法
     */
    public boolean isSourceMethod(SootMethod method) {
        String sig = method.getSignature();
        String className = method.getDeclaringClass().getName();
        String methodName = method.getName();
        
        // 检查1：签名模式匹配
        for (String pattern : sourceSignaturePatterns) {
            if (sig.contains(pattern)) {
                return true;
            }
        }
        
        // 检查2：Source类的特定方法
        if (sourceClassNames.contains(className)) {
            // ObjectInputStream$GetField的读取方法
            if (className.equals("java.io.ObjectInputStream$GetField")) {
                return methodName.equals("get") ||           // Object get(String, Object)
                       methodName.equals("defaulted") ||     // boolean defaulted(String)
                       methodName.startsWith("get");         // getInt, getLong, etc.
            }
        }
        
        // 检查3：ObjectInputStream的其他读取方法
        if (className.equals("java.io.ObjectInputStream")) {
            return methodName.equals("readFields") ||
                   methodName.equals("readObject") ||
                   methodName.equals("readUnshared") ||
                   methodName.equals("readObjectOverride") ||
                   methodName.equals("defaultReadObject");
        }
        
        return false;
    }
    
    /**
     * 判断方法是否是反序列化入口方法
     * 
     * 入口方法 vs Source方法的区别：
     * - 入口方法：反序列化时被调用的方法（如readObject）
     * - Source方法：产生污点的方法（如ObjectInputStream.readObject()）
     * 
     * @param method 待检查的方法
     * @return true if 是反序列化入口方法
     */
    public boolean isDeserializationEntry(SootMethod method) {
        String methodName = method.getName();
        int paramCount = method.getParameterCount();
        
        // readObject(ObjectInputStream)
        if (methodName.equals("readObject") && paramCount == 1) {
            String paramType = method.getParameterType(0).toString();
            if (paramType.equals("java.io.ObjectInputStream")) {
                return true;
            }
        }
        
        // readExternal(ObjectInput)
        if (methodName.equals("readExternal") && paramCount == 1) {
            String paramType = method.getParameterType(0).toString();
            if (paramType.equals("java.io.ObjectInput")) {
                return true;
            }
        }
        
        // readResolve()
        if (methodName.equals("readResolve") && paramCount == 0) {
            return true;
        }
        
        // readObjectNoData()
        if (methodName.equals("readObjectNoData") && paramCount == 0) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 添加自定义Source方法签名模式
     * 
     * @param pattern 签名模式（支持部分匹配）
     */
    public void addSourcePattern(String pattern) {
        sourceSignaturePatterns.add(pattern);
    }
    
    /**
     * 添加自定义Source类
     * 
     * @param className 完整类名
     */
    public void addSourceClass(String className) {
        sourceClassNames.add(className);
    }
}
