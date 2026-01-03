package com.squirtle.core.loader;

import soot.Scene;
import soot.SootClass;
import soot.SourceLocator;

import java.io.File;
import java.util.*;
import java.util.logging.Logger;

/**
 * Serializable类加载器
 * 
 * 负责预加载所有Serializable类，确保：
 * 1. 找到所有readObject入口点
 * 2. CHA能在完整的类集合中分析
 * 3. 调用图构建从完整的入口开始
 * 
 * 策略：
 * - 遍历rt.jar和其他jar
 * - 过滤Serializable类
 * - 动态加载到Scene
 * 
 * @author BugTurtle
 * @version 1.0
 */
public class SerializableClassLoader {
    
    private static final Logger logger = Logger.getLogger(SerializableClassLoader.class.getName());
    
    // 缓存已枚举的类（避免重复扫描rt.jar）
    private static List<String> cachedRtJarClasses = null;
    
    /**
     * 预加载所有Serializable类
     * 
     * @param rtJarPath rt.jar路径
     * @return 新加载的类数量
     */
    public static int preloadSerializableClasses(String rtJarPath) {
        logger.info("🔥 开始预加载Serializable类（Flash策略）...");
        logger.info("   目标：找到所有readObject入口点");
        
        long startTime = System.currentTimeMillis();
        
        // 记录初始类数
        int initialClassCount = Scene.v().getClasses().size();
        logger.info("   初始Scene类数: " + initialClassCount);
        
        // 1. 枚举rt.jar中的所有类
        List<String> allClasses = enumerateRtJarClasses(rtJarPath);
        logger.info("   rt.jar中找到 " + allClasses.size() + " 个类");
        
        // 2. 过滤并加载Serializable类
        int loadedCount = 0;
        int skippedCount = 0;
        
        for (String className : allClasses) {
            try {
                // 检查是否已经在Scene中
                if (Scene.v().containsClass(className)) {
                    skippedCount++;
                    continue;
                }
                
                // 加载类
                SootClass sc = Scene.v().loadClassAndSupport(className);
                
                // 检查是否是Serializable
                if (isSerializable(sc)) {
                    loadedCount++;
                    
                    // 每500个类输出一次进度
                    if (loadedCount % 500 == 0) {
                        logger.info("   进度: 已加载 " + loadedCount + " 个Serializable类...");
                    }
                }
                
            } catch (Exception e) {
                // 忽略加载失败的类（phantom类等）
            }
        }
        
        long elapsedTime = System.currentTimeMillis() - startTime;
        
        // 3. 输出统计
        int finalClassCount = Scene.v().getClasses().size();
        logger.info("✅ 预加载完成!");
        logger.info("   新加载: " + loadedCount + " 个Serializable类");
        logger.info("   已存在: " + skippedCount + " 个类");
        logger.info("   总类数: " + initialClassCount + " → " + finalClassCount + 
                    " (+" + (finalClassCount - initialClassCount) + ")");
        logger.info("   耗时: " + (elapsedTime / 1000.0) + " 秒");
        
        return loadedCount;
    }
    
    /**
     * 枚举rt.jar中的所有类（带缓存）
     */
    private static List<String> enumerateRtJarClasses(String rtJarPath) {
        // 使用缓存避免重复扫描
        if (cachedRtJarClasses != null) {
            logger.info("   使用缓存的rt.jar类列表");
            return cachedRtJarClasses;
        }
        
        File rtJarFile = new File(rtJarPath);
        if (!rtJarFile.exists()) {
            logger.warning("⚠️  rt.jar不存在: " + rtJarPath);
            return Collections.emptyList();
        }
        
        logger.info("   正在扫描rt.jar: " + rtJarPath);
        
        try {
            // 使用Soot的SourceLocator获取所有类
            List<String> classes = SourceLocator.v().getClassesUnder(rtJarPath);
            
            // 缓存结果
            cachedRtJarClasses = classes;
            
            return classes;
        } catch (Exception e) {
            logger.warning("扫描rt.jar失败: " + e.getMessage());
            return Collections.emptyList();
        }
    }
    
    /**
     * 检查类是否实现了Serializable接口
     */
    private static boolean isSerializable(SootClass sootClass) {
        if (sootClass == null || sootClass.isPhantom()) {
            return false;
        }
        
        try {
            // 检查直接实现的接口
            for (SootClass interfaceClass : sootClass.getInterfaces()) {
                if ("java.io.Serializable".equals(interfaceClass.getName())) {
                    return true;
                }
            }
            
            // 递归检查父类
            if (sootClass.hasSuperclass()) {
                SootClass superClass = sootClass.getSuperclass();
                if (!"java.lang.Object".equals(superClass.getName())) {
                    return isSerializable(superClass);
                }
            }
            
            return false;
        } catch (Exception e) {
            // 某些类可能无法正确解析继承关系
            return false;
        }
    }
    
    /**
     * 预加载多个JAR中的Serializable类
     * 
     * @param jarPaths JAR路径列表（包括rt.jar和目标jar）
     * @return 新加载的类总数
     */
    public static int preloadSerializableClasses(List<String> jarPaths) {
        int totalLoaded = 0;
        
        for (String jarPath : jarPaths) {
            logger.info("正在处理JAR: " + jarPath);
            
            // 枚举JAR中的类
            List<String> classes = SourceLocator.v().getClassesUnder(jarPath);
            
            int loaded = 0;
            for (String className : classes) {
                try {
                    if (Scene.v().containsClass(className)) {
                        continue;
                    }
                    
                    SootClass sc = Scene.v().loadClassAndSupport(className);
                    
                    if (isSerializable(sc)) {
                        loaded++;
                        totalLoaded++;
                    }
                } catch (Exception e) {
                    // 忽略
                }
            }
            
            logger.info("   从此JAR加载: " + loaded + " 个Serializable类");
        }
        
        return totalLoaded;
    }
    
    /**
     * 清除缓存（用于测试）
     */
    public static void clearCache() {
        cachedRtJarClasses = null;
    }
}


