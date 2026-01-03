package com.squirtle.test.deserializationtest;

import java.io.*;

/**
 * 测试反序列化漏洞检测的主类
 */
public class DeserializationTest {
    
    public static void main(String[] args) {
        System.out.println("开始反序列化测试...");
        
        // 场景1：直接反序列化
        deserializeFromFile("data.ser");
        
        // 场景2：从网络输入反序列化
        deserializeFromNetwork();
        
        // 场景3：处理用户上传的序列化数据
        processUserData();
    }
    
    /**
     * 从文件反序列化 - 目标方法
     */
    public static void deserializeFromFile(String filename) {
        try {
            FileInputStream fis = new FileInputStream(filename);
            ObjectInputStream ois = new ObjectInputStream(fis);
            
            // 关键调用：这里会触发所有Serializable类的readObject方法
            Object obj = ois.readObject(); // 目标调用点!
            
            ois.close();
            fis.close();
            
            System.out.println("反序列化完成: " + obj);
        } catch (Exception e) {
            System.err.println("反序列化失败: " + e.getMessage());
        }
    }
    
    /**
     * 从网络反序列化
     */
    public static void deserializeFromNetwork() {
        try {
            // 模拟网络输入
            ByteArrayInputStream bis = new ByteArrayInputStream(new byte[0]);
            ObjectInputStream ois = new ObjectInputStream(bis);
            
            Object data = ois.readObject(); // 另一个目标调用点!
            
            ois.close();
        } catch (Exception e) {
            System.err.println("网络反序列化失败: " + e.getMessage());
        }
    }
    
    /**
     * 处理用户数据
     */
    public static void processUserData() {
        // 嵌套调用场景
        handleUserInput("user_data.ser");
    }
    
    private static void handleUserInput(String data) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(data.getBytes());
            ObjectInputStream ois = new ObjectInputStream(bis);
            
            // 第三个目标调用点
            Object userObj = ois.readObject();
            
            ois.close();
        } catch (Exception e) {
            System.err.println("用户数据处理失败: " + e.getMessage());
        }
    }
}
