package com.squirtle.test.deserializationtest;

import java.io.*;

/**
 * 测试用例：包含反序列化漏洞的类
 */
public class VulnerableClass implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String command;
    private Object data;
    
    public VulnerableClass(String command) {
        this.command = command;
    }
    
    /**
     * 自定义反序列化方法 - 存在安全风险
     */
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject(); // 正常反序列化
        
        // 危险操作：执行命令
        if (command != null) {
            try {
                Runtime.getRuntime().exec(command); // 命令执行漏洞!
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        // 危险操作：反射调用
        if (data != null) {
            try {
                data.getClass().getMethod("toString").invoke(data); // 反射调用
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
    private void writeObject(ObjectOutputStream oos) throws IOException {
        oos.defaultWriteObject();
    }
}
