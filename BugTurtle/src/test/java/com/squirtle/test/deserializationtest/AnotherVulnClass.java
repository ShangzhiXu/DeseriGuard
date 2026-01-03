package com.squirtle.test.deserializationtest;

import java.io.*;
import java.lang.reflect.Method;

/**
 * 另一个包含反序列化漏洞的类
 */
public class AnotherVulnClass implements Serializable {
    private static final long serialVersionUID = 2L;
    
    private String className;
    private String methodName;
    
    /**
     * 更危险的readObject方法
     */
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        
        // 动态类加载和方法调用
        if (className != null && methodName != null) {
            try {
                Class<?> clazz = Class.forName(className);
                Method method = clazz.getMethod(methodName);
                method.invoke(null); // 静态方法调用
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
