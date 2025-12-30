package com.example.Utils;

import bsh.XThis;
import com.caucho.bytecode.JField;
import sun.reflect.ReflectionFactory;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ReflectionUtil {

    public static void setField(Object object, String name, Object value) throws Exception {
        Class clazz = object.getClass();
        Field field = getField(clazz, name);
        field.setAccessible(true);
        field.set(object, value);
    }

    public static Object getField(Object object, String name) throws Exception {
        Class clazz = object.getClass();
        Field field = getField(clazz, name);
        field.setAccessible(true);
        return field.get(object);
    }

    private static Field getField(Class clz, String name) throws Exception {
        Field f = null;
        try {
            f = clz.getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            Class superClass = clz.getSuperclass();
            if (superClass != null) f = getField(superClass, name);
        }
        return f;
    }

    public static HashMap<Object, Object> makeMap(Object... v) throws Exception {
        HashMap<Object, Object> s = new HashMap<>();
        ReflectionUtil.setField(s, "size", v.length);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        } catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tb = Array.newInstance(nodeC, v.length);
        for (int i = 0; i < v.length; i++) {
            Array.set(tb, i, nodeCons.newInstance(0, v[i], v[i], null));
        }
        ReflectionUtil.setField(s, "table", tb);
        return s;
    }

    public static TreeMap<Object, Object> makeTree(Object v1, Object v2) throws Exception {
        TreeMap<Object, Object> s = new TreeMap<>();
        ReflectionUtil.setField(s, "size", 2);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.TreeMap$Node");
        } catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.TreeMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);
        Object entry1 = nodeCons.newInstance(v1, "value1", null);
        Object entry2 = nodeCons.newInstance(v2, "value2", entry1);

        setField(s, "root", entry2);
        return s;
    }

    public static ConcurrentHashMap<Object, Object> makeConcurrentMap(Object... v) throws Exception {
        ConcurrentHashMap<Object, Object> s = new ConcurrentHashMap<>();
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.concurrent.ConcurrentHashMap$Node");
        } catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.concurrent.ConcurrentHashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tb = Array.newInstance(nodeC, v.length);
        for (int i = 0; i < v.length; i++) {
            Array.set(tb, i, nodeCons.newInstance(0, v[i], v[i], null));
        }
        ReflectionUtil.setField(s, "table", tb);
        return s;
    }

    public static Hashtable makeTable(Object v) throws Exception {
        Hashtable table = new Hashtable();
        ReflectionUtil.setField(table, "count", 1);
        Class entryClz = Class.forName("java.util.Hashtable$Entry");
        Constructor entryConstr = entryClz.getDeclaredConstructor(int.class, Object.class, Object.class, entryClz);
        entryConstr.setAccessible(true);

        Object tb = Array.newInstance(entryClz, 1);
        Array.set(tb, 0, entryConstr.newInstance("key".hashCode(), v, "value", null));
        ReflectionUtil.setField(table, "table", tb);
        return table;
    }

    public static <T> T createWithoutConstructor(Class<T> classToCreate) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        return createWithConstructor(classToCreate, Object.class, new Class[0], new Object[0]);
    }

    public static <T> T createWithConstructor(Class<T> classToCreate, Class<? super T> constructorClass, Class<?>[] consArgTypes, Object[] consArgs) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Constructor<? super T> objCons = constructorClass.getDeclaredConstructor(consArgTypes);
        objCons.setAccessible(true);
        Constructor<?> sc = ReflectionFactory.getReflectionFactory().newConstructorForSerialization(classToCreate, objCons);
        sc.setAccessible(true);
        return (T) sc.newInstance(consArgs);
    }

    public static Object createObject(String className, Class[] argTypes, Object[] argValues) throws Exception {
        Class clz = Class.forName(className);
        Constructor c = clz.getDeclaredConstructor(argTypes);
        c.setAccessible(true);
        return c.newInstance(argValues);
    }
}
