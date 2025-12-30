package com.example.Utils;

import com.thoughtworks.xstream.XStream;

public class XStreamUtil {

    public static <T> String serialize(T o) throws Exception {
        XStream xStream = new XStream();
        String xml = xStream.toXML(o);
        return xml;
    }

    public static Object deserialize(String xml) throws Exception {
        XStream xStream = new XStream();
        return xStream.fromXML(xml);
    }

}
