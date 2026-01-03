package com.squirtle.core.taint.guided.model;

import soot.Local;
import soot.Type;
import java.util.*;

/**
 * 局部变量类型映射
 * 
 * 追踪局部变量的可能类型和定义来源，用于精化CHA和判断是否展开
 */
public class LocalTypeMap {
    private final Map<Local, Set<Type>> typeMap;
    private final Map<Local, BaseOrigin> originMap;
    
    public LocalTypeMap() {
        this.typeMap = new HashMap<>();
        this.originMap = new HashMap<>();
    }
    
    public void replaceType(Local local, Type type) {
        Set<Type> types = new HashSet<>();
        types.add(type);
        typeMap.put(local, types);
    }
    
    public void replaceTypes(Local local, Set<Type> types) {
        typeMap.put(local, new HashSet<>(types));
    }
    
    public void replaceType(Local local, Type type, BaseOrigin origin) {
        Set<Type> types = new HashSet<>();
        types.add(type);
        typeMap.put(local, types);
        originMap.put(local, origin);
    }
    
    public void replaceTypes(Local local, Set<Type> types, BaseOrigin origin) {
        typeMap.put(local, new HashSet<>(types));
        originMap.put(local, origin);
    }
    
    public Set<Type> getTypes(Local local) {
        return typeMap.getOrDefault(local, Collections.emptySet());
    }
    
    public BaseOrigin getOrigin(Local local) {
        return originMap.getOrDefault(local, BaseOrigin.UNKNOWN);
    }
}

