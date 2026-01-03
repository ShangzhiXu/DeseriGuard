package com.squirtle.core.taint.guided.model;

import soot.Type;
import java.util.*;

/**
 * 类型约束信息
 * 
 * 用于精化CHA的类型推断结果
 */
public class TypeConstraints {
    private final Set<Type> possibleTypes;
    private final TypePrecision precision;
    
    public TypeConstraints(Set<Type> possibleTypes, TypePrecision precision) {
        this.possibleTypes = new HashSet<>(possibleTypes);
        this.precision = precision;
    }
    
    // Getters
    public Set<Type> getPossibleTypes() {
        return possibleTypes;
    }
    
    public TypePrecision getPrecision() {
        return precision;
    }
    
    @Override
    public String toString() {
        return String.format("TypeConstraints{precision=%s, types=%s}",
                precision, possibleTypes);
    }
}









