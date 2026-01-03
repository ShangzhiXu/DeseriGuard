package com.squirtle.core.taint.guided.model;

/**
 * 类型精度级别
 */
public enum TypePrecision {
    EXACT,           // new/cast表达式
    FIELD_TYPE,      // 字段类型
    RETURN_TYPE,     // 方法返回类型
    PARAM_TYPE,      // 参数类型
    DECLARED_TYPE,   // 声明类型
    UNKNOWN          // 无法推断
}









