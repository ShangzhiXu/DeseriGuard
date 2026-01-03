package com.squirtle.core.taint.guided.model;

/**
 * Base对象的来源类型
 * 
 * 用于区分方法调用的base对象来自哪里，以决定是否需要展开CHA：
 * - FIELD：来自字段（可控） → 必须展开CHA
 * - PARAMETER：来自参数（部分可控） → 根据类型推导
 * - LOCAL_NEW：来自局部new（不可控） → 不展开CHA
 * - LOCAL_CONST：来自常量（不可控） → 不展开CHA
 * - STATIC_CALL：来自静态调用 → 无base
 * - UNKNOWN：未知来源 → 保守展开CHA
 */
public enum BaseOrigin {
    /**
     * 来自字段引用（this.field 或 obj.field）
     * 例如：LazyMap.factory.transform(...)
     * → 攻击者可以控制factory字段指向任意Transformer实现
     * → 必须展开CHA
     */
    FIELD,
    
    /**
     * 来自方法参数（普通参数，非this）
     * 例如：transform(Object input) 中的 input.getClass()
     * → 虽然值可控，但类型取决于声明类型
     * → 需要类型推导缩小范围
     */
    PARAMETER,
    
    /**
     * 来自this对象
     * 例如：LazyMap.get() 中的 this.factory.transform()
     * → this的类型是精确的（当前类）
     * → 应该用精确派发，只解析当前类及其父类
     */
    THIS,
    
    /**
     * 来自局部new表达式
     * 例如：new StringBuilder().append(...)
     * → 类型固定，不可控
     * → 不展开CHA
     */
    LOCAL_NEW,
    
    /**
     * 来自常量或StringConstant
     * 例如："hello".toString()
     * → 类型固定，不可控
     * → 不展开CHA
     */
    LOCAL_CONST,
    
    /**
     * 静态调用（无base）
     * 例如：Class.forName(...)
     * → 无需考虑base
     */
    STATIC_CALL,
    
    /**
     * 未知来源（保守处理）
     * 例如：复杂的数据流追踪失败
     * → 保守展开CHA
     */
    UNKNOWN
}

