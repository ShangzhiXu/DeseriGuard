package com.squirtle.core.taint.guided.model;

/**
 * 🆕 问题1修复：参数来源信息
 * 
 * 用于精确追踪方法调用参数的来源，支持反向污点传播时正确映射到caller的污点需求
 * 
 * 文档设计：
 * - CALLER_PARAM：来自 caller 的第 paramIndex 个参数
 * - CALLER_THIS：来自 caller 的 this
 * - FIELD：来自字段（通过 this 访问）
 * - CONST：来自常量（不可控）
 * - UNKNOWN：未知来源（保守处理）
 */
public class ArgumentSource {
    
    /**
     * 来源类型
     */
    public enum Type {
        /**
         * 来自 caller 的第 paramIndex 个参数
         * 例如：B.bar(x) 中 x 来自 A.foo 的 param[2]
         * → 反向传播时需要 callerTaint.param[2] = true
         */
        CALLER_PARAM,
        
        /**
         * 来自 caller 的 this
         * 例如：B.bar(this) 或 B.bar(this.field)
         * → 反向传播时需要 callerTaint.this = true
         */
        CALLER_THIS,
        
        /**
         * 来自字段（通过 this 访问）
         * 例如：B.bar(this.iArgs)
         * → 反向传播时需要 callerTaint.this = true
         */
        FIELD,
        
        /**
         * 来自常量（不可控）
         * 例如：B.bar("constant")
         * → 不需要反向传播（不可控）
         */
        CONST,
        
        /**
         * 未知来源（保守处理）
         * → 反向传播时保守地传播到 this 和所有参数
         */
        UNKNOWN
    }
    
    private final Type type;
    private final int paramIndex;  // 仅当 type == CALLER_PARAM 时有效
    
    private ArgumentSource(Type type, int paramIndex) {
        this.type = type;
        this.paramIndex = paramIndex;
    }
    
    // ===== 工厂方法 =====
    
    /**
     * 创建来自 caller 参数的来源
     * @param index caller 的参数索引
     */
    public static ArgumentSource fromCallerParam(int index) {
        return new ArgumentSource(Type.CALLER_PARAM, index);
    }
    
    /**
     * 创建来自 caller 的 this 的来源
     */
    public static ArgumentSource fromCallerThis() {
        return new ArgumentSource(Type.CALLER_THIS, -1);
    }
    
    /**
     * 创建来自字段的来源
     */
    public static ArgumentSource fromField() {
        return new ArgumentSource(Type.FIELD, -1);
    }
    
    /**
     * 创建来自常量的来源
     */
    public static ArgumentSource fromConst() {
        return new ArgumentSource(Type.CONST, -1);
    }
    
    /**
     * 创建未知来源
     */
    public static ArgumentSource unknown() {
        return new ArgumentSource(Type.UNKNOWN, -1);
    }
    
    // ===== Getters =====
    
    public Type getType() {
        return type;
    }
    
    /**
     * 获取来源参数索引（仅当 type == CALLER_PARAM 时有效）
     */
    public int getParamIndex() {
        return paramIndex;
    }
    
    /**
     * 检查是否是可控来源
     */
    public boolean isControllable() {
        return type != Type.CONST;
    }
    
    /**
     * 转换为字符串格式（用于序列化到 CallEdge）
     * 格式：TYPE 或 TYPE:INDEX
     */
    public String toSerializedString() {
        if (type == Type.CALLER_PARAM) {
            return "CALLER_PARAM:" + paramIndex;
        }
        return type.name();
    }
    
    /**
     * 从序列化字符串解析
     */
    public static ArgumentSource fromSerializedString(String str) {
        if (str == null || str.isEmpty()) {
            return unknown();
        }
        
        if (str.startsWith("CALLER_PARAM:")) {
            try {
                int index = Integer.parseInt(str.substring("CALLER_PARAM:".length()));
                return fromCallerParam(index);
            } catch (NumberFormatException e) {
                return unknown();
            }
        }
        
        try {
            Type t = Type.valueOf(str);
            switch (t) {
                case CALLER_PARAM:
                    return unknown();  // 缺少索引，当作未知
                case CALLER_THIS:
                    return fromCallerThis();
                case FIELD:
                    return fromField();
                case CONST:
                    return fromConst();
                default:
                    return unknown();
            }
        } catch (IllegalArgumentException e) {
            // 兼容旧格式（BaseOrigin 的名称）
            switch (str) {
                case "PARAMETER":
                    return unknown();  // 旧格式没有索引，当作未知
                case "THIS":
                    return fromCallerThis();
                case "FIELD":
                    return fromField();
                case "LOCAL_CONST":
                    return fromConst();
                case "LOCAL_NEW":
                    return fromConst();  // 局部创建的对象也不可控
                default:
                    return unknown();
            }
        }
    }
    
    @Override
    public String toString() {
        if (type == Type.CALLER_PARAM) {
            return "ArgumentSource{CALLER_PARAM[" + paramIndex + "]}";
        }
        return "ArgumentSource{" + type + "}";
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ArgumentSource)) return false;
        ArgumentSource that = (ArgumentSource) o;
        return type == that.type && paramIndex == that.paramIndex;
    }
    
    @Override
    public int hashCode() {
        return 31 * type.hashCode() + paramIndex;
    }
}
