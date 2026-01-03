package com.squirtle.core.taint.summary;

import soot.SootMethod;
import java.util.Arrays;

/**
 * 方法污点摘要（Method Taint Summary）
 * 
 * 记录每个方法的污点传播特性，是Summary-based污点分析的核心数据结构。
 * 
 * 对应Flash污点传播规则中的全局符号：
 * - taintedParameters[i] ↔ τ(pᵢ) - 第i个参数是否污点
 * - taintedThis ↔ τ(g_this) - this参数是否污点
 * - taintedReturn ↔ τ(g_ret) - 返回值是否污点
 * 
 * @see docs/减少UNKNOWN边的方案.md
 * @author BugTurtle
 * @version 2.0 - Summary-based Taint Analysis
 */
public class MethodTaintSummary {
    
    /** 所属方法 */
    private final SootMethod method;
    
    /** 参数污点状态数组（τ(p₀), τ(p₁), ...） */
    private boolean[] taintedParameters;
    
    /** this参数污点状态（τ(g_this)），只对实例方法有意义 */
    private boolean taintedThis;
    
    /** 返回值污点状态（τ(g_ret)） */
    private boolean taintedReturn;
    
    /** 版本号，用于检测变化 */
    private int version;
    
    /**
     * 构造函数 - 创建空的摘要
     * 
     * @param method 方法
     */
    public MethodTaintSummary(SootMethod method) {
        this.method = method;
        this.taintedParameters = new boolean[method.getParameterCount()];
        this.taintedThis = false;
        this.taintedReturn = false;
        this.version = 0;
    }
    
    // ========== Getters ==========
    
    public SootMethod getMethod() {
        return method;
    }
    
    public boolean isParameterTainted(int index) {
        if (index < 0 || index >= taintedParameters.length) {
            throw new IndexOutOfBoundsException("参数索引超出范围: " + index);
        }
        return taintedParameters[index];
    }
    
    public boolean isThisTainted() {
        return taintedThis;
    }
    
    public boolean isReturnTainted() {
        return taintedReturn;
    }
    
    public int getVersion() {
        return version;
    }
    
    public int getParameterCount() {
        return taintedParameters.length;
    }
    
    // ========== Setters ==========
    
    /**
     * 设置参数污点状态
     * 
     * @param index 参数索引
     * @param value 污点状态
     * @return 是否发生变化
     */
    public boolean setParameterTainted(int index, boolean value) {
        if (index < 0 || index >= taintedParameters.length) {
            throw new IndexOutOfBoundsException("参数索引超出范围: " + index);
        }
        
        boolean oldValue = taintedParameters[index];
        if (oldValue != value) {
            taintedParameters[index] = value;
            version++;
            return true;
        }
        return false;
    }
    
    /**
     * 设置this污点状态
     * 
     * @param value 污点状态
     * @return 是否发生变化
     */
    public boolean setThisTainted(boolean value) {
        boolean oldValue = this.taintedThis;
        if (oldValue != value) {
            this.taintedThis = value;
            version++;
            return true;
        }
        return false;
    }
    
    /**
     * 设置返回值污点状态
     * 
     * @param value 污点状态
     * @return 是否发生变化
     */
    public boolean setReturnTainted(boolean value) {
        boolean oldValue = this.taintedReturn;
        if (oldValue != value) {
            this.taintedReturn = value;
            version++;
            return true;
        }
        return false;
    }
    
    // ========== 核心方法 ==========
    
    /**
     * 检测摘要是否相对于旧版本发生变化
     * 
     * 用于触发worklist更新（[Return-Side-Effect]规则）
     * 
     * @param old 旧版本摘要
     * @return 是否发生变化
     */
    public boolean hasChanged(MethodTaintSummary old) {
        if (this.method != old.method) {
            throw new IllegalArgumentException("不同方法的summary不能比较");
        }
        
        // 检查this污点
        if (this.taintedThis != old.taintedThis) {
            return true;
        }
        
        // 检查返回值污点
        if (this.taintedReturn != old.taintedReturn) {
            return true;
        }
        
        // 检查参数污点（数组长度应该相同）
        if (this.taintedParameters.length != old.taintedParameters.length) {
            throw new IllegalStateException("同一方法的参数数量不应该变化");
        }
        
        for (int i = 0; i < taintedParameters.length; i++) {
            if (this.taintedParameters[i] != old.taintedParameters[i]) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 合并另一个摘要（使用OR操作）
     * 
     * 实现污点的传播规则：τ(x) = τ(x) ∨ τ(y)
     * 
     * @param other 另一个摘要
     * @return 是否发生变化
     */
    public boolean merge(MethodTaintSummary other) {
        if (this.method != other.method) {
            throw new IllegalArgumentException("只能合并同一方法的summary");
        }
        
        boolean changed = false;
        
        // 合并this污点
        if (!this.taintedThis && other.taintedThis) {
            this.taintedThis = true;
            changed = true;
        }
        
        // 合并返回值污点
        if (!this.taintedReturn && other.taintedReturn) {
            this.taintedReturn = true;
            changed = true;
        }
        
        // 合并参数污点
        for (int i = 0; i < taintedParameters.length; i++) {
            if (!this.taintedParameters[i] && other.taintedParameters[i]) {
                this.taintedParameters[i] = true;
                changed = true;
            }
        }
        
        if (changed) {
            version++;
        }
        
        return changed;
    }
    
    /**
     * 深拷贝
     * 
     * @return 克隆对象
     */
    @Override
    public MethodTaintSummary clone() {
        MethodTaintSummary copy = new MethodTaintSummary(this.method);
        copy.taintedParameters = Arrays.copyOf(this.taintedParameters, this.taintedParameters.length);
        copy.taintedThis = this.taintedThis;
        copy.taintedReturn = this.taintedReturn;
        copy.version = this.version;
        return copy;
    }
    
    /**
     * 转换为可读字符串（用于调试）
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("MethodTaintSummary{");
        sb.append("method=").append(method.getSignature());
        sb.append(", params=").append(Arrays.toString(taintedParameters));
        sb.append(", this=").append(taintedThis);
        sb.append(", return=").append(taintedReturn);
        sb.append(", version=").append(version);
        sb.append('}');
        return sb.toString();
    }
}






