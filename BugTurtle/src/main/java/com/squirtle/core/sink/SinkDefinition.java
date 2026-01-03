package com.squirtle.core.sink;

import com.squirtle.core.taint.guided.model.MethodLevelTaint;
import soot.SootMethod;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Sink定义（对齐Flash）
 * 
 * <p>表示一个危险方法（sink）及其可控性约束。
 * 
 * <p><b>可控性约束索引约定</b>（对齐Flash的ContrUtil）：
 * <ul>
 *   <li><b>-1</b>: base（this对象）必须可控</li>
 *   <li><b>0, 1, 2...</b>: param0, param1, param2... 必须可控</li>
 * </ul>
 * 
 * <p><b>示例</b>：
 * <pre>
 * // Runtime.exec(String cmd)
 * // 签名: &lt;java.lang.Runtime: java.lang.Process exec(java.lang.String)&gt;
 * // 约束: [0] → param0(cmd)必须可控
 * new SinkDefinition(
 *     "&lt;java.lang.Runtime: java.lang.Process exec(java.lang.String)&gt;",
 *     Arrays.asList(0)
 * );
 * 
 * // ProcessBuilder.start()
 * // 签名: &lt;java.lang.ProcessBuilder: java.lang.Process start()&gt;
 * // 约束: [-1] → base(ProcessBuilder实例)必须可控
 * new SinkDefinition(
 *     "&lt;java.lang.ProcessBuilder: java.lang.Process start()&gt;",
 *     Arrays.asList(-1)
 * );
 * 
 * // FileOutputStream.write(byte[])
 * // 签名: &lt;java.io.FileOutputStream: void write(byte[])&gt;
 * // 约束: [-1, 0] → base和param0都必须可控
 * new SinkDefinition(
 *     "&lt;java.io.FileOutputStream: void write(byte[])&gt;",
 *     Arrays.asList(-1, 0)
 * );
 * </pre>
 * 
 * @see FlashAlignedSinkRegistry
 * @see MethodLevelTaint
 * @author BugTurtle
 */
public class SinkDefinition {
    
    /** 完整的Soot方法签名 */
    private final String signature;
    
    /** 可控性约束：-1=base, 0=param0, 1=param1, ... */
    private final List<Integer> requiredTaintedIndices;
    
    /** Sink类别（用于分类统计） */
    private final SinkCategory category;
    
    /**
     * 构造Sink定义
     * 
     * @param signature 完整的Soot方法签名（如 &lt;java.lang.Runtime: java.lang.Process exec(java.lang.String)&gt;）
     * @param requiredTaintedIndices 可控性约束索引列表
     * @param category Sink类别
     */
    public SinkDefinition(String signature, List<Integer> requiredTaintedIndices, SinkCategory category) {
        this.signature = Objects.requireNonNull(signature, "signature cannot be null");
        this.requiredTaintedIndices = new ArrayList<>(Objects.requireNonNull(requiredTaintedIndices, "requiredTaintedIndices cannot be null"));
        this.category = Objects.requireNonNull(category, "category cannot be null");
    }
    
    /**
     * 检查方法是否匹配此sink定义
     * 
     * @param method 待检查的方法
     * @return true如果方法签名完全匹配
     */
    public boolean matches(SootMethod method) {
        if (method == null) {
            return false;
        }
        return signature.equals(method.getSignature());
    }
    
    /**
     * 检查污点是否满足此sink的可控性约束
     * 
     * <p><b>检查规则</b>：
     * <ul>
     *   <li>如果约束要求 base(-1) 可控，则检查 {@link MethodLevelTaint#isThisTainted()}</li>
     *   <li>如果约束要求 param[i] 可控，则检查 {@link MethodLevelTaint#isParamTainted(int)}</li>
     *   <li>所有约束都必须满足才返回 true</li>
     * </ul>
     * 
     * <p><b>示例</b>：
     * <pre>
     * // Runtime.exec(String cmd) 的约束是 [0]
     * SinkDefinition sink = ...;
     * MethodLevelTaint taint = ...; // param0 = true (可控)
     * 
     * boolean satisfied = sink.isTaintSatisfied(taint);
     * // → 检查 taint.isParamTainted(0) → true → 满足约束 ✓
     * </pre>
     * 
     * @param taint 方法入口的污点状态
     * @return true如果所有约束都满足，false如果有任何约束不满足
     */
    public boolean isTaintSatisfied(MethodLevelTaint taint) {
        if (taint == null) {
            return false;
        }
        
        for (Integer requiredIndex : requiredTaintedIndices) {
            if (requiredIndex == -1) {
                // base必须可控
                if (!taint.isThisTainted()) {
                    return false;
                }
            } else {
                // param[requiredIndex]必须可控
                if (!taint.isParamTainted(requiredIndex)) {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    // ========== Getters ==========
    
    public String getSignature() {
        return signature;
    }
    
    public List<Integer> getRequiredTaintedIndices() {
        return new ArrayList<>(requiredTaintedIndices);
    }
    
    public SinkCategory getCategory() {
        return category;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SinkDefinition)) return false;
        
        SinkDefinition that = (SinkDefinition) o;
        return signature.equals(that.signature);
    }
    
    @Override
    public int hashCode() {
        return signature.hashCode();
    }
    
    @Override
    public String toString() {
        return String.format("Sink{signature=%s, constraints=%s, category=%s}", 
                signature, requiredTaintedIndices, category);
    }
    
    /**
     * Sink类别枚举（对齐Flash的7大类）
     */
    public enum SinkCategory {
        /** 命令执行 */
        COMMAND_EXECUTION("Command Execution"),
        
        /** JNDI注入 */
        JNDI_INJECTION("JNDI Injection"),
        
        /** 类加载/实例化 */
        CLASS_LOADING("Class Loading"),
        
        /** 脚本执行 */
        SCRIPT_EXECUTION("Script Execution"),
        
        /** 文件操作 */
        FILE_OPERATION("File Operation"),
        
        /** 网络/数据库 */
        NETWORK_DATABASE("Network/Database"),
        
        /** RMI/RPC */
        RMI_RPC("RMI/RPC"),
        
        /** XSLT字节码执行（TemplatesImpl） */
        XSLT_BYTECODE("XSLT Bytecode Execution");
        
        private final String displayName;
        
        SinkCategory(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
        
        @Override
        public String toString() {
            return displayName;
        }
    }
}










