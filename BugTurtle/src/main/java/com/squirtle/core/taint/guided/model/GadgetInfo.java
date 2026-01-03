package com.squirtle.core.taint.guided.model;

import com.squirtle.core.sink.SinkDefinition;
import soot.SootMethod;
import soot.Unit;

import java.util.Objects;

/**
 * Gadget信息
 * 
 * <p>记录一次成功到达sink的路径信息，包括：
 * <ul>
 *   <li>调用者方法（caller）</li>
 *   <li>Sink方法（危险方法）</li>
 *   <li>调用位置（call site）</li>
 *   <li>污点状态（可控性信息）</li>
 *   <li>Sink定义（类别和约束）</li>
 * </ul>
 * 
 * <p><b>使用场景</b>：
 * <pre>
 * // 在TaintGuidedCallGraphBuilder中记录
 * if (sinkRegistry.isSinkWithTaint(target, targetTaint)) {
 *     GadgetInfo gadget = new GadgetInfo(caller, target, callSite, targetTaint, sinkDef);
 *     discoveredGadgets.add(gadget);
 * }
 * </pre>
 * 
 * @author BugTurtle
 */
public class GadgetInfo {
    
    /** 调用者方法 */
    private final SootMethod caller;
    
    /** Sink方法（危险方法） */
    private final SootMethod sink;
    
    /** 调用位置 */
    private final Unit callSite;
    
    /** 污点状态（目标方法的入口污点） */
    private final MethodLevelTaint taint;
    
    /** Sink定义 */
    private final SinkDefinition sinkDefinition;
    
    /**
     * 构造Gadget信息
     * 
     * @param caller 调用者方法
     * @param sink Sink方法
     * @param callSite 调用位置
     * @param taint 污点状态
     * @param sinkDefinition Sink定义
     */
    public GadgetInfo(SootMethod caller, SootMethod sink, Unit callSite, 
                     MethodLevelTaint taint, SinkDefinition sinkDefinition) {
        this.caller = Objects.requireNonNull(caller, "caller cannot be null");
        this.sink = Objects.requireNonNull(sink, "sink cannot be null");
        this.callSite = Objects.requireNonNull(callSite, "callSite cannot be null");
        this.taint = Objects.requireNonNull(taint, "taint cannot be null");
        this.sinkDefinition = Objects.requireNonNull(sinkDefinition, "sinkDefinition cannot be null");
    }
    
    // ========== Getters ==========
    
    public SootMethod getCaller() {
        return caller;
    }
    
    public SootMethod getSink() {
        return sink;
    }
    
    public Unit getCallSite() {
        return callSite;
    }
    
    public MethodLevelTaint getTaint() {
        return taint;
    }
    
    public SinkDefinition getSinkDefinition() {
        return sinkDefinition;
    }
    
    public SinkDefinition.SinkCategory getSinkCategory() {
        return sinkDefinition.getCategory();
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof GadgetInfo)) return false;
        
        GadgetInfo that = (GadgetInfo) o;
        return caller.equals(that.caller) &&
               sink.equals(that.sink) &&
               callSite.equals(that.callSite);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(caller, sink, callSite);
    }
    
    @Override
    public String toString() {
        return String.format("Gadget{%s -> %s (%s)}", 
                caller.getSignature(), 
                sink.getSignature(),
                sinkDefinition.getCategory());
    }
}










