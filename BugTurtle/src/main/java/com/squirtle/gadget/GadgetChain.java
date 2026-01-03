package com.squirtle.gadget;

import com.squirtle.core.callgraph.CallGraph;
import soot.SootMethod;

import java.util.*;

/**
 * Gadget链表示
 * 
 * 存储从source到sink的完整调用链
 * 
 * @author BugTurtle
 */
public class GadgetChain {
    
    private final List<CallGraph.CallEdge> edges;  // 调用边序列（sink→source）
    private final SootMethod source;               // 起始方法（readObject等）
    private final SootMethod sink;                 // 危险方法（exec等）
    private final SourceSinkManager.SinkCategory category;  // sink类别
    
    public GadgetChain(List<CallGraph.CallEdge> edges, SootMethod source, 
                      SootMethod sink, SourceSinkManager.SinkCategory category) {
        this.edges = new ArrayList<>(edges);
        this.source = source;
        this.sink = sink;
        this.category = category;
    }
    
    /**
     * 获取链长度
     */
    public int getLength() {
        return edges.size();
    }
    
    /**
     * 获取方法序列（source→sink顺序）
     */
    public List<SootMethod> getMethods() {
        List<SootMethod> methods = new ArrayList<>();
        
        if (edges.isEmpty()) {
            return methods;
        }
        
        // edges是sink→source反向存储的
        // 需要反转并正确构建：source → ... → sink
        
        // 1. 添加source（最后一条边的caller）
        methods.add(source);
        
        // 2. 反向遍历edges，添加每条边的callee
        for (int i = edges.size() - 1; i >= 0; i--) {
            methods.add(edges.get(i).getCallee());
        }
        
        return methods;
    }
    
    /**
     * 获取方法签名序列
     */
    public List<String> getMethodSignatures() {
        List<String> sigs = new ArrayList<>();
        for (SootMethod m : getMethods()) {
            sigs.add(m.getSignature());
        }
        return sigs;
    }
    
    /**
     * 获取子签名序列（用于去重）
     */
    public List<String> getSubSignatures() {
        List<String> subs = new ArrayList<>();
        for (SootMethod m : getMethods()) {
            subs.add(m.getSubSignature());
        }
        return subs;
    }
    
    // Getters
    public List<CallGraph.CallEdge> getEdges() { return new ArrayList<>(edges); }
    public SootMethod getSource() { return source; }
    public SootMethod getSink() { return sink; }
    public SourceSinkManager.SinkCategory getCategory() { return category; }
    
    @Override
    public String toString() {
        return String.format("GadgetChain{length=%d, %s → ... → %s [%s]}", 
            getLength(), source.getName(), sink.getName(), category);
    }
}

