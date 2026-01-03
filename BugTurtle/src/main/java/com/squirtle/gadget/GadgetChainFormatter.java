package com.squirtle.gadget;

import soot.SootMethod;
import java.util.*;

/**
 * Gadget链格式化输出
 * 
 * @author BugTurtle
 */
public class GadgetChainFormatter {
    
    /**
     * 格式化为Flash风格输出
     */
    public static String toFlashStyle(GadgetChain chain) {
        StringBuilder sb = new StringBuilder();
        List<SootMethod> methods = chain.getMethods();
        
        for (int i = 0; i < methods.size(); i++) {
            SootMethod method = methods.get(i);
            sb.append(method.getSignature());
            
            if (i < methods.size() - 1) {
                sb.append("\n  → ");
            }
        }
        
        return sb.toString();
    }
    
    /**
     * 格式化为简洁输出
     */
    public static String toSimple(GadgetChain chain) {
        List<SootMethod> methods = chain.getMethods();
        return String.format("%s → ... (%d步) → %s [%s]",
            methods.get(0).getName(),
            chain.getLength(),
            methods.get(methods.size() - 1).getName(),
            chain.getCategory());
    }
    
    /**
     * 生成统计摘要
     */
    public static String generateSummary(List<GadgetChain> chains) {
        if (chains.isEmpty()) {
            return "未发现gadget链";
        }
        
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════\n");
        sb.append("📊 Gadget链搜索摘要\n");
        sb.append("═══════════════════════════════════════\n\n");
        
        // 总数
        sb.append(String.format("总链数: %d\n\n", chains.size()));
        
        // 长度分布
        Map<Integer, Integer> lengthDist = new HashMap<>();
        for (GadgetChain chain : chains) {
            int len = chain.getLength();
            lengthDist.put(len, lengthDist.getOrDefault(len, 0) + 1);
        }
        
        sb.append("长度分布:\n");
        List<Integer> lengths = new ArrayList<>(lengthDist.keySet());
        Collections.sort(lengths);
        for (int len : lengths) {
            sb.append(String.format("  %2d步: %d条链\n", len, lengthDist.get(len)));
        }
        sb.append("\n");
        
        // 分类分布
        Map<SourceSinkManager.SinkCategory, Integer> catDist = new HashMap<>();
        for (GadgetChain chain : chains) {
            SourceSinkManager.SinkCategory cat = chain.getCategory();
            catDist.put(cat, catDist.getOrDefault(cat, 0) + 1);
        }
        
        sb.append("分类分布:\n");
        for (Map.Entry<SourceSinkManager.SinkCategory, Integer> entry : catDist.entrySet()) {
            sb.append(String.format("  %-20s: %d条链\n", entry.getKey(), entry.getValue()));
        }
        
        return sb.toString();
    }
    
    /**
     * 输出Top N链
     */
    public static String formatTopChains(List<GadgetChain> chains, int topN) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n═══════════════════════════════════════\n");
        sb.append(String.format("🔝 Top %d Gadget链\n", Math.min(topN, chains.size())));
        sb.append("═══════════════════════════════════════\n\n");
        
        for (int i = 0; i < Math.min(topN, chains.size()); i++) {
            GadgetChain chain = chains.get(i);
            sb.append(String.format("【链 %d】长度=%d, 类别=%s\n", 
                i + 1, chain.getLength(), chain.getCategory()));
            sb.append(toFlashStyle(chain));
            sb.append("\n\n");
        }
        
        return sb.toString();
    }
}

