package com.squirtle.gadget;

import java.util.*;

/**
 * Gadget链去重器（Flash LCS策略）
 * 
 * 使用最长公共子序列(LCS)计算相似度
 * 相似度 >= 阈值的链被认为是重复
 * 
 * @author BugTurtle
 */
public class GadgetChainDeduplicator {
    
    private final double lcsThreshold;
    
    public GadgetChainDeduplicator(double lcsThreshold) {
        this.lcsThreshold = lcsThreshold;
    }
    
    /**
     * 去重
     */
    public List<GadgetChain> deduplicate(List<GadgetChain> chains) {
        if (chains.isEmpty()) {
            return chains;
        }
        
        // 按source-sink对分组
        Map<String, List<GadgetChain>> groups = new HashMap<>();
        for (GadgetChain chain : chains) {
            String key = chain.getSource().getSignature() + "#" + chain.getSink().getSignature();
            groups.computeIfAbsent(key, k -> new ArrayList<>()).add(chain);
        }
        
        // 对每组进行LCS去重
        List<GadgetChain> unique = new ArrayList<>();
        for (List<GadgetChain> group : groups.values()) {
            unique.addAll(deduplicateGroup(group));
        }
        
        return unique;
    }
    
    /**
     * 对同一source-sink对的链进行去重
     */
    private List<GadgetChain> deduplicateGroup(List<GadgetChain> group) {
        if (group.size() <= 1) {
            return group;
        }
        
        List<GadgetChain> unique = new ArrayList<>();
        List<List<String>> uniqueSubs = new ArrayList<>();
        
        for (GadgetChain chain : group) {
            List<String> subSigs = chain.getSubSignatures();
            
            // 检查是否与已有链相似
            boolean isDuplicate = false;
            for (List<String> existing : uniqueSubs) {
                double similarity = computeLCS(subSigs, existing);
                if (similarity >= lcsThreshold) {
                    isDuplicate = true;
                    break;
                }
            }
            
            if (!isDuplicate) {
                unique.add(chain);
                uniqueSubs.add(subSigs);
            }
        }
        
        return unique;
    }
    
    /**
     * 计算LCS相似度（Flash算法）
     * 公开为public static，供在线去重使用
     */
    public static double computeLCS(List<String> list1, List<String> list2) {
        if (list1.isEmpty() || list2.isEmpty()) {
            return 0.0;
        }
        
        int lcsLength = computeLCSLength(list1, list2);
        return (2.0 * lcsLength) / (list1.size() + list2.size());
    }
    
    /**
     * 计算LCS长度（动态规划）
     */
    private static int computeLCSLength(List<String> list1, List<String> list2) {
        int m = list1.size();
        int n = list2.size();
        int[][] dp = new int[m + 1][n + 1];
        
        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                if (list1.get(i - 1).equals(list2.get(j - 1))) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
                }
            }
        }
        
        return dp[m][n];
    }
}

