package com.squirtle.gadget;

import java.io.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * Gadget链输出管理器
 * 
 * 功能：
 * 1. 将gadget链输出到文件
 * 2. 支持Flash风格的格式
 * 3. 支持按长度分层输出
 * 
 * @author BugTurtle
 */
public class GadgetChainOutputWriter {
    
    private static final Logger logger = Logger.getLogger(GadgetChainOutputWriter.class.getName());
    
    private final String outputPath;
    private final boolean enableTiering;  // 是否按长度分层输出
    
    public GadgetChainOutputWriter(String outputPath) {
        this(outputPath, false);
    }
    
    public GadgetChainOutputWriter(String outputPath, boolean enableTiering) {
        this.outputPath = outputPath;
        this.enableTiering = enableTiering;
    }
    
    /**
     * 输出gadget链到文件
     */
    public void write(List<GadgetChain> chains) throws IOException {
        if (enableTiering) {
            writeTiered(chains);
        } else {
            writeToFile(chains, outputPath);
        }
    }
    
    /**
     * 单文件输出（Flash风格）
     */
    private void writeToFile(List<GadgetChain> chains, String filepath) throws IOException {
        File file = new File(filepath);
        file.getParentFile().mkdirs();
        
        try (PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(file)))) {
            for (GadgetChain chain : chains) {
                writeChain(chain, writer);
            }
            
            // 输出统计信息
            writer.println("total gadget chains : " + chains.size());
            writer.flush();
            
            logger.info("已输出 " + chains.size() + " 条gadget链到: " + filepath);
        }
    }
    
    /**
     * 分层输出
     */
    private void writeTiered(List<GadgetChain> chains) throws IOException {
        // 按长度分组
        Map<String, List<GadgetChain>> tiered = new LinkedHashMap<>();
        tiered.put("short", new ArrayList<>());    // 2-4步
        tiered.put("medium", new ArrayList<>());   // 5-8步
        tiered.put("long", new ArrayList<>());     // 9-12步
        
        for (GadgetChain chain : chains) {
            int len = chain.getLength();
            if (len <= 4) {
                tiered.get("short").add(chain);
            } else if (len <= 8) {
                tiered.get("medium").add(chain);
            } else {
                tiered.get("long").add(chain);
            }
        }
        
        // 输出每一层
        File baseFile = new File(outputPath);
        String baseName = baseFile.getName().replace(".txt", "");
        String baseDir = baseFile.getParent() != null ? baseFile.getParent() : ".";
        
        for (Map.Entry<String, List<GadgetChain>> entry : tiered.entrySet()) {
            String tier = entry.getKey();
            List<GadgetChain> tierChains = entry.getValue();
            
            if (!tierChains.isEmpty()) {
                String tierPath = baseDir + File.separator + baseName + "_" + tier + ".txt";
                writeToFile(tierChains, tierPath);
            }
        }
    }
    
    /**
     * 输出单条链（Flash格式）
     * 
     * 格式：
     * <方法签名>
     * <方法签名>
     * ...
     * <sink签名>
     * (空行)
     */
    private void writeChain(GadgetChain chain, PrintWriter writer) {
        List<String> signatures = chain.getMethodSignatures();
        
        for (String sig : signatures) {
            writer.println(sig);
        }
        
        // 空行分隔
        writer.println();
    }
    
    /**
     * 输出带注释的链条（可选的详细格式）
     */
    public void writeDetailed(List<GadgetChain> chains, String filepath) throws IOException {
        File file = new File(filepath);
        file.getParentFile().mkdirs();
        
        try (PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(file)))) {
            writer.println("================================================================");
            writer.println("BugTurtle Gadget Chain Analysis Report");
            writer.println("================================================================");
            writer.println();
            
            // 按长度排序（短链优先）
            List<GadgetChain> sorted = new ArrayList<>(chains);
            sorted.sort(Comparator.comparingInt(GadgetChain::getLength));
            
            int index = 1;
            for (GadgetChain chain : sorted) {
                writer.println("【Chain #" + index + "】");
                writer.println("Length: " + chain.getLength());
                writer.println("Source: " + chain.getSource().getSignature());
                writer.println("Sink: " + chain.getSink().getSignature() + " [" + chain.getCategory() + "]");
                writer.println("Path:");
                
                List<String> sigs = chain.getMethodSignatures();
                for (int i = 0; i < sigs.size(); i++) {
                    writer.println("  " + (i + 1) + ". " + sigs.get(i));
                }
                
                writer.println();
                writer.println("----------------------------------------------------------------");
                writer.println();
                index++;
            }
            
            writer.println("================================================================");
            writer.println("Total Chains: " + chains.size());
            writer.println("================================================================");
            writer.flush();
            
            logger.info("已输出详细报告到: " + filepath);
        }
    }
}






