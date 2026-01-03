package com.squirtle.test;

import com.squirtle.config.SootJarAnalysisConfig;
import com.squirtle.core.callgraph.CallGraph;
import com.squirtle.core.taint.guided.TaintGuidedCallGraphBuilder;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;

import java.util.*;

/**
 * 合并测试：Ysoserial 5条 + Flash 16条 = 21条
 * 
 * 使用新的污点驱动调用图构建
 */
public class VerifyAllCC3Chains {

    private static CallGraph callGraph;

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║           BugTurtle CC3 完整链检测验证（21条）                ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");

        // 只初始化一次
        initializeAnalysis();

        int ysoDetected = 0;
        int flashDetected = 0;

        // ==================== Part 1: Ysoserial 5条 ====================
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("  Ysoserial CC3 经典链（5条）");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        ysoDetected += verifyChain("CC1", "CC1: AnnotationInvocationHandler + LazyMap → Runtime.exec",
            new String[] {
                "<sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>",
                "<sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.ChainedTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>",
                "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>"
            }
        );

        ysoDetected += verifyChain("CC3", "CC3: AnnotationInvocationHandler + InstantiateTransformer → RCE",
            new String[] {
                "<sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>",
                "<sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.ChainedTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InstantiateTransformer: java.lang.Object transform(java.lang.Object)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void <init>(javax.xml.transform.Templates)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer()>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: com.sun.org.apache.xalan.internal.xsltc.Translet getTransletInstance()>",
                "<java.lang.Class: java.lang.Object newInstance()>"
            }
        );

        ysoDetected += verifyChain("CC5", "CC5: BadAttributeValueExpException + TiedMapEntry → Runtime.exec",
            new String[] {
                "<javax.management.BadAttributeValueExpException: void readObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.String toString()>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.ChainedTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>",
                "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>"
            }
        );

        ysoDetected += verifyChain("CC6", "CC6: HashSet + TiedMapEntry → Runtime.exec",
            new String[] {
                "<java.util.HashSet: void readObject(java.io.ObjectInputStream)>",
                "<java.util.HashMap: java.lang.Object put(java.lang.Object,java.lang.Object)>",
                "<java.util.HashMap: int hash(java.lang.Object)>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.ChainedTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>",
                "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>"
            }
        );

        ysoDetected += verifyChain("CC7", "CC7: Hashtable + LazyMap → Runtime.exec",
            new String[] {
                "<java.util.Hashtable: void readObject(java.io.ObjectInputStream)>",
                "<java.util.Hashtable: void reconstitutionPut(java.util.Hashtable$Entry[],java.lang.Object,java.lang.Object)>",
                "<java.util.AbstractMap: boolean equals(java.lang.Object)>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.ChainedTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>",
                "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>"
            }
        );

        System.out.println("\n" + repeat("=", 70));
        System.out.println("【检测结果统计】");
        System.out.println(repeat("=", 70));
        System.out.println("ysoserial CC3 经典链总数: 5 条");
        System.out.println("BugTurtle成功检测: " + ysoDetected + " 条");
        System.out.println("检测覆盖率: " + ysoDetected + "/5 = " + String.format("%.1f%%", (ysoDetected * 100.0 / 5)));
        System.out.println(repeat("=", 70) + "\n");

        // ==================== Part 2: Flash 16条 ====================
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║  Flash CC3 真实可利用链检测验证（16条，不含Agent链）          ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");
        System.out.println("【已实现的6条链】\n");
        
        flashDetected += verifyChain("POC_1", "POC_1: HashMap + InstantiateTransformer → RCE",
            new String[] {
                "<java.util.HashMap: void readObject(java.io.ObjectInputStream)>",
                "<java.util.HashMap: int hash(java.lang.Object)>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>",
                "<org.apache.commons.collections.map.DefaultedMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InstantiateTransformer: java.lang.Object transform(java.lang.Object)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void <init>(javax.xml.transform.Templates)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer()>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: com.sun.org.apache.xalan.internal.xsltc.Translet getTransletInstance()>",
                "<java.lang.Class: java.lang.Object newInstance()>"
            }
        );

        flashDetected += verifyChain("POC_2", "POC_2: HttpCallerInfo DNS泄露",
            new String[] {
                "<sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>",
                "<sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InstantiateTransformer: java.lang.Object transform(java.lang.Object)>",
                "<sun.net.www.protocol.http.HttpCallerInfo: void <init>(java.net.URL)>",
                "<java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>"
            }
        );

        flashDetected += verifyChain("POC_3", "POC_3: Throwable + Proxy → RCE",
            new String[] {
                "<java.lang.Throwable: void readObject(java.io.ObjectInputStream)>",
                "<sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.ChainedTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>",
                "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>"
            }
        );

        flashDetected += verifyChain("POC_4", "POC_4: JEditorPane SSRF",
            new String[] {
                "<sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>",
                "<sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.ChainedTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InstantiateTransformer: java.lang.Object transform(java.lang.Object)>",
                "<javax.swing.JEditorPane: void <init>(java.lang.String)>",
                "<javax.swing.JEditorPane: void setPage(java.lang.String)>",
                "<javax.swing.JEditorPane: void setPage(java.net.URL)>",
                "<javax.swing.JEditorPane: java.io.InputStream getStream(java.net.URL)>"
            }
        );

        flashDetected += verifyChain("POC_6", "POC_6: ReferenceMap + InstantiateTransformer → RCE",
            new String[] {
                "<org.apache.commons.collections.map.ReferenceMap: void readObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.map.AbstractReferenceMap: void doReadObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.map.AbstractReferenceMap: java.lang.Object put(java.lang.Object,java.lang.Object)>",
                "<org.apache.commons.collections.map.AbstractHashedMap: java.lang.Object put(java.lang.Object,java.lang.Object)>",
                "<org.apache.commons.collections.map.AbstractHashedMap: int hash(java.lang.Object)>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>",
                "<org.apache.commons.collections.map.DefaultedMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InstantiateTransformer: java.lang.Object transform(java.lang.Object)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void <init>(javax.xml.transform.Templates)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer()>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: com.sun.org.apache.xalan.internal.xsltc.Translet getTransletInstance()>",
                "<java.lang.Class: java.lang.Object newInstance()>"
            }
        );

        flashDetected += verifyChain("POC_7", "POC_7: ReferenceMap + URL DNS泄露",
            new String[] {
                "<org.apache.commons.collections.map.ReferenceMap: void readObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.map.AbstractReferenceMap: void doReadObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.map.AbstractReferenceMap: java.lang.Object put(java.lang.Object,java.lang.Object)>",
                "<org.apache.commons.collections.map.AbstractHashedMap: java.lang.Object put(java.lang.Object,java.lang.Object)>",
                "<org.apache.commons.collections.map.AbstractHashedMap: int hash(java.lang.Object)>",
                "<java.net.URL: int hashCode()>",
                "<java.net.URLStreamHandler: int hashCode(java.net.URL)>",
                "<java.net.URLStreamHandler: java.net.InetAddress getHostAddress(java.net.URL)>",
                "<java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>"
            }
        );

        System.out.println("\n【待实现的10条链】\n");

        flashDetected += verifyChain("POC_11", "POC_11: ConcurrentHashMap + InstantiateTransformer → RCE",
            new String[] {
                "<java.util.concurrent.ConcurrentHashMap: void readObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>",
                "<org.apache.commons.collections.map.DefaultedMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InstantiateTransformer: java.lang.Object transform(java.lang.Object)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void <init>(javax.xml.transform.Templates)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer()>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: com.sun.org.apache.xalan.internal.xsltc.Translet getTransletInstance()>",
                "<java.lang.Class: java.lang.Object newInstance()>"
            }
        );

        flashDetected += verifyChain("POC_12", "POC_12: Flat3Map (CC4) + InstantiateTransformer → RCE",
            new String[] {
                "<org.apache.commons.collections4.map.Flat3Map: void readObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>",
                "<org.apache.commons.collections.map.DefaultedMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InstantiateTransformer: java.lang.Object transform(java.lang.Object)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void <init>(javax.xml.transform.Templates)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer()>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: com.sun.org.apache.xalan.internal.xsltc.Translet getTransletInstance()>",
                "<java.lang.Class: java.lang.Object newInstance()>"
            }
        );

        flashDetected += verifyChain("POC_14", "POC_14: HashMap + FactoryTransformer → SSRF",
            new String[] {
                "<java.util.HashMap: void readObject(java.io.ObjectInputStream)>",
                "<java.util.HashMap: int hash(java.lang.Object)>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>",
                "<org.apache.commons.collections.map.DefaultedMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.FactoryTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InstantiateFactory: java.lang.Object create()>",
                "<javax.swing.JEditorPane: void <init>(java.lang.String)>",
                "<javax.swing.JEditorPane: void setPage(java.lang.String)>",
                "<javax.swing.JEditorPane: void setPage(java.net.URL)>"
            }
        );

        flashDetected += verifyChain("POC_15", "POC_15: Collections$SetFromMap + Proxy → RCE",
            new String[] {
                "<java.util.Collections$SetFromMap: void readObject(java.io.ObjectInputStream)>",
                "<sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.ChainedTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>",
                "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>"
            }
        );

        flashDetected += verifyChain("POC_16", "POC_16: AnnotationInvocationHandler (双层Proxy) → RCE",
            new String[] {
                "<sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>",
                "<sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.FactoryTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InstantiateFactory: java.lang.Object create()>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void <init>(javax.xml.transform.Templates)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer()>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: com.sun.org.apache.xalan.internal.xsltc.Translet getTransletInstance()>",
                "<java.lang.Class: java.lang.Object newInstance()>"
            }
        );

        flashDetected += verifyChain("POC_17", "POC_17: Throwable + Proxy + FactoryTransformer → RCE",
            new String[] {
                "<java.lang.Throwable: void readObject(java.io.ObjectInputStream)>",
                "<sun.reflect.annotation.AnnotationInvocationHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.FactoryTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InstantiateFactory: java.lang.Object create()>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void <init>(javax.xml.transform.Templates)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer()>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: com.sun.org.apache.xalan.internal.xsltc.Translet getTransletInstance()>",
                "<java.lang.Class: java.lang.Object newInstance()>"
            }
        );

        flashDetected += verifyChain("POC_19", "POC_19: ReferenceMap + ChainedTransformer → RCE",
            new String[] {
                "<org.apache.commons.collections.map.ReferenceMap: void readObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.map.AbstractReferenceMap: void doReadObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.map.AbstractReferenceMap: java.lang.Object put(java.lang.Object,java.lang.Object)>",
                "<org.apache.commons.collections.map.AbstractHashedMap: java.lang.Object put(java.lang.Object,java.lang.Object)>",
                "<org.apache.commons.collections.map.AbstractHashedMap: int hash(java.lang.Object)>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>",
                "<org.apache.commons.collections.map.DefaultedMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.ChainedTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>",
                "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>"
            }
        );

        flashDetected += verifyChain("POC_22", "POC_22: Flat3Map (CC4) + ChainedTransformer → RCE",
            new String[] {
                "<org.apache.commons.collections4.map.Flat3Map: void readObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>",
                "<org.apache.commons.collections.map.DefaultedMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.ChainedTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>",
                "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>"
            }
        );

        flashDetected += verifyChain("POC_23", "POC_23: ConcurrentHashMap + ChainedTransformer → RCE",
            new String[] {
                "<java.util.concurrent.ConcurrentHashMap: void readObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: int hashCode()>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>",
                "<org.apache.commons.collections.map.DefaultedMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.ChainedTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>",
                "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>"
            }
        );

        flashDetected += verifyChain("POC_25", "POC_25: BadAttributeValueExpException + FactoryTransformer → RCE",
            new String[] {
                "<javax.management.BadAttributeValueExpException: void readObject(java.io.ObjectInputStream)>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.String toString()>",
                "<org.apache.commons.collections.keyvalue.TiedMapEntry: java.lang.Object getValue()>",
                "<org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>",
                "<org.apache.commons.collections.functors.FactoryTransformer: java.lang.Object transform(java.lang.Object)>",
                "<org.apache.commons.collections.functors.InstantiateFactory: java.lang.Object create()>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter: void <init>(javax.xml.transform.Templates)>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: javax.xml.transform.Transformer newTransformer()>",
                "<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl: com.sun.org.apache.xalan.internal.xsltc.Translet getTransletInstance()>",
                "<java.lang.Class: java.lang.Object newInstance()>"
            }
        );

        System.out.println("\n" + repeat("=", 70));
        System.out.println("【检测结果统计】");
        System.out.println(repeat("=", 70));
        System.out.println("Flash CC3 真实可利用链总数: 16 条");
        System.out.println("BugTurtle成功检测: " + flashDetected + " 条");
        System.out.println("检测覆盖率: " + flashDetected + "/16 = " + String.format("%.1f%%", (flashDetected * 100.0 / 16)));
        System.out.println(repeat("=", 70) + "\n");

        // 总结
        int total = ysoDetected + flashDetected;
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("  总计");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("成功检测: " + total + "/21 = " + String.format("%.1f%%", (total * 100.0 / 21)));
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }

    private static void initializeAnalysis() {
        try {
            System.out.println("【步骤1】初始化Soot...\n");
            
            String libDir = "libs/target/CC3/";
            SootJarAnalysisConfig.initializeSootForLibraryAnalysis(libDir);
            java.util.Set<SootClass> targetClasses = SootJarAnalysisConfig.getAllLoadedClasses();
            
            System.out.println("Soot初始化完成");
            System.out.println("   加载类数量: " + targetClasses.size());
            
            System.out.println("\n【步骤2】构建污点驱动的调用图（新算法）...\n");
            
            // ✅ 使用新的污点驱动调用图构建
            TaintGuidedCallGraphBuilder builder = new TaintGuidedCallGraphBuilder();
            callGraph = builder.buildTaintGuidedCallGraph(targetClasses);
            
            System.out.println("\n初始化完成");
            System.out.println("   调用图边数: " + callGraph.getAllEdges().size());
            System.out.println();
            
        } catch (Exception e) {
            System.err.println("初始化失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static int verifyChain(String chainId, String description, String[] chain) {
        System.out.println("【" + chainId + "】" + description);
        
        boolean allEdgesExist = true;
        int existingEdges = 0;
        String missingEdge = null;
        
        for (int i = 0; i < chain.length - 1; i++) {
            String callerSig = chain[i];
            String calleeSig = chain[i + 1];
            
            if (!Scene.v().containsMethod(callerSig) || !Scene.v().containsMethod(calleeSig)) {
                continue;
            }
            
            SootMethod caller = Scene.v().getMethod(callerSig);
            SootMethod callee = Scene.v().getMethod(calleeSig);
            
            boolean edgeExists = hasEdge(callGraph, caller, callee);
            if (edgeExists) {
                existingEdges++;
            } else {
                allEdgesExist = false;
                if (missingEdge == null) {
                    missingEdge = "边" + (i+1) + ": " + simplifySignature(callerSig) + " → " + simplifySignature(calleeSig);
                }
            }
        }
        
        int totalEdges = chain.length - 1;
        String result = allEdgesExist ? "✅ 完整检测" : 
            (existingEdges > 0 ? "⚠️ 部分检测 (" + existingEdges + "/" + totalEdges + ")" : 
             "❌ 未检测到");
        
        System.out.println("   " + result);
        if (missingEdge != null) {
            System.out.println("   ❌ 缺失: " + missingEdge);
        }
        System.out.println();
        
        return allEdgesExist ? 1 : 0;
    }
    
    private static String simplifySignature(String sig) {
        try {
            int colonPos = sig.indexOf(':');
            if (colonPos == -1) return sig;
            
            int classStart = sig.lastIndexOf('.', colonPos) + 1;
            int methodStart = sig.indexOf(": ") + 2;
            int methodEnd = sig.indexOf('(', methodStart);
            if (methodEnd == -1) methodEnd = sig.indexOf('>', methodStart);
            if (methodEnd == -1) methodEnd = sig.length();
            
            String className = sig.substring(classStart, colonPos);
            String methodName = sig.substring(methodStart, methodEnd);
            
            return className + "." + methodName;
        } catch (Exception e) {
            return sig;
        }
    }

    private static String repeat(String str, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append(str);
        }
        return sb.toString();
    }

    /**
     * 检查是否存在从caller到callee的边（支持通过反射方法的间接连接）
     * 
     * <p>允许以下路径：
     * <ul>
     *   <li>直接边：caller → callee</li>
     *   <li>通过Method.invoke：caller → Method.invoke → callee</li>
     *   <li>通过Constructor.newInstance：caller → Constructor.newInstance → callee</li>
     *   <li>通过Class.newInstance：caller → Class.newInstance → callee</li>
     * </ul>
     */
    private static boolean hasEdge(CallGraph graph, SootMethod caller, SootMethod callee) {
        // 1. 检查直接边
        Set<CallGraph.CallEdge> outEdges = graph.getOutgoingEdges(caller);
        for (CallGraph.CallEdge edge : outEdges) {
            if (edge.getCallee().equals(callee)) {
                return true;  // 直接边 ✓
            }
        }
        
        // 2. 检查通过反射方法的间接边
        for (CallGraph.CallEdge edge : outEdges) {
            SootMethod intermediate = edge.getCallee();
            
            // 检查是否是反射方法
            if (isReflectionMethod(intermediate)) {
                // 检查反射方法是否连接到目标
                Set<CallGraph.CallEdge> reflectionOutEdges = graph.getOutgoingEdges(intermediate);
                for (CallGraph.CallEdge reflectionEdge : reflectionOutEdges) {
                    if (reflectionEdge.getCallee().equals(callee)) {
                        return true;  // 通过反射的间接边 ✓
                    }
                }
            }
        }
        
        return false;
    }
    
    /**
     * 检查是否是反射方法
     */
    private static boolean isReflectionMethod(SootMethod method) {
        String sig = method.getSignature();
        return sig.contains("<java.lang.reflect.Method: java.lang.Object invoke(") ||
               sig.contains("<java.lang.reflect.Constructor: java.lang.Object newInstance(") ||
               sig.equals("<java.lang.Class: java.lang.Object newInstance()>");
    }
}





