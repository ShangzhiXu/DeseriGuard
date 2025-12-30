//package com.mchange.v2.naming;
//
//import com.mchange.v2.log.MLevel;
//import com.mchange.v2.log.MLog;
//import com.mchange.v2.log.MLogger;
//import com.mchange.v2.ser.IndirectlySerialized;
//import com.mchange.v2.ser.Indirector;
//
//import javax.naming.*;
//import java.io.IOException;
//import java.io.InvalidObjectException;
//import java.util.Hashtable;
//import java.util.Properties;
//
//public class ReferenceIndirector implements Indirector {
//    static final MLogger logger = MLog.getLogger(ReferenceIndirector.class);
//    Name name;
//    Name contextName;
//    Hashtable environmentProperties;
//
//    public ReferenceIndirector() {
//    }
//
//    public Name getName() {
//        return this.name;
//    }
//
//    public void setName(Name var1) {
//        this.name = var1;
//    }
//
//    public Name getNameContextName() {
//        return this.contextName;
//    }
//
//    public void setNameContextName(Name var1) {
//        this.contextName = var1;
//    }
//
//    public Hashtable getEnvironmentProperties() {
//        return this.environmentProperties;
//    }
//
//    public void setEnvironmentProperties(Hashtable var1) {
//        this.environmentProperties = var1;
//    }
//
//    public IndirectlySerialized indirectForm(Object var1) throws Exception {
//        Properties properties = new Properties();
//        CompoundName compoundName = new CompoundName("ldap://xxx", properties);
//        this.contextName = compoundName;
//        Reference var2 = ((Referenceable)var1).getReference();
//        return new ReferenceSerialized(var2, this.name, this.contextName, this.environmentProperties);
//    }
//
//    private static class ReferenceSerialized implements IndirectlySerialized {
//        Reference reference;
//        Name name;
//        Name contextName;
//        Hashtable env;
//
//        ReferenceSerialized(Reference var1, Name var2, Name var3, Hashtable var4) {
//            this.reference = var1;
//            this.name = var2;
//            this.contextName = var3;
//            this.env = var4;
//        }
//
//        public Object getObject() throws ClassNotFoundException, IOException {
//            try {
//                InitialContext var1;
//                if (this.env == null) {
//                    var1 = new InitialContext();
//                } else {
//                    var1 = new InitialContext(this.env);
//                }
//
//                Context var2 = null;
//                if (this.contextName != null) {
//                    var2 = (Context)var1.lookup(this.contextName);
//                }
//
//                return ReferenceableUtils.referenceToObject(this.reference, this.name, var2, this.env);
//            } catch (NamingException var3) {
//                if (ReferenceIndirector.logger.isLoggable(MLevel.WARNING)) {
//                    ReferenceIndirector.logger.log(MLevel.WARNING, "Failed to acquire the Context necessary to lookup an Object.", var3);
//                }
//
//                throw new InvalidObjectException("Failed to acquire the Context necessary to lookup an Object: " + var3.toString());
//            }
//        }
//    }
//}
