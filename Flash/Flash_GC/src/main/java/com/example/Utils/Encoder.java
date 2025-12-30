package com.example.Utils;
import com.sun.org.apache.bcel.internal.Repository;

import java.util.Base64;

public class Encoder {

    public static String encodeBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] decodeBase64(String string) {
        return Base64.getDecoder().decode(string);
    }

    public static byte[] class2Bytes(Class clz) {
        return Repository.lookupClass(clz).getBytes();
    }
}
