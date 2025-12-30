package com.example.Utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class SerializeUtil {

    public static <T> byte[] serialize(T o) throws Exception {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        ObjectOutputStream outputStream = new ObjectOutputStream(bao);
        outputStream.writeObject(o);
        return bao.toByteArray();
    }

    public static Object deserialize(byte[] bytes) throws Exception {
        ByteArrayInputStream bai = new ByteArrayInputStream(bytes);
        ObjectInputStream inputStream = new ObjectInputStream(bai);
        return inputStream.readObject();
    }

}
