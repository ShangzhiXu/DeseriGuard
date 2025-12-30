package com.example.Utils;

import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class HessianUtil {

    public static <T> byte[] serialize(T o) throws IOException {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        HessianOutput output = new HessianOutput(bao);
        output.getSerializerFactory().setAllowNonSerializable(true);
        output.writeObject(o);
        return bao.toByteArray();
    }

    public static void deserialize(byte[] bytes) throws IOException {
        ByteArrayInputStream bai = new ByteArrayInputStream(bytes);
        HessianInput input = new HessianInput(bai);
        input.readObject();
    }

}
