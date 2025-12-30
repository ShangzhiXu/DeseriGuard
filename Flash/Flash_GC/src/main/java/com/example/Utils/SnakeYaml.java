package com.example.Utils;

import org.yaml.snakeyaml.Yaml;

public class SnakeYaml {

    public static <T> String serialize(T o) throws Exception {
        Yaml yaml = new Yaml();
        return yaml.dump(o);
    }

    public static Object deserialize(String xml) throws Exception {
        Yaml yaml = new Yaml();
        return yaml.load(xml);
    }

}
