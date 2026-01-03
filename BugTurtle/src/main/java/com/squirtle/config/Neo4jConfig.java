package com.squirtle.config;

import java.io.InputStream;
import java.util.Properties;

public class Neo4jConfig {
    private static Properties props = new Properties();

    static {
        try (InputStream input = Neo4jConfig.class.getClassLoader().getResourceAsStream("neo4j.properties")) {
            props.load(input);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String getUri() {
        return props.getProperty("neo4j.uri");
    }

    public static String getUser() {
        return props.getProperty("neo4j.user");
    }

    public static String getPassword() {
        return props.getProperty("neo4j.password");
    }
}
