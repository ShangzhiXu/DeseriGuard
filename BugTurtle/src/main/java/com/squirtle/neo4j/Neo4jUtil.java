package com.squirtle.neo4j;

import com.squirtle.config.Neo4jConfig;
import org.neo4j.driver.*;
import org.neo4j.driver.Record;

public class Neo4jUtil {
    private static Driver driver;
    static {
        // 创建驱动
        driver = GraphDatabase.driver(
                Neo4jConfig.getUri(),
                AuthTokens.basic(Neo4jConfig.getUser(), Neo4jConfig.getPassword())
        );
    }
    /**
     * 创建节点
     */
    public void createPersonNode(String name, int age) {
        try (Session session = driver.session()) {
            String query = "CREATE (p:Person {name: $name, age: $age})";
            session.writeTransaction(tx -> {
                tx.run(query, Values.parameters("name", name, "age", age));
                return null;
            });
        }
    }
    /**
     * 创建关系
     */
    public void createRelationship(String name1, String name2) {
        try (Session session = driver.session()) {
            String query =
                    "MATCH (a:Person {name: $name1}), (b:Person {name: $name2}) " +
                            "CREATE (a)-[:KNOWS]->(b)";
            session.writeTransaction(tx -> {
                tx.run(query, Values.parameters("name1", name1, "name2", name2));
                return null;
            });
        }
    }
    /**
     * 查询节点
     */
    public void findPersonByName(String name) {
        try (Session session = driver.session()) {
            String query = "MATCH (p:Person {name: $name}) RETURN p.name AS name, p.age AS age";
            session.readTransaction(tx -> {
                Result result = tx.run(query, Values.parameters("name", name));
                while (result.hasNext()) {
                    Record record = result.next();
                    System.out.println("Name: " + record.get("name").asString());
                    System.out.println("Age: " + record.get("age").asInt());
                }
                return null;
            });
        }
    }
    /**
     * 删除节点
     */
    public void deletePerson(String name) {
        try (Session session = driver.session()) {
            String query = "MATCH (p:Person {name: $name}) DETACH DELETE p";
            session.writeTransaction(tx -> {
                tx.run(query, Values.parameters("name", name));
                return null;
            });
        }
    }
    /**
     * 关闭连接
     */
    public void close() {
        driver.close();
    }



}
