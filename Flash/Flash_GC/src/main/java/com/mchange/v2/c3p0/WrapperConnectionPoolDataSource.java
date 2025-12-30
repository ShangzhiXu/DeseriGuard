////
//// Source code recreated from a .class file by IntelliJ IDEA
//// (powered by FernFlower decompiler)
////
//
//package com.mchange.v2.c3p0;
//
//import com.mchange.v1.db.sql.ConnectionUtils;
//import com.mchange.v2.c3p0.cfg.C3P0Config;
//import com.mchange.v2.c3p0.cfg.C3P0ConfigUtils;
//import com.mchange.v2.c3p0.impl.C3P0ImplUtils;
//import com.mchange.v2.c3p0.impl.C3P0PooledConnection;
//import com.mchange.v2.c3p0.impl.NewPooledConnection;
//import com.mchange.v2.c3p0.impl.WrapperConnectionPoolDataSourceBase;
//import com.mchange.v2.log.MLevel;
//import com.mchange.v2.log.MLog;
//import com.mchange.v2.log.MLogger;
//import java.beans.PropertyChangeEvent;
//import java.beans.PropertyVetoException;
//import java.beans.VetoableChangeListener;
//import java.io.PrintWriter;
//import java.sql.Connection;
//import java.sql.SQLException;
//import java.util.Map;
//import javax.sql.ConnectionPoolDataSource;
//import javax.sql.DataSource;
//import javax.sql.PooledConnection;
//
//public final class WrapperConnectionPoolDataSource extends WrapperConnectionPoolDataSourceBase implements ConnectionPoolDataSource {
//    static final MLogger logger = MLog.getLogger(WrapperConnectionPoolDataSource.class);
//    ConnectionTester connectionTester;
//    Map userOverrides;
//
//    public WrapperConnectionPoolDataSource(boolean autoregister) {
//        super(autoregister);
//        this.connectionTester = C3P0Registry.getDefaultConnectionTester();
//        this.setUpPropertyListeners();
//
//        try {
//            this.userOverrides = C3P0ImplUtils.parseUserOverridesAsString(this.getUserOverridesAsString());
//        } catch (Exception var3) {
//            if (logger.isLoggable(MLevel.WARNING)) {
//                logger.log(MLevel.WARNING, "Failed to parse stringified userOverrides. " + this.getUserOverridesAsString(), var3);
//            }
//        }
//
//    }
//
//    public WrapperConnectionPoolDataSource() {
//        this(true);
//    }
//
//    private void setUpPropertyListeners() {
//        VetoableChangeListener setConnectionTesterListener = new VetoableChangeListener() {
//            public void vetoableChange(PropertyChangeEvent evt) throws PropertyVetoException {
//                String propName = evt.getPropertyName();
//                Object val = evt.getNewValue();
//                if ("connectionTesterClassName".equals(propName)) {
//                    try {
//                        WrapperConnectionPoolDataSource.this.recreateConnectionTester((String)val);
//                    } catch (Exception var6) {
//                        if (WrapperConnectionPoolDataSource.logger.isLoggable(MLevel.WARNING)) {
//                            WrapperConnectionPoolDataSource.logger.log(MLevel.WARNING, "Failed to create ConnectionTester of class " + val, var6);
//                        }
//
//                        throw new PropertyVetoException("Could not instantiate connection tester class with name '" + val + "'.", evt);
//                    }
//                } else if ("userOverridesAsString".equals(propName)) {
//                    try {
//                        WrapperConnectionPoolDataSource.this.userOverrides = C3P0ImplUtils.parseUserOverridesAsString((String)val);
//                    } catch (Exception var5) {
//                        if (WrapperConnectionPoolDataSource.logger.isLoggable(MLevel.WARNING)) {
//                            WrapperConnectionPoolDataSource.logger.log(MLevel.WARNING, "Failed to parse stringified userOverrides. " + val, var5);
//                        }
//
//                        throw new PropertyVetoException("Failed to parse stringified userOverrides. " + val, evt);
//                    }
//                }
//
//            }
//        };
//        this.addVetoableChangeListener(setConnectionTesterListener);
//    }
//
//    public WrapperConnectionPoolDataSource(String configName) {
//        this();
//
//        try {
//            if (configName != null) {
//                C3P0Config.bindNamedConfigToBean(this, configName, true);
//            }
//        } catch (Exception var3) {
//            if (logger.isLoggable(MLevel.WARNING)) {
//                logger.log(MLevel.WARNING, "Error binding WrapperConnectionPoolDataSource to named-config '" + configName + "'. Some default-config values may be used.", var3);
//            }
//        }
//
//    }
//
//    public PooledConnection getPooledConnection() throws SQLException {
//        return this.getPooledConnection((ConnectionCustomizer)((ConnectionCustomizer)null), (String)null);
//    }
//
//    protected PooledConnection getPooledConnection(ConnectionCustomizer cc, String pdsIdt) throws SQLException {
//        DataSource nds = this.getNestedDataSource();
//        if (nds == null) {
//            throw new SQLException("No standard DataSource has been set beneath this wrapper! [ nestedDataSource == null ]");
//        } else {
//            Connection conn = null;
//
//            try {
//                conn = nds.getConnection();
//                if (conn == null) {
//                    throw new SQLException("An (unpooled) DataSource returned null from its getConnection() method! DataSource: " + this.getNestedDataSource());
//                } else {
//                    return (PooledConnection)(this.isUsesTraditionalReflectiveProxies(this.getUser()) ? new C3P0PooledConnection(conn, this.connectionTester, this.isAutoCommitOnClose(this.getUser()), this.isForceIgnoreUnresolvedTransactions(this.getUser()), cc, pdsIdt) : new NewPooledConnection(conn, this.connectionTester, this.isAutoCommitOnClose(this.getUser()), this.isForceIgnoreUnresolvedTransactions(this.getUser()), this.getPreferredTestQuery(this.getUser()), cc, pdsIdt));
//                }
//            } catch (SQLException var6) {
//                ConnectionUtils.attemptClose(conn);
//                throw var6;
//            } catch (RuntimeException var7) {
//                ConnectionUtils.attemptClose(conn);
//                throw var7;
//            }
//        }
//    }
//
//    public PooledConnection getPooledConnection(String user, String password) throws SQLException {
//        return this.getPooledConnection(user, password, (ConnectionCustomizer)null, (String)null);
//    }
//
//    protected PooledConnection getPooledConnection(String user, String password, ConnectionCustomizer cc, String pdsIdt) throws SQLException {
//        DataSource nds = this.getNestedDataSource();
//        if (nds == null) {
//            throw new SQLException("No standard DataSource has been set beneath this wrapper! [ nestedDataSource == null ]");
//        } else {
//            Connection conn = null;
//
//            try {
//                conn = nds.getConnection(user, password);
//                if (conn == null) {
//                    throw new SQLException("An (unpooled) DataSource returned null from its getConnection() method! DataSource: " + this.getNestedDataSource());
//                } else {
//                    return (PooledConnection)(this.isUsesTraditionalReflectiveProxies(user) ? new C3P0PooledConnection(conn, this.connectionTester, this.isAutoCommitOnClose(user), this.isForceIgnoreUnresolvedTransactions(user), cc, pdsIdt) : new NewPooledConnection(conn, this.connectionTester, this.isAutoCommitOnClose(user), this.isForceIgnoreUnresolvedTransactions(user), this.getPreferredTestQuery(user), cc, pdsIdt));
//                }
//            } catch (SQLException var8) {
//                ConnectionUtils.attemptClose(conn);
//                throw var8;
//            } catch (RuntimeException var9) {
//                ConnectionUtils.attemptClose(conn);
//                throw var9;
//            }
//        }
//    }
//
//    private boolean isAutoCommitOnClose(String userName) {
//        if (userName == null) {
//            return this.isAutoCommitOnClose();
//        } else {
//            Boolean override = C3P0ConfigUtils.extractBooleanOverride("autoCommitOnClose", userName, this.userOverrides);
//            return override == null ? this.isAutoCommitOnClose() : override;
//        }
//    }
//
//    private boolean isForceIgnoreUnresolvedTransactions(String userName) {
//        if (userName == null) {
//            return this.isForceIgnoreUnresolvedTransactions();
//        } else {
//            Boolean override = C3P0ConfigUtils.extractBooleanOverride("forceIgnoreUnresolvedTransactions", userName, this.userOverrides);
//            return override == null ? this.isForceIgnoreUnresolvedTransactions() : override;
//        }
//    }
//
//    private boolean isUsesTraditionalReflectiveProxies(String userName) {
//        if (userName == null) {
//            return this.isUsesTraditionalReflectiveProxies();
//        } else {
//            Boolean override = C3P0ConfigUtils.extractBooleanOverride("usesTraditionalReflectiveProxies", userName, this.userOverrides);
//            return override == null ? this.isUsesTraditionalReflectiveProxies() : override;
//        }
//    }
//
//    private String getPreferredTestQuery(String userName) {
//        if (userName == null) {
//            return this.getPreferredTestQuery();
//        } else {
//            String override = (String)C3P0ConfigUtils.extractUserOverride("preferredTestQuery", userName, this.userOverrides);
//            return override == null ? this.getPreferredTestQuery() : override;
//        }
//    }
//
//    public PrintWriter getLogWriter() throws SQLException {
//        return this.getNestedDataSource().getLogWriter();
//    }
//
//    public void setLogWriter(PrintWriter out) throws SQLException {
//        this.getNestedDataSource().setLogWriter(out);
//    }
//
//    public void setLoginTimeout(int seconds) throws SQLException {
//        this.getNestedDataSource().setLoginTimeout(seconds);
//    }
//
//    public int getLoginTimeout() throws SQLException {
//        return this.getNestedDataSource().getLoginTimeout();
//    }
//
//    public String getUser() {
//        try {
//            return C3P0ImplUtils.findAuth(this.getNestedDataSource()).getUser();
//        } catch (SQLException var2) {
//            if (logger.isLoggable(MLevel.WARNING)) {
//                logger.log(MLevel.WARNING, "An Exception occurred while trying to find the 'user' property from our nested DataSource. Defaulting to no specified username.", var2);
//            }
//
//            return null;
//        }
//    }
//
//    public String getPassword() {
//        try {
//            return C3P0ImplUtils.findAuth(this.getNestedDataSource()).getPassword();
//        } catch (SQLException var2) {
//            if (logger.isLoggable(MLevel.WARNING)) {
//                logger.log(MLevel.WARNING, "An Exception occurred while trying to find the 'password' property from our nested DataSource. Defaulting to no specified password.", var2);
//            }
//
//            return null;
//        }
//    }
//
//    public Map getUserOverrides() {
//        return this.userOverrides;
//    }
//
//    public String toString() {
//        StringBuffer sb = new StringBuffer();
//        sb.append(super.toString());
//        return sb.toString();
//    }
//
//    protected String extraToStringInfo() {
//        return this.userOverrides != null ? "; userOverrides: " + this.userOverrides.toString() : null;
//    }
//
//    private synchronized void recreateConnectionTester(String className) throws Exception {
//        if (className != null) {
//            ConnectionTester ct = (ConnectionTester)Class.forName(className).newInstance();
//            this.connectionTester = ct;
//        } else {
//            this.connectionTester = C3P0Registry.getDefaultConnectionTester();
//        }
//
//    }
//}
