package com.qualys.plugins.QualysAPISecurityPlugin.QualysAuth;

enum AuthType {
    Basic, OAuth
}

public class QualysAuth {
    private AuthType authType;
    private String server;
    private String username;
    private String password;
    private String authKey;
    private String proxyServer;
    private String proxyUsername;
    private String proxyPassword;
    private int proxyPort;

    public QualysAuth () {
        
    }

    public QualysAuth (String server, String oauthKey) {
        this.authType = AuthType.OAuth;
        this.authKey = oauthKey;
    }

    public String getServer() {
        return server;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
    
    public String getProxyServer() {
        return proxyServer;
    }

    public String getProxyUsername() {
        return proxyUsername;
    }

    public String getProxyPassword() {
        return proxyPassword;
    }
    public int getProxyPort() {
        return proxyPort;
    }
    public String getAuthKey() {
        return authKey;
    }
   
    public void setQualysCredentials(String server, String username, String password) {
    	this.authType = AuthType.Basic;
        this.server = server;
        this.username = username;
        this.password = password;
    }
    public void setProxyCredentials(String proxyServer, int proxyPort, String proxyUsername, String proxyPassword) {
    	this.proxyServer = proxyServer;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = proxyPassword;
        this.proxyPort = proxyPort;
    }

}
