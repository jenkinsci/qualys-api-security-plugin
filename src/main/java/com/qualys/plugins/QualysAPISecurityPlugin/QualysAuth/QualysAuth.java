package com.qualys.plugins.QualysAPISecurityPlugin.QualysAuth;

import hudson.util.Secret;

enum AuthType {
    Basic, OAuth
}

public class QualysAuth {
    private AuthType authType;
    private String server;
    private String username;
    private Secret password;
    private String authKey;
    private String proxyServer;
    private String proxyUsername;
    private Secret proxyPassword;
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

    public Secret getPassword() {
        return password;
    }
    
    public String getProxyServer() {
        return proxyServer;
    }

    public String getProxyUsername() {
        return proxyUsername;
    }

    public Secret getProxyPassword() {
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
        this.password = Secret.fromString(password);
    }
    
    public void setProxyCredentials(String proxyServer, int proxyPort, String proxyUsername, Secret proxyPassword) {
    	this.proxyServer = proxyServer;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = proxyPassword;
        this.proxyPort = proxyPort;
    }
    
    public void setProxyCredentials(String proxyServer, int proxyPort, String proxyUsername, String proxyPassword) {
    	this.proxyServer = proxyServer;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = Secret.fromString(proxyPassword);
        this.proxyPort = proxyPort;
    }

}
