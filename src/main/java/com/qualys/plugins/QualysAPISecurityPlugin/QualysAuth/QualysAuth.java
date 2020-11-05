package com.qualys.plugins.QualysAPISecurityPlugin.QualysAuth;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import hudson.util.Secret;

enum AuthType {
    Basic, OAuth
}

public class QualysAuth implements Serializable{
    private AuthType authType;
    private String server;
    private String username;
    private Secret password;
    private String authKey;
    private String proxyServer;
    private String proxyUsername;
    private Secret proxyPassword;
    private int proxyPort;
	private String gatewayURL = null;
    public static List<String> serverPlatformURL = new ArrayList<String>();
    public static List<String> serverApiURL = new ArrayList<String>();
    public static List<String> serverGatewayURL = new ArrayList<String>();
    private String token;
    private boolean freeUserType = true;

    public QualysAuth () {
        
    }

    static {
    	serverPlatformURL.add("https://qualysguard.qualys.com");
    	serverPlatformURL.add("https://qualysguard.qg2.apps.qualys.com");
    	serverPlatformURL.add("https://qualysguard.qg3.apps.qualys.com");
    	serverPlatformURL.add("https://qualysguard.qg4.apps.qualys.com");
    	serverPlatformURL.add("https://qualysguard.qualys.eu");
    	serverPlatformURL.add("https://qualysguard.qg2.apps.qualys.eu");
    	serverPlatformURL.add("https://qualysguard.qg1.apps.qualys.in");
    	serverPlatformURL.add("https://qualysguard.qg1.apps.qualys.ca");
    	
    	serverApiURL.add("https://qualysapi.qualys.com");
    	serverApiURL.add("https://qualysapi.qg2.apps.qualys.com");
    	serverApiURL.add("https://qualysapi.qg3.apps.qualys.com");
    	serverApiURL.add("https://qualysapi.qg4.apps.qualys.com");
    	serverApiURL.add("https://qualysapi.qualys.eu");
    	serverApiURL.add("https://qualysapi.qg2.apps.qualys.eu");
    	serverApiURL.add("https://qualysapi.qg1.apps.qualys.in");
    	serverApiURL.add("https://qualysapi.qg1.apps.qualys.ca");
    	
    	serverGatewayURL.add("https://gateway.qg1.apps.qualys.com");
    	serverGatewayURL.add("https://gateway.qg2.apps.qualys.com");
    	serverGatewayURL.add("https://gateway.qg3.apps.qualys.com");
    	serverGatewayURL.add("https://gateway.qg4.apps.qualys.com");
    	serverGatewayURL.add("https://gateway.qg1.apps.qualys.eu");
    	serverGatewayURL.add("https://gateway.qg2.apps.qualys.eu");
    	serverGatewayURL.add("https://gateway.qg1.apps.qualys.in");
    	serverGatewayURL.add("https://gateway.qg1.apps.qualys.ca");
    	
    }

    public QualysAuth (String server, String oauthKey) {
        this.authType = AuthType.OAuth;
        this.authKey = oauthKey;
    }

    public String getServer() {
    	int pos;
		if (gatewayURL == null) {
			if (server.endsWith("/")) {
				server = server.substring(0, server.length() - 1);
			}
			pos = serverPlatformURL.indexOf(server);
			if (pos == -1) {
				pos = serverApiURL.indexOf(server);
			}
			if (pos == -1) {
				pos = serverGatewayURL.indexOf(server);
			}
			if (pos == -1) {
				gatewayURL = server.replace("https://qualysapi.", "https://qualysgateway.");
			}
			if (pos == -1) {
				gatewayURL = server.replace("https://qualysguard.", "https://qualysgateway.");
			}
			else 
			{
				gatewayURL = serverGatewayURL.get(pos);
			}
		}

		return gatewayURL;
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
    
    public void setTokenServer(String tokenServer)
    {
    	this.server =  tokenServer;
    }

    public void setQualysCredentials(String server, String username, String password) {
    	this.authType = AuthType.Basic;
        this.server = server;
        this.username = username;
        this.password = Secret.fromString(password);
    }
    
    public void setProxyCredentials(String proxyServer, int proxyPort, String proxyUsername, String proxyPassword) {
    	this.proxyServer = proxyServer;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = Secret.fromString(proxyPassword);
        this.proxyPort = proxyPort;
    }
    
    public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public boolean isFreeUserType() {
		return freeUserType;
	}

	public void setFreeUserType(boolean freeUserType) {
		this.freeUserType = freeUserType;
	}
	
	


}
