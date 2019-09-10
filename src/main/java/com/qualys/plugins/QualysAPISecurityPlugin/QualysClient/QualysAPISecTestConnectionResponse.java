package com.qualys.plugins.QualysAPISecurityPlugin.QualysClient;

public class QualysAPISecTestConnectionResponse{
    public int responseCode;
    public boolean success;
    public String message;
    
    public QualysAPISecTestConnectionResponse(){
    	this.responseCode = 0;
    	this.success = false;
    	this.message = "";
    }
    
    public QualysAPISecTestConnectionResponse(int responseCode, boolean status, String message){
    	this.responseCode = responseCode;
    	this.success = status;
    	this.message = message;
    }
}