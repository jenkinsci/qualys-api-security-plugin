package com.qualys.plugins.QualysAPISecurityPlugin;

import java.io.File;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysAuth.QualysAuth;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysClient.QualysAPISecClient;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysClient.QualysAPISecResponse;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysClient.QualysAPISecTestConnectionResponse;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysCriteria.QualysCriteria;
import com.qualys.plugins.QualysAPISecurityPlugin.util.Helper;

import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;

public class APISecLauncher extends MasterToSlaveCallable<String, Exception> {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
    private TaskListener listener;
    private String apiId;
    private String portalUrl;
    private QualysAuth auth;
    private String swaggerPath;
    private String workspace;
    private String criteria;
    private boolean failConditionsConfigured;
    private boolean renderReport = true;
    
    private final static Logger logger = Helper.getLogger(APISecLauncher.class.getName());
    
    public APISecLauncher(TaskListener listener, String apiId, 
    		QualysAuth auth, String portalUrl, String swaggerPath, String workspace,
    		boolean failConditionsConfigured, String criteria) {
    	
    	this.listener = listener;
    	this.apiId = apiId;
    	this.auth = auth;
    	this.portalUrl = portalUrl;
    	this.swaggerPath = swaggerPath;
    	this.workspace = workspace;
    	this.criteria = criteria;
    	this.failConditionsConfigured = failConditionsConfigured;
    }
    
    public String call() throws Exception {
    	QualysAPISecResponse response = launchScan();
    	JsonObject respObj;
    	boolean buildPassed = true;
    	JsonObject evaluationResult = null;
    	String failureMessage = "";
    	boolean validationFailed = false;
    	boolean invalidSwagger = false;
    	if(response.errored || (response.responseCode < 200 && response.responseCode > 299)){
    		throw new Exception("Error launching scan. Message: " + (response.errorMessage != null ? response.errorMessage : "Response code from server - " + response.responseCode));
    	}else {
    		respObj = response.response;
    		this.listener.getLogger().println("Successfully launched Qualys API Security Assessment.");
    		JsonElement swaggerState = respObj.get("swaggerState");
    		
			if(swaggerState != null && !swaggerState.getAsString().equalsIgnoreCase("valid")) {
				this.listener.getLogger().println("Swagger state of this file is - " + swaggerState.getAsString());
			}
    		
    		evaluationResult = evaluateFailurePolicy(respObj);
			buildPassed = evaluationResult.get("passed").getAsBoolean();
			
    		if(failConditionsConfigured) {
    			if(buildPassed) listener.getLogger().println("Qualys API Security Assessment - Build passes the configured pass/fail criteria.");
    			else listener.getLogger().println("Qualys API Security Assessment - Failing the build against the configured pass/fail criteria.");
    		}
    		
    		respObj.add("buildEvaluationResult", evaluationResult);
			
    	}
    	if(evaluationResult != null && evaluationResult.has("passed")) {
    		if(failConditionsConfigured && !buildPassed) {
    			validationFailed = true;
    			failureMessage += evaluationResult.get("failureMessage").getAsString();
    		}
    	}
    	
    	if(validationFailed) {
    		respObj.addProperty("failureMessage", failureMessage);
    	}
    	respObj.addProperty("renderReport", renderReport);
    	Gson gson = new Gson();
    	return gson.toJson(respObj);
    }
    
    public JsonObject evaluateFailurePolicy(JsonObject result) throws Exception{
		Gson gson = new Gson();
		QualysCriteria criteriaObj = new QualysCriteria(criteria);
		Boolean passed = criteriaObj.evaluate(result);
		JsonObject obj = new JsonObject();
		obj.add("passed", gson.toJsonTree(passed));
		obj.add("result", criteriaObj.returnObject);
		if(!passed) {
			String failureMessage = getBuildFailureMessages(criteriaObj.getBuildFailedReasons());
			obj.addProperty("failureMessage", failureMessage);
		}
		return obj;
	}
    
    private String getBuildFailureMessages(ArrayList<String> result) throws Exception {
    	String message = String.join("\n", result);
    	return message;
    }
    
    public QualysAPISecResponse launchScan() throws Exception {
    	QualysAPISecResponse resp = null;
    	
    	QualysAPISecClient apiClient = new QualysAPISecClient(auth, this.listener.getLogger());
    	
    	try {
    		listener.getLogger().println("Checking token for APISEC module");
    		logger.info("Checking token for APISEC module");
    		//test connection
    		int retryCount = 0;
    		boolean retry = true;
    		
    		while(retry && retryCount <= 3) {
	    		QualysAPISecTestConnectionResponse testConnResp = apiClient.testConnection();
            	logger.info("Received response : " + testConnResp);
            	
	    		retry = false;
	    		retryCount++;
	    		
	    		//JP-210 retry 3 times after 5 sec delay to test connection
	    		if(testConnResp.success == true && testConnResp.responseCode == 201) {
	    			break;
		   		}else if(testConnResp.responseCode >= 500 && testConnResp.responseCode <= 599 && retryCount < 3) {
    				retry = true;
    				long secInMillis = TimeUnit.SECONDS.toMillis(5);
    				listener.getLogger().println("Something went wrong with server; Could be a temporary glitch. Retrying in 5 secs...");
    				Thread.sleep(secInMillis);
    				continue;
    			} else {
	    			throw new Exception(testConnResp.message);
		   		}
    		}
        } catch (Exception e) {
    		logger.info("Test connection with Qualys API server failed. Reason : " + e.getMessage());
            throw new Exception("Test connection with Qualys API server failed. Reason : " + e.getMessage());
        }
    	
    	this.listener.getLogger().println("Launching Static Assessment on API with swagger file: " + swaggerPath);
    	
    	File uploadSwaggerFile = new File(workspace + File.separator + swaggerPath);
    	apiClient.setTimeout(300);
    	resp = apiClient.assessAPI(uploadSwaggerFile, apiId);
    	if(resp.errored || resp.responseCode != 200) {
    		if(resp.response != null && resp.response.has("message")) {
    			throw new Exception("Static Assesment API failed; Response code from server: " + resp.responseCode + ". Error message: " + resp.response.get("message"));
    		}else if(!resp.errorMessage.isEmpty()) {
    			throw new Exception("Static Assesment API failed; Error message: " + resp.errorMessage);
    		}
    	}
    	return resp;
    }
}