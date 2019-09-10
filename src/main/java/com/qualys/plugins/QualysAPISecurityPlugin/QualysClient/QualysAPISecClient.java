package com.qualys.plugins.QualysAPISecurityPlugin.QualysClient;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysAuth.QualysAuth;

import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.CloseableHttpClient;
//import org.apache.http.entity.m

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.logging.Logger;

public class QualysAPISecClient extends QualysBaseClient {
    HashMap<String, String> apiMap;
    Logger logger = Logger.getLogger(QualysAPISecClient.class.getName());

    public QualysAPISecClient(QualysAuth auth) {
        super(auth, System.out);
        this.populateApiMap();
    }

    public QualysAPISecClient(QualysAuth auth, PrintStream stream) {
        super(auth, stream);
        this.populateApiMap();
    }

    private void populateApiMap() {
        this.apiMap = new HashMap<>();
        this.apiMap.put("getAppList", "/asapi/v1.0/api");
        this.apiMap.put("createApp", "/asapi/v1.0/api/create");
        this.apiMap.put("updateCicd", "/asapi/v1.0/api/cicd/update/");
    }

    public JsonArray getAppList() {
        JsonArray appList = new JsonArray();
        QualysAPISecResponse response = this.get(this.apiMap.get("getAppList"));
        JsonObject respObj = response.response;
        appList = respObj.get("list").getAsJsonArray();
        return appList;
    }
    
    public QualysAPISecResponse createApp(JsonObject requestDataJson) {
        return this.post(this.apiMap.get("createApp"), requestDataJson);
    }
    
    public QualysAPISecResponse updateCicd(File file, String appId) {
        return this.put(this.apiMap.get("updateCicd") + appId, file);
    }

    public QualysAPISecTestConnectionResponse testConnection() throws Exception{
    	String apiPath = this.apiMap.get("getAppList");
        String apiResponseString = "";
        String errorMessage = "";
        boolean success = false;
        CloseableHttpClient httpclient = null;
        int responseCode = 0;
        try {
            URL url = this.getAbsoluteUrl(apiPath);
            this.stream.println("Making Request: " + url.toString());
            httpclient = this.getHttpClient();	
            
            HttpGet getRequest = new HttpGet(url.toString());
        	getRequest.addHeader("accept", "application/json");
        	getRequest.addHeader("Authorization", "Basic " +  this.getBasicAuthHeader());
        	CloseableHttpResponse response = httpclient.execute(getRequest); 
        	responseCode = response.getStatusLine().getStatusCode();
        	this.stream.println("Server returned with Response code: " + responseCode);
        	if(response.getEntity()!=null) {
	            BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
	            String output;
	            while ((output = br.readLine()) != null) {
	                apiResponseString += output;
	            }
        	}        	
            
        } catch (UnknownHostException exc) {
        	errorMessage = "Error testing connection; Invalid inputs. Please check API server and/or proxy details.";
        } catch (Exception e) {
        	errorMessage = "Error testing connection; Reason: " + e.getMessage();
        }
       
        if(errorMessage.isEmpty()) {
	        if(responseCode >= 200 && responseCode <= 299) {
	        	success = true;
	    	}else if (responseCode == 401){
	    		errorMessage = "Connection test failed; response code : 401; Please provide valid Qualys credentials";
			} else {
				errorMessage ="Error testing connection; Server returned: "+ responseCode + "; " + " Invalid inputs or something went wrong with server. Please check API server and/or proxy details.";
			}
        }
        
        QualysAPISecTestConnectionResponse resp = new QualysAPISecTestConnectionResponse(responseCode, success, errorMessage);
		return resp;
    }
    
    private QualysAPISecResponse executeRequest(HttpRequestBase requestBase) {
    	QualysAPISecResponse apiResponse = new QualysAPISecResponse();
    	String apiResponseString = "";
    	InputStream responseStream = null;
    	CloseableHttpClient httpclient = null;
    	
    	try {
    		httpclient = this.getHttpClient();
	    	CloseableHttpResponse response = httpclient.execute(requestBase); 
	    	apiResponse.responseCode = response.getStatusLine().getStatusCode();
	    	logger.info("Server returned with ResponseCode: "+ apiResponse.responseCode);
	    	this.stream.println("Server returned with Response code: " + apiResponse.responseCode);
	    	if(response.getEntity()!=null) {
	    		responseStream = response.getEntity().getContent();
	            BufferedReader br = new BufferedReader(new InputStreamReader(responseStream));
	            String output;
	            while ((output = br.readLine()) != null) {
	                apiResponseString += output;
	            }
	
	            JsonParser jsonParser = new JsonParser();
	            JsonElement jsonTree = jsonParser.parse(apiResponseString);
	            if (!jsonTree.isJsonObject()) {
	                throw new InvalidAPIResponseException();
	            }	  
	            apiResponse.response = jsonTree.getAsJsonObject();
	    	}
	        
	    }catch (JsonParseException je) {
			apiResponse.errored = true;
	        apiResponse.errorMessage = apiResponseString;
		} catch (Exception e) {
	        apiResponse.errored = true;
	        apiResponse.errorMessage = e.getMessage();
	    } finally {
	    	if (responseStream != null){
                try {
                    responseStream.close() ;
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
	    }
    	
    	httpclient.getConnectionManager().shutdown();
	    return apiResponse;
    }
    
    private QualysAPISecResponse get(String apiPath) {
        QualysAPISecResponse apiResponse = new QualysAPISecResponse();
        
        try {
            URL url = this.getAbsoluteUrl(apiPath);
            this.stream.println("Making Request: " + url.toString());
            
            HttpGet getRequest = new HttpGet(url.toString());
        	getRequest.addHeader("accept", "application/json");
        	getRequest.addHeader("Authorization", "Basic " +  this.getBasicAuthHeader());
        	apiResponse = executeRequest(getRequest);
        } catch(Exception e) {
        	apiResponse.errored = true;
	        apiResponse.errorMessage = e.getMessage();
        }
        return apiResponse;
    }
    
    private QualysAPISecResponse post(String apiPath, JsonObject requestDataJson) {
        QualysAPISecResponse apiResponse = new QualysAPISecResponse();
        
        try {
            URL url = this.getAbsoluteUrl(apiPath);
            this.stream.println("Making Request: " + url.toString());
            
            HttpGet getRequest = new HttpGet(url.toString());
        	getRequest.addHeader("accept", "application/json");
        	getRequest.addHeader("Authorization", "Basic " +  this.getBasicAuthHeader());
        	apiResponse = executeRequest(getRequest);
        } catch(Exception e) {
        	apiResponse.errored = true;
	        apiResponse.errorMessage = e.getMessage();
        }
        return apiResponse;
    }
    
    
    private QualysAPISecResponse put(String apiPath, File file) {
        QualysAPISecResponse apiResponse = new QualysAPISecResponse();
        
        try {
            URL url = this.getAbsoluteUrl(apiPath);
            this.stream.println("Making Request: " + url.toString());
            HttpPut putrequest = new HttpPut(url.toString());
            putrequest.addHeader("accept", "application/json");
            putrequest.addHeader("Authorization", "Basic " +  this.getBasicAuthHeader());
            
            HttpEntity data = MultipartEntityBuilder.create()
                    .setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                    .addBinaryBody("file", file, ContentType.DEFAULT_BINARY, file.getName())
                    .build();
            putrequest.setEntity(data);
        	apiResponse = executeRequest(putrequest);
        } catch(Exception e) {
        	apiResponse.errored = true;
	        apiResponse.errorMessage = e.getMessage();
        }
        return apiResponse;
    }
   
}
