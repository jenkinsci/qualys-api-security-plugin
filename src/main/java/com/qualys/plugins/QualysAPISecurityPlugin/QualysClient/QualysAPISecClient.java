package com.qualys.plugins.QualysAPISecurityPlugin.QualysClient;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.SocketException;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;
import java.util.logging.Logger;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
//import org.apache.http.entity.m

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysAuth.QualysAuth;

public class QualysAPISecClient extends QualysBaseClient {
	HashMap<String, String> apiMap;
	Logger logger = Logger.getLogger(QualysAPISecClient.class.getName());
	private String token = null;
	private int retryInterval = 5;
	private int retryCount = 5;
	private String tempToken = "";

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
		this.apiMap.put("getAuth", "/auth");// [POST]
		this.apiMap.put("getAppList", "/as/v1/api");// [GET]
		this.apiMap.put("assessAPI", "/as/v1/api/swagger/assess?platform=Jenkins"); // [PUT]
	}

	public JsonArray getAppList() {
		JsonArray appList = new JsonArray();
		QualysAPISecResponse response = this.get(this.apiMap.get("getAppList"));
		JsonObject respObj = response.response;
		if (respObj != null && respObj.has("list"))
			appList = respObj.get("list").getAsJsonArray();
		return appList;
	}

	public QualysAPISecResponse assessAPI(File file, String apiId) {
		return this.put(this.apiMap.get("assessAPI") + apiId, file);
	}

	public QualysAPISecTestConnectionResponse testConnection() throws Exception {
		String errorMessage = "";
		CloseableHttpResponse response = null;
		boolean success = false;
		boolean isValidToken = false;
		int statusCd = 0;
		try {

			if (this.auth.getToken() != null && !this.auth.getToken().isEmpty() && this.auth.isFreeUserType()) {
				logger.info("Token is not empty, now validating the subscription");
				try {
					isValidToken = validateSubscription(this.auth.getToken());

				} catch (Exception e) {
					errorMessage = "Token Validation Failed. Reason: " + e;
					success = false;
					logger.info("Token Validation Failed");
					throw new Exception(errorMessage);
				}
				this.tempToken = this.auth.getToken();
				if (isValidToken) {
					statusCd = 201;
				}
			}
			if (!this.auth.isFreeUserType() && (this.auth.getToken() == null || this.auth.getToken().isEmpty())) {
				response = getAuthToken();
				statusCd = response.getStatusLine().getStatusCode();
				if (statusCd == 201) {
					logger.info("Token generated");
					this.stream.println("Token generated");
					isValidToken = validateSubscription(this.tempToken);
					if (!isValidToken) {
						errorMessage = "Token validation Failed. APISEC module is not activated for provided user.";
						success = false;
						throw new Exception(errorMessage);
					}
				} else if (statusCd == 401) {
					logger.info("Connection test failed; " + this.tempToken);
					errorMessage = "Connection test failed; response code : 401; Please provide valid Qualys credentials";
					success = false;
					throw new Exception(errorMessage);
				} else if (statusCd == 500) {
					logger.info("Connection test failed; " + this.tempToken);
					errorMessage = "Connection test failed; response code : 500; API server error. Please try again";
					success = false;
					throw new Exception(errorMessage);
				} else {
					logger.info("Error testing connection; " + this.tempToken);
					errorMessage = "Error testing connection; Server returned: " + statusCd + "; "
							+ " Invalid inputs or something went wrong with server. Please check API server and/or proxy details.";
					success = false;
					throw new Exception(errorMessage);
				}

			}
			if (isValidToken) {
				this.token = this.tempToken;
				this.tempToken = "";
				success = true;
			} else {
				errorMessage = "Token validation Failed. APISEC module is not activated for the provided user.";
				success = false;
				logger.info("Token validation Failed");
				throw new Exception(errorMessage);
			}

		} catch (Exception e) {
			if (!errorMessage.isEmpty()) {
				throw new Exception(errorMessage);
			} else {
				throw new Exception(e);
			}
		}

		QualysAPISecTestConnectionResponse resp = new QualysAPISecTestConnectionResponse(statusCd, success,
				errorMessage);
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
			logger.info("Server returned with ResponseCode: " + apiResponse.responseCode);
			this.stream.println("Server returned with Response code: " + apiResponse.responseCode);
			if (response.getEntity() != null) {
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

		} catch (JsonParseException je) {
			apiResponse.errored = true;
			apiResponse.errorMessage = apiResponseString;
		} catch (Exception e) {
			apiResponse.errored = true;
			apiResponse.errorMessage = e.getMessage();
		} finally {
			if (responseStream != null) {
				try {
					responseStream.close();
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
		String apiResponseString = "";
		CloseableHttpClient httpclient = null;
		CloseableHttpResponse response = null;
		try {
			URL url = this.getAbsoluteUrl(apiPath);
			this.stream.println("Making Get Request for URL: " + url.toString());
			httpclient = this.getHttpClient();
			HttpGet getRequest = new HttpGet(url.toString());
			getRequest.addHeader("accept", "application/json");
			if (this.token == null) {
				QualysAPISecTestConnectionResponse testConnectionResponse = this.testConnection();
				if (!testConnectionResponse.success) {
					apiResponse.errored = true;
					apiResponse.errorMessage = "Token generation failed";
					return apiResponse;
				}
			}
			getRequest.addHeader("Authorization", "Bearer " + this.token);
			response = httpclient.execute(getRequest);
			apiResponse.responseCode = response.getStatusLine().getStatusCode();
			if (apiResponse.responseCode == 401
					&& apiResponse.response.get("message").toString().contains("JWT expired")) {
				this.stream.println("JWT Token is expired. Regenerating token ... ");
				QualysAPISecTestConnectionResponse testConnectionResponse = this.testConnection();
				if (!testConnectionResponse.success) {
					apiResponse.errored = true;
					apiResponse.errorMessage = "Token generation failed";
					return apiResponse;
				}
				getRequest.addHeader("Authorization", "Bearer " + this.token);
				response = httpclient.execute(getRequest);
			}
			if (response.getEntity() != null) {
				BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
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

		} catch (Exception e) {
			apiResponse.errored = true;
			apiResponse.errorMessage = e.getMessage();
		}
		return apiResponse;
	}

	private CloseableHttpResponse post(String apiPath) throws Exception {
		CloseableHttpResponse response = null;
		try {
			URL url = this.getAbsoluteUrl(apiPath);
			this.stream.println("Making Request To: " + url.toString());
			CloseableHttpClient httpclient = this.getHttpClient();
			HttpPost postRequest = new HttpPost(url.toString());
			postRequest.addHeader("accept", "application/json");
			postRequest.addHeader("Content-Type", "application/x-www-form-urlencoded");
			postRequest.setEntity(new ByteArrayEntity(this.getJWTAuthHeader()));
			response = httpclient.execute(postRequest);

			System.out.println("Post request status: " + response.getStatusLine().getStatusCode());
		} catch (Exception e) {
			throw new Exception("" + e);
		}
		return response;
	}

	private QualysAPISecResponse put(String apiPath, File file) {
		QualysAPISecResponse apiResponse = new QualysAPISecResponse();

		try {
			URL url = this.getAbsoluteUrl(apiPath);
			this.stream.println("Making Put Request: " + url.toString());
			HttpPut putrequest = new HttpPut(url.toString());
			putrequest.addHeader("accept", "application/json");
			if (this.token == null) {
				QualysAPISecTestConnectionResponse testConnectionResponse = this.testConnection();
				if (!testConnectionResponse.success) {
					apiResponse.errored = true;
					apiResponse.errorMessage = "Token generation failed";
					return apiResponse;
				}
			}
			putrequest.addHeader("Authorization", "Bearer " + this.token);

			HttpEntity data = MultipartEntityBuilder.create().setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
					.addBinaryBody("file", file, ContentType.DEFAULT_BINARY, file.getName()).build();
			putrequest.setEntity(data);
			apiResponse = executeRequest(putrequest);
		} catch (Exception e) {
			this.stream.println("Exception occurred in put " + e.getMessage());
			apiResponse.errored = true;
			apiResponse.errorMessage = e.getMessage();
		}
		return apiResponse;
	}

	private boolean validateSubscription(String jwt) throws Exception {
		String[] jwtToken = jwt.split("\\.");
		Base64.Decoder decoder = Base64.getDecoder();
		
		// Checking length of token
		if (jwtToken.length != 3) {
			throw new Exception("Token format is invalid. Incorrect length of token");
		}

		// Checking is base 64 encoded or not
		JsonObject decodedjwtToken = null;
		Gson gson = new Gson();
		try {
			String djwtToken0 = new String(decoder.decode(jwtToken[0]));
			String djwtToken = new String(decoder.decode(jwtToken[1]));
			decodedjwtToken = gson.fromJson(djwtToken, JsonObject.class);
		} catch (Exception e) {
			throw new Exception("Token format is invalid. Unable to decode token");
		}

		logger.info("Validating the subscription");
		if (decodedjwtToken != null && decodedjwtToken.has("modulesAllowed")) {
			if (decodedjwtToken.get("modulesAllowed").toString().contains("\"APISEC\"")) {
				System.out.println("APISEC Module Found");
				this.stream.println("APISEC Module Found");
				return true;
			}
		} 
		throw new Exception("Token format is invalid. APISEC Module Not Found");
	}

	private CloseableHttpResponse getAuthToken() throws Exception {
		this.stream.println("Generating Auth Token...");
		String outputMsg = "";
		int timeInterval = 0;
		CloseableHttpResponse response = null;
		while (timeInterval < this.retryCount) {
			outputMsg = "";
			try {
				response = this.post(this.apiMap.get("getAuth"));
				if (response.getEntity() != null) {
					BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
					String output;
					while ((output = br.readLine()) != null) {
						outputMsg += output;
					}
				}
				this.tempToken = outputMsg;
				this.stream.println("Fetching auth token: Response code: " + response.getStatusLine().getStatusCode());
				break;
			} catch (SocketException e) {
				this.stream.println("SocketException : " + e);
				throw e;
			} catch (IOException e) {
				this.stream.println("IOException : " + e);
				throw e;
			} catch (Exception e) {
				this.stream.println("Exception : " + e);

				// Handling Empty response and empty response code here
				timeInterval++;
				if (timeInterval < this.retryCount) {
					try {
						this.stream.println("Retry fetching auth token ...");
						Thread.sleep(this.retryInterval * 1000);
					} catch (Exception e1) {
						this.stream.println("Exception : " + e1);
						throw e1;
					}
				} else {
					throw e;
				}
			}
		}
		return response;
	}
}
