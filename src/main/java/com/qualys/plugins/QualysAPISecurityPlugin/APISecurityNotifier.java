package com.qualys.plugins.QualysAPISecurityPlugin;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;

import org.apache.commons.lang.StringUtils;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysAuth.QualysAuth;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysClient.QualysAPISecClient;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysClient.QualysAPISecTestConnectionResponse;
import com.qualys.plugins.QualysAPISecurityPlugin.report.ReportAction;
import com.qualys.plugins.QualysAPISecurityPlugin.util.Helper;
import com.qualys.plugins.QualysAPISecurityPlugin.util.InvalidConfigurationException;
import com.qualys.plugins.QualysAPISecurityPlugin.util.Severity;
import com.qualys.plugins.QualysAPISecurityPlugin.util.ValidateParameters;

import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;

@Extension
public class APISecurityNotifier extends Builder implements SimpleBuildStep {
	private final static int PROXY_PORT = 80;
	private String platform;
	private String apiServer;
    private String credsId;
    private String apiId;
    private String proxyServer;
    private int proxyPort = PROXY_PORT;
    private String proxyCredentialsId;
    private boolean useProxy = false;
    private String swaggerPath;   
    private boolean isFailOnGrade;
    private String grade;
    private boolean isFailOnSecurityGroup;
    private boolean isFailOnDataGroup;
    private boolean isFailOnViolationGroup;
    private String securityGroupCount;
    private String dataGroupCount;
    private String violationGroupCount;
    private String securityCriticality;
    private String dataCriticality;
    private String violationCriticality;
    private boolean freeUserType = true;
    private String token;
    
    private final static String tokenServerPath = "https://gateway.qg3.apps.qualys.com/";
    
    private final static Logger logger = Helper.getLogger(APISecurityNotifier.class.getName());
    
    @DataBoundConstructor
	public APISecurityNotifier(String platform, String apiServer, String credsId, boolean useProxy, String proxyServer, int proxyPort, String proxyCredentialsId,
    		String swaggerPath, String apiId, boolean isFailOnGrade, String grade, boolean isFailOnSecurityGroup,
    		String securityGroupCount, String securityCriticality, boolean isFailOnDataGroup, String dataGroupCount,	String dataCriticality,
    		boolean isFailOnViolationGroup, String violationGroupCount,String violationCriticality,String token, boolean freeUserType) {
        
    	this.platform = platform;
        if("pcp".equalsIgnoreCase(platform)) {
        	this.apiServer = apiServer;
        }
        this.credsId = credsId;
        this.apiId = apiId;
        
        this.useProxy = useProxy;
        if(this.useProxy) {
	        this.proxyServer = proxyServer;
	        this.proxyPort = proxyPort;
	        this.proxyCredentialsId = proxyCredentialsId;
        }
        this.swaggerPath = swaggerPath;
        
        if(isFailOnGrade) {
        	this.isFailOnGrade = true;
        	this.grade = grade;
        }
        if(isFailOnSecurityGroup) {
        	this.isFailOnSecurityGroup = true;
        	this.securityGroupCount = securityGroupCount;
        	this.securityCriticality = securityCriticality;
        }
        if(isFailOnDataGroup) {
        	this.isFailOnDataGroup = true;
        	this.dataGroupCount = dataGroupCount;
        	this.dataCriticality = dataCriticality;
        }
        if(isFailOnViolationGroup) {
        	this.isFailOnViolationGroup = true;
        	this.violationGroupCount = violationGroupCount;
        	this.violationCriticality = violationCriticality;
        }
       
        if(this.freeUserType)
        {
        	this.token = token;
        	this.apiServer = tokenServerPath;
        	this.apiId = "";
        }
        else
        {
        	this.token = "";
        }
		
    }
    
    public APISecurityNotifier() {};
    
    public String getPlatform() { return platform; }
    
    public boolean isFreeUserType() {
		return freeUserType;
	}
	
	/*
	 * @DataBoundSetter public void setFreeUserType(boolean freeUserType) {
	 * this.freeUserType = freeUserType; }
	 */
	
	public boolean getFreeUserType() {
		return this.freeUserType;
	}
    
    @DataBoundSetter
    public void setToken(String token) { this.token = token; }
	
	public String getToken() {
		return this.token;
	}
    
    @DataBoundSetter
    public void setPlatform(String platform) { this.platform = platform; }
    
    public String getApiServer() { return apiServer; }
    
	@DataBoundSetter
    public void setApiServer(String apiServer) { 
		if (apiServer!=null && apiServer.endsWith("/")) {
			apiServer = apiServer.substring(0, apiServer.length() - 1);
		}
		this.apiServer = apiServer;
    }
	
	@DataBoundSetter
	public void setCredsId(String cred) { this.credsId = cred; }

	public String getCredsId() { return credsId; }
    
    public String getApiId() { return apiId;	}

    @DataBoundSetter
	public void setApiId(String apiId) { this.apiId = apiId; }
    
    public String getProxyServer() { return proxyServer; }

	@DataBoundSetter
	public void setProxyServer(String proxyServer) { this.proxyServer = proxyServer; }
	
	public int getProxyPort() { return proxyPort; }

	@DataBoundSetter
	public void setProxyPort(int proxyPort) {
		proxyPort = proxyPort <= 0 ? PROXY_PORT : proxyPort;
		this.proxyPort = proxyPort;
	}
	
	public String getProxyCredentialsId() { return proxyCredentialsId; }

	@DataBoundSetter
	public void setProxyCredentialsId(String proxyCredentialsId) { this.proxyCredentialsId = proxyCredentialsId; }
	
	public boolean getUseProxy() { return useProxy; }

	@DataBoundSetter
	public void setUseProxy(boolean useProxy) { this.useProxy = useProxy; }
	
	public String getSwaggerPath() { return swaggerPath;	}
	
    @DataBoundSetter
	public void setSwaggerPath(String swaggerPath) { this.swaggerPath = swaggerPath; }
	
    @DataBoundSetter
	public void setIsFailOnGrade(boolean flag) { this.isFailOnGrade = flag; }
    public boolean getIsFailOnGrade() { return this.isFailOnGrade; }
    
    @DataBoundSetter
	public void setGrade(String val) { this.grade = val; }
    public String getGrade() { return this.grade; }
    
    @DataBoundSetter
	public void setIsFailOnSecurityGroup(boolean flag) { this.isFailOnSecurityGroup = flag; }
    public boolean getIsFailOnSecurityGroup() { return this.isFailOnSecurityGroup; }
    
    @DataBoundSetter
	public void setIsFailOnDataGroup(boolean flag) { this.isFailOnDataGroup = flag; }
    public boolean getIsFailOnDataGroup() { return this.isFailOnDataGroup; }
    
    @DataBoundSetter
	public void setIsFailOnViolationGroup(boolean flag) { this.isFailOnViolationGroup = flag; }
    public boolean getIsFailOnViolationGroup() { return this.isFailOnViolationGroup; }
    
    @DataBoundSetter
	public void setSecurityGroupCount(String val) { this.securityGroupCount = val; }
    public String getSecurityGroupCount() { return this.securityGroupCount; }
    
    @DataBoundSetter
	public void setDataGroupCount(String val) { this.dataGroupCount = val; }
    public String getDataGroupCount() { return this.dataGroupCount; }
    
    @DataBoundSetter
	public void setViolationGroupCount(String val) { this.violationGroupCount = val; }
    public String getViolationGroupCount() { return this.violationGroupCount; }
    
    @DataBoundSetter
	public void setSecurityCriticality(String val) { this.securityCriticality = val; }
    public String getSecurityCriticality() { return this.securityCriticality; }
    
    @DataBoundSetter
	public void setDataCriticality(String val) { this.dataCriticality = val; }
    public String getDataCriticality() { return this.dataCriticality; }

    @DataBoundSetter
	public void setViolationCriticality(String val) { this.violationCriticality = val; }
    public String getViolationCriticality() { return this.violationCriticality; }
    
    @Extension
	@Symbol(value = { "qualysAPIStaticAssessment" })
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
    	private final String URL_REGEX = "^(https)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
        private final String PROXY_REGEX = "^((https?)://)?[-a-zA-Z0-9+&@#/%?=~_|!,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
        private final String TOKEN_REGEX = "^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$";
        private boolean freeUserType = true;
        
    	@Override
        public String getDisplayName() {
    		return "Perform API Security Assessment with Qualys";
        }
		
    	public boolean isNonUTF8String(String string) {
        	if(string != null && !string.isEmpty()) {
	        	try 
	        	{
	        	    byte[] bytes = string.getBytes("UTF-8");
	        	} 
	        	catch (UnsupportedEncodingException e)
	        	{
	        	    return true;
	        	}
        	}
        	return false;
        }
        
        public FormValidation doCheckApiServer(@QueryParameter String apiServer) {
        	if(isNonUTF8String(apiServer)) {
            	return FormValidation.error("Please provide valid UTF-8 string value.");
            }
        	try {
        		String server = apiServer != null ? apiServer.trim() : "";
            	Pattern patt = Pattern.compile(URL_REGEX);
                Matcher matcher = patt.matcher(server);
            	
                if (!(matcher.matches())) {
                    return FormValidation.error("Server name is not valid!");
                } else {
                	 return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }

        public FormValidation doCheckCredsId(@QueryParameter String credsId) {
            try {
                if (credsId.trim().equals("")) {
                    return FormValidation.error("API Credentials cannot be empty.");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }
        
        public FormValidation doCheckSwaggerPath(@QueryParameter String swaggerPath) {
            try {
                if (swaggerPath.trim().equals("")) {
                    return FormValidation.error("Swagger Path cannot be empty.");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }
        
        @POST
        public ListBoxModel doFillCredsIdItems(@AncestorInPath Item item, @QueryParameter String credsId) {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
            	if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                	return result.add(credsId);
                }
            } else {
            	if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                	return result.add(credsId);
                }
            }
            return result
                    .withEmptySelection()
                    .withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item, null, Collections.<DomainRequirement>emptyList()))
                    .withMatching(CredentialsMatchers.withId(credsId));
        }
        
        @POST
        public ListBoxModel doFillApiIdItems(@AncestorInPath Item item, @QueryParameter String platform, @QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer, 
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy,@QueryParameter String token) {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel model = new StandardListBoxModel();
        	if(!token.isEmpty())
        	{
        		logger.info("API ID is not needed for free user type");
        		return model.withEmptySelection();
        	}
        	try {
        		if(isFilledInputs(platform, apiServer, credsId, useProxy, proxyServer)) {
        			int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
                	
                	String apiUser = "";
            		String apiPass = "";
            		String server = apiServer != null ? apiServer.trim() : "";
            		//set apiServer URL according to platform
                	if(!platform.equalsIgnoreCase("pcp")) {
                		Map<String, String> platformObj = Helper.platformsList.get(platform);
                		server = platformObj.get("url");
                		logger.info("Using qualys API Server URL: " + server);
                	}
            		if (StringUtils.isNotEmpty(credsId)) {

                        StandardUsernamePasswordCredentials c = CredentialsMatchers.firstOrNull(CredentialsProvider.lookupCredentials(
                                        StandardUsernamePasswordCredentials.class,
                                        item,
                                        null,
                                        Collections.<DomainRequirement>emptyList()),
                                CredentialsMatchers.withId(credsId));

                        apiUser = (c != null ? c.getUsername() : "");
                        apiPass = (c != null ? c.getPassword().getPlainText() : "");
                    }
            		QualysAuth auth = new QualysAuth();
                	auth.setQualysCredentials(server, apiUser, apiPass);
                	
                	String proxyUsername = "";
                	String proxyPassword = "";
                	if (StringUtils.isNotEmpty(proxyCredentialsId)) {

                        StandardUsernamePasswordCredentials c = CredentialsMatchers.firstOrNull(CredentialsProvider.lookupCredentials(
                                        StandardUsernamePasswordCredentials.class,
                                        item,
                                        null,
                                        Collections.<DomainRequirement>emptyList()),
                                CredentialsMatchers.withId(proxyCredentialsId));

                        proxyUsername = (c != null ? c.getUsername() : "");
                        proxyPassword = (c != null ? c.getPassword().getPlainText() : "");
                    }
                	if(useProxy) {
                    	auth.setProxyCredentials(proxyServer, proxyPortInt, proxyUsername, proxyPassword);
                	}
                	QualysAPISecClient client = new QualysAPISecClient(auth, System.out);
	        		JsonArray dataList = client.getAppList();
	        		if(dataList!=null)
	        		{
		        		for(JsonElement  webapp : dataList) {
		        			JsonObject obj = webapp.getAsJsonObject();
		        			String id = obj.get("id").getAsString();
		        			String name = obj.get("name").getAsString();
		        			Option e = new Option(name, id);
		                	model.add(e);
		        		}
	        		}
        		}
        	} catch(Exception e) {
        		e.printStackTrace();
        		//return object;
        	}
        	model.sort(Helper.OptionItemmsComparator);
        	return model.withEmptySelection();
        }
        
        public boolean isFilledInputs(String platform, String apiServer, String credsId, boolean useProxy, String proxyServer) {
			if(platform.equalsIgnoreCase("pcp") && StringUtils.isBlank(apiServer)) return false;
        	if(StringUtils.isBlank(credsId)) return false;
			if(useProxy && StringUtils.isBlank(proxyServer)) return false;
        	return true;
        }
        
        public List<Map<String, String>> getPlatforms() {
        	List<Map<String, String>> result = new ArrayList<Map<String, String>>();
        	for (Map.Entry<String, Map<String, String>> platform : Helper.platformsList.entrySet()) {
                Map<String, String>obj = platform.getValue();
                result.add(obj);
            }
            return result;
        }
        
        @POST
        public FormValidation doCheckConnection(@QueryParameter String platform, @QueryParameter String apiServer, @QueryParameter String credsId,
        		@QueryParameter String proxyServer, @QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, 
        		@QueryParameter boolean useProxy, @AncestorInPath Item item, @QueryParameter String token) {

	        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
	        	String proxyUsername = "";
	    		String proxyPassword = "";
	    		QualysAuth auth = new QualysAuth();
	    		int proxyPortInt = 0;
	    		String apiUser = "";
        		String apiPass = "";
        		String server = "";
        		logger.info("Is this a Free User Type : " + freeUserType);
        		try 
	    		{
        			if(!freeUserType)
        			{
		    			server = apiServer != null ? apiServer.trim() : "";
		        		//set apiServer URL according to platform
		            	if(!platform.equalsIgnoreCase("pcp")) {
		            		Map<String, String> platformObj = Helper.platformsList.get(platform);
		            		server = platformObj.get("url");
		            		logger.info("Using qualys API Server URL: " + server);
		            	}
		        		if (StringUtils.isNotEmpty(credsId)) {
		
		                    StandardUsernamePasswordCredentials c = CredentialsMatchers.firstOrNull(CredentialsProvider.lookupCredentials(
		                                    StandardUsernamePasswordCredentials.class,
		                                    item,
		                                    null,
		                                    Collections.<DomainRequirement>emptyList()),
		                            CredentialsMatchers.withId(credsId));
		
		                    apiUser = (c != null ? c.getUsername() : "");
		                    apiPass = (c != null ? c.getPassword().getPlainText() : "");
		                }
		        		
		            	auth.setQualysCredentials(server, apiUser, apiPass);
		    		}
        			if (StringUtils.isNotEmpty(proxyCredentialsId)) {
	
	                    StandardUsernamePasswordCredentials c = CredentialsMatchers.firstOrNull(CredentialsProvider.lookupCredentials(
	                                    StandardUsernamePasswordCredentials.class,
	                                    item,
	                                    null,
	                                    Collections.<DomainRequirement>emptyList()),
	                            CredentialsMatchers.withId(proxyCredentialsId));
	
	                    proxyUsername = (c != null ? c.getUsername() : "");
	                    proxyPassword = (c != null ? c.getPassword().getPlainText() : "");
        			}
        			if(useProxy) {
        				proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
        				auth.setProxyCredentials(proxyServer, proxyPortInt, proxyUsername, proxyPassword);
        			}
        			if(freeUserType)
        			{
		            	if(StringUtils.isNotEmpty(token))
		            	{
		            		auth.setToken(token);
		            		auth.setFreeUserType(freeUserType);
		            	}
		            	else
		            	{
		            		return FormValidation.error("Token should not be empty !!");
		            	}
        			}
		            QualysAPISecClient client = new QualysAPISecClient(auth, System.out);
		            QualysAPISecTestConnectionResponse resp = client.testConnection();
		            logger.info("Received response code: " + resp.responseCode);
		            if(!resp.success) {
		            	return FormValidation.error(resp.message);
		    	   	}
		            return FormValidation.ok("Token Validation Successful");
	    	    }
	        	catch (Exception e) 
        		{
		            logger.info("Exception in validate token: " + e.getMessage());
		            return FormValidation.error(e.getMessage());
		        }
	               
        }
        
        public FormValidation doCheckToken(@QueryParameter String token) {        	
        	try {
            	Pattern patt = Pattern.compile(TOKEN_REGEX);
                Matcher matcher = patt.matcher(token);
            	
                if (!(matcher.matches())) {
                    return FormValidation.error("Enter a valid token !");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }
        
        public FormValidation doCheckProxyServer(@QueryParameter String proxyServer) {
        	if(isNonUTF8String(proxyServer)) {
            	return FormValidation.error("Please provide valid UTF-8 string value.");
            }
        	try {
        		String server;
				if (proxyServer == null || proxyServer.trim().equals("")) {
					return FormValidation.error("Proxy server cannot be empty !");
				} else {
					server = proxyServer.trim();
				}
            	Pattern patt = Pattern.compile(PROXY_REGEX);
                Matcher matcher = patt.matcher(server);
            	
                if (!(matcher.matches())) {
                    return FormValidation.error("Enter valid proxy server !");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }
        
        public FormValidation doCheckProxyUser(@QueryParameter String proxyUser) {
        	if(isNonUTF8String(proxyUser)) {
            	return FormValidation.error("Please provide valid UTF-8 string value.");
            }
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckProxyPort(@QueryParameter String proxyPort) {
        	try {
        		if (proxyPort != null && !proxyPort.isEmpty() && proxyPort.trim().length() > 0) {
        			int proxyPortInt = Integer.parseInt(proxyPort);
        			if(proxyPortInt < 1 || proxyPortInt > 65535) {
        				return FormValidation.error("Please enter a valid port number!");
        			}
        		} else {
        			return FormValidation.error("Port number cannot be empty!");
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid port number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckGrade(@QueryParameter String grade) {
        	try {
        		if (grade != null && !grade.isEmpty() && grade.trim().length() > 0) {
        			float gradeFloat = Float.parseFloat(grade);
        			if(gradeFloat < 0 || gradeFloat > 100) {
        				return FormValidation.error("Please enter a valid grade score!");
        			}
        		}else {
        			return FormValidation.error("Please enter a valid grade!");
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid grade!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckDataGroupCount(@QueryParameter String dataGroupCount) {
        	try {
        		if (dataGroupCount != null && !dataGroupCount.isEmpty() && dataGroupCount.trim().length() > 0) {
        			int count = Integer.parseInt(dataGroupCount);
        			if(count < 0 ) {
        				return FormValidation.error("Please enter a valid input in Data Validation issues count field!");
        			}
        		}else {
        			return FormValidation.error("Data Validation issues count field should not be empty!");
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Please enter a valid number in Data Validation issues count field!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckViolationGroupCount(@QueryParameter String violationGroupCount) {
        	try {
        		if (violationGroupCount != null && !violationGroupCount.isEmpty() && violationGroupCount.trim().length() > 0) {
        			int count = Integer.parseInt(violationGroupCount);
        			if(count < 0 ) {
        				return FormValidation.error("Please enter a valid input in OAS Violation issues count field!");
        			}
        		}else {
        			return FormValidation.error("OAS Violation issues count field should not be empty!");
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Please enter a valid number in OAS Violation issues count field!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckSecurityGroupCount(@QueryParameter String securityGroupCount) {
        	try {
        		if (securityGroupCount != null && !securityGroupCount.isEmpty() && securityGroupCount.trim().length() > 0) {
        			int num = Integer.parseInt(securityGroupCount);
        			if(num < 0 ) {
        				return FormValidation.error("Please enter a valid input in Security issues count field!");
        			}
        		}else {
        			return FormValidation.error("Security issues count field should not be empty!");
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Please enter a valid number in Security issues count field!");
        	}
        	return FormValidation.ok();
        }
        
        @POST
        public ListBoxModel doFillPlatformItems() {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	ListBoxModel model = new ListBoxModel();
        	for(Map<String, String> platform: getPlatforms()) {
        		Option e = new Option(platform.get("name"), platform.get("code"));
            	model.add(e);
        	}
        	return model;
        }
        
        @POST
        public ListBoxModel doFillSecurityCriticalityItems() {
        	return fillItems();
        }
        
        @POST
        public ListBoxModel doFillDataCriticalityItems() {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	return fillItems();
        }
        
        @POST
        public ListBoxModel doFillViolationCriticalityItems() {
        	return fillItems();
        }
        
        public ListBoxModel fillItems()
        {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	ListBoxModel model = new ListBoxModel();
        	for(Severity sev : Severity.values())
    		{
        		Option opt = new Option(sev.getValue(), sev.getValue());
        		model.add(opt);
    		}
        	return model;
        }
        
        @POST
        public ListBoxModel doFillProxyCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String proxyCredentialsId) {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
            StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
            	if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                	return result.add(proxyCredentialsId);
                }
            } else {
            	if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                	return result.add(proxyCredentialsId);
                }
            }
            return result
                    .withEmptySelection()
                    .withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item, null, Collections.<DomainRequirement>emptyList()))
                    .withMatching(CredentialsMatchers.withId(proxyCredentialsId));
        }

		@Override
		public boolean isApplicable(Class<? extends AbstractProject> jobType) {
			return true;
		}
    }
    
    @Override
    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }
    
    public String getPluginVersion() {
    	try {
     	   MavenXpp3Reader reader = new MavenXpp3Reader();
            Model model;
            if ((new File("pom.xml")).exists())
              model = reader.read(new FileReader("pom.xml"));
            else
              model = reader.read(
                new InputStreamReader(
                		APISecurityNotifier.class.getResourceAsStream(
                    "/META-INF/maven/com.qualys.plugins/qualys-api-security/pom.xml"
                  )
                )
              );
            return model.getVersion();
        }catch(Exception e) {
     	   logger.info("Exception while reading plugin version; Reason :" + e.getMessage());
     	   return "unknown";
        }
	}
    
    
	@Override
    public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath filePath, @Nonnull Launcher launcher, @Nonnull TaskListener taskListener) throws InterruptedException, IOException {
    	taskListener.getLogger().println("Qualys API Static Assessment(version-"+ getPluginVersion() +") task - Started.");
	    	if ((apiId != null && !apiId.isEmpty()) || freeUserType) {
	             try {
	            	 Item project = run.getParent();
	            	 launchStaticAssessment(run, taskListener, project, filePath.absolutize(), launcher);
	            	 
	             } catch (Exception e) {
	            	 if(e.toString().equals("java.lang.Exception")) {
		            		throw new AbortException("Exception in Qualys API Static Assessment task. Finishing the build.");
		            	} else if (e.getMessage()!= null && e.getMessage().equalsIgnoreCase("sleep interrupted")) {
		            		logger.log(Level.SEVERE, "Error: User Aborted");
		            		throw new AbortException("User Aborted/Interrupted execution of the build.");
		            	}else {
			            	 logger.log(Level.SEVERE, "Error: "+e.getMessage());
			            	 e.printStackTrace();
			                 throw new AbortException(e.getMessage());
		            	}
	             }
	        } else {
	        	taskListener.getLogger().println("No APP ID Configured.");
	        	throw new AbortException("API ID can't be set to null or empty.");
	        }
        return;
    }
    
    public void launchStaticAssessment(Run<?, ?> run, TaskListener listener, Item project, FilePath workspace, Launcher launcher) throws Exception {
    	//Map<String, String> platformObj = Helper.platformsList.get(platform);
    	String portalUrl = apiServer;
    	String proxyUsername = "";
		String proxyPassword = "";
		String apiUser = "";
    	String apiPass = "";
    	QualysAuth auth = new QualysAuth();
    	//set apiServer URL according to platform
		/*
		 * if(!platform.equalsIgnoreCase("pcp") && StringUtils.isEmpty(this.token)) {
		 * setApiServer(platformObj.get("url"));
		 * logger.info("Using qualys API Server URL: " + apiServer); portalUrl =
		 * platformObj.get("portal"); }
		 */
    	
    	if(!freeUserType)
		{
    		listener.getLogger().println("Qualys Platform: " + platform +". Using Qualys API server: " + apiServer);
			try {
					StandardUsernamePasswordCredentials credential = CredentialsMatchers.firstOrNull(
							CredentialsProvider.lookupCredentials(
									StandardUsernamePasswordCredentials.class,
									project, ACL.SYSTEM,
									URIRequirementBuilder.fromUri(apiServer).build()),
							CredentialsMatchers.withId(credsId));
					
					if (credential != null) {
						apiUser = credential.getUsername();
						apiPass = credential.getPassword().getPlainText();
						if(apiPass.trim().equals("") || apiUser.trim().equals("")) {
							throw new Exception("Username and/or Password field is empty for credentials id: " + credsId);
						}
					}else {
						throw new Exception("Could not read credentials for credentials id: " + credsId);
					}
			}catch(Exception e){
				e.printStackTrace();
				throw new Exception("Invalid credentials! " + e.getMessage());
			}
			
			auth.setQualysCredentials(apiServer, apiUser, apiPass);
		}	
    	//test connection first
    	
    	if(freeUserType && StringUtils.isNotEmpty(token))
    	{
    		auth.setTokenServer(apiServer);
    		auth.setToken(token);
    		auth.setFreeUserType(freeUserType);
    	}
    	
    	if(useProxy) {
    		if (StringUtils.isNotEmpty(proxyCredentialsId)) {
    			StandardUsernamePasswordCredentials credential = CredentialsMatchers.firstOrNull(
    					CredentialsProvider.lookupCredentials(
    							StandardUsernamePasswordCredentials.class,
    							project, ACL.SYSTEM,
    							URIRequirementBuilder.fromUri(apiServer).build()),
    					CredentialsMatchers.withId(proxyCredentialsId));
    			
    			if (credential != null) {
    				proxyUsername = (credential != null ? credential.getUsername() : "");
                    proxyPassword = (credential != null ? credential.getPassword().getPlainText() : "");
    			}
            }
        	auth.setProxyCredentials(proxyServer, proxyPort, proxyUsername, proxyPassword);
    	}
    	
    	if ((apiId == null || apiId.isEmpty()) && !freeUserType) {
         	listener.getLogger().println("No API Id configured.");
         	return;
        }
    	
    	JsonObject criteriaObject = validateAndMakeCriteriaObject(listener, workspace);
    	boolean failConditionsConfigured = isFailOnGrade || isFailOnDataGroup || isFailOnSecurityGroup || isFailOnViolationGroup;
    	listener.getLogger().println("Using Build failure conditions: " + criteriaObject);
    	
    	logger.info("Qualys task - Started Static Assessment with Qualys API.");
    	Gson gson = new Gson();
    	String result = "";
    	String artifactsDir = run.getArtifactsDir().getAbsolutePath();
    	try {
			result = launcher.getChannel().call(new APISecLauncher(listener, apiId, 
	    			auth, portalUrl, swaggerPath, workspace.toString(), failConditionsConfigured, gson.toJson(criteriaObject)));
		}catch(Exception e) {
			e.printStackTrace(listener.getLogger());
			throw new Exception(e.getMessage());
		}
    	JsonParser jsonParser = new JsonParser();
    	JsonObject resultObj = jsonParser.parse(result).getAsJsonObject();
		Helper.createNewFile(run.getArtifactsDir(), "qualys_api_assess_result_" + apiId, "", listener.getLogger());
		Helper.writeArtifactFile(run.getArtifactsDir(), "qualys_api_assess_result_" + apiId, listener.getLogger(), resultObj);
    	if(resultObj != null && !resultObj.get("renderReport").isJsonNull() && resultObj.get("renderReport").getAsBoolean()) {
			ReportAction reportAction = new ReportAction(run, apiId, portalUrl, swaggerPath);
			run.addAction(reportAction);
    	}
    	listener.getLogger().println("Qualys task - Finished.");
        logger.info("Qualys task - Finished.");
        
        if(resultObj!=null && resultObj.has("failureMessage") && !resultObj.get("failureMessage").isJsonNull()) {
        	throw new Exception(resultObj.get("failureMessage").getAsString());
        }
    }
    
    public JsonObject validateAndMakeCriteriaObject(TaskListener listener, FilePath workspace) throws Exception{
    	JsonObject criteriaObject = new JsonObject();
    	JsonObject failConditions = new JsonObject();
    	//validate api id
    	if((apiId == null || StringUtils.isBlank(apiId)) && !freeUserType) {
    		throw new Exception("Invalid/missing API id. API id can't be set to null/empty.");
    	}
    	//validate swagger path
    	if(swaggerPath == null || StringUtils.isBlank(swaggerPath)) {
    		throw new Exception("Invalid/missing Swagger file path. Swagger file path can't be set to null/empty.");
    	}
    	
    	if(isFailOnGrade) {
    		try{
    			ValidateParameters.validateFloat(grade);
    		}catch(InvalidConfigurationException e){
    			throw new Exception("Invalid/missing configuration for 'grade' parameter value, provide valid float number.");
    		}
    		failConditions.addProperty("grade", grade);
    	}
		if (isFailOnSecurityGroup || isFailOnDataGroup || isFailOnViolationGroup) {
			JsonObject groupCriticality = new JsonObject();
			if (isFailOnSecurityGroup) {
				try {
					validateCriteriaObj("security", securityGroupCount, securityCriticality , groupCriticality);
				} catch (InvalidConfigurationException e) {
					throw new Exception(
							"Invalid/Missing configuration for security GroupCriticality configuration('securityCriticality' or 'securityGroupCount') parameter value, provide valid numbers.");
				}
			}
			if (isFailOnDataGroup) {
				try {
					validateCriteriaObj("data validation", dataGroupCount, dataCriticality, groupCriticality);
				} catch (InvalidConfigurationException e) {
					throw new Exception(
							"Invalid/Missing configuration for data GroupCriticality configuration('dataCriticality' or 'dataGroupCount') parameter value, provide valid numbers.");
				}

			}
			if (isFailOnViolationGroup) {
				try {
					validateCriteriaObj("oas violation", violationGroupCount, violationCriticality , groupCriticality);
				} catch (InvalidConfigurationException e) {
					throw new Exception(
							"Invalid/Missing configuration for violation GroupCriticality configuration('violationCriticality' or 'violationGroupCount') parameter value, provide valid numbers.");
				}
			}
			failConditions.add("groupCriticality", groupCriticality);
		}
    	criteriaObject.add("failConditions", failConditions);
    	return criteriaObject;
    }
    
    public void validateCriteriaObj(String criticalityGroup, String groupCount, String severity, JsonObject groupCriticality) throws InvalidConfigurationException
    {
    	ValidateParameters.validateSeverity(severity);
		ValidateParameters.validateGroupCountNumber(groupCount);
    	JsonObject obj = new JsonObject();
    	obj.addProperty("count", groupCount);
    	obj.addProperty("severity", severity);
		groupCriticality.add(criticalityGroup, obj);
    }
    
}
