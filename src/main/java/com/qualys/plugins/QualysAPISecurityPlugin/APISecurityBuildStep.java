package com.qualys.plugins.QualysAPISecurityPlugin;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.workflow.steps.AbstractStepDescriptorImpl;
import org.jenkinsci.plugins.workflow.steps.AbstractStepImpl;
import org.jenkinsci.plugins.workflow.steps.AbstractSynchronousNonBlockingStepExecution;
import org.jenkinsci.plugins.workflow.steps.StepContextParameter;
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
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysAuth.QualysAuth;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysClient.QualysAPISecClient;
import com.qualys.plugins.QualysAPISecurityPlugin.QualysClient.QualysAPISecTestConnectionResponse;
import com.qualys.plugins.QualysAPISecurityPlugin.util.Helper;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import jenkins.model.Jenkins;


public class APISecurityBuildStep extends AbstractStepImpl {
	private String platform;
	private String apiServer;
    private String credsId;
    private String apiId;
    private String proxyServer;
    private int proxyPort;
    private String proxyCredentialsId;
    private boolean useProxy = false;
    private String swaggerPath;
    private String newAppName;
    
    private boolean isFailOnGrade;
    private String grade;
    private boolean isFailOnSecurityGroup;
    private boolean isFailOnDataGroup;
    private boolean isFailOnValidationGroup;
    private String securityGroupCount;
    private String dataGroupCount;
    private String validationGroupCount;
    private String securityCriticality;
    private String dataCriticality;
    private String validationCriticality;
    
    private final static int PROXY_PORT = 80;
    
    private final static Logger logger = Helper.getLogger(APISecurityBuildStep.class.getName());
    
    public String getPlatform() { return platform; }
    
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
	public void setNewAppName(String newAppName) { this.newAppName = newAppName; }
    
    public String getNewAppName() { return newAppName;	}

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
	public void setIsFailOnValidationGroup(boolean flag) { this.isFailOnValidationGroup = flag; }
    public boolean getIsFailOnValidationGroup() { return this.isFailOnValidationGroup; }
    
    @DataBoundSetter
	public void setSecurityGroupCount(String val) { this.securityGroupCount = val; }
    public String getSecurityGroupCount() { return this.securityGroupCount; }
    
    @DataBoundSetter
	public void setDataGroupCount(String val) { this.dataGroupCount = val; }
    public String getDataGroupCount() { return this.dataGroupCount; }
    
    @DataBoundSetter
	public void setValidationGroupCount(String val) { this.validationGroupCount = val; }
    public String getValidationGroupCount() { return this.validationGroupCount; }
    
    @DataBoundSetter
	public void setSecurityCriticality(String val) { this.securityCriticality = val; }
    public String getSecurityCriticality() { return this.securityCriticality; }
    
    @DataBoundSetter
	public void setDataCriticality(String val) { this.dataCriticality = val; }
    public String getDataCriticality() { return this.dataCriticality; }

    @DataBoundSetter
	public void setValidationCriticality(String val) { this.validationCriticality = val; }
    public String getValidationCriticality() { return this.validationCriticality; }
    
	@DataBoundConstructor
    public APISecurityBuildStep( String platform, String apiServer, String credsId, boolean useProxy, String proxyServer, int proxyPort, String proxyCredentialsId,
    		String swaggerPath, String apiId, String newAppName, boolean isFailOnGrade, String grade, boolean isFailOnSecurityGroup,
    		String securityGroupCount, String securityCriticality, boolean isFailOnDataGroup, String dataGroupCount,	String dataCriticality,
    		boolean isFailOnValidationGroup, String validationGroupCount,	String validationCriticality) {
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
        if(isFailOnValidationGroup) {
        	this.isFailOnValidationGroup = true;
        	this.validationGroupCount = validationGroupCount;
        	this.validationCriticality = validationCriticality;
        }
    }

    @Extension
    public static final class DescriptorImpl extends AbstractStepDescriptorImpl {
       
        private final String URL_REGEX = "^(https)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
        private final String PROXY_REGEX = "^((https?)://)?[-a-zA-Z0-9+&@#/%?=~_|!,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
        
        public DescriptorImpl() {
            super(APISecurityBuildExecution.class);
        }

        @Override
        public String getFunctionName() { return "qualysAPIStaticAssessment"; }

        @Override
        public String getDisplayName() { return "Perform API Static Assesment"; }
        
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
        	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
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
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy) {
        	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
        	StandardListBoxModel model = new StandardListBoxModel();
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
                		logger.info("Using qualys API Server URL: " + apiServer);
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
                    	//int proxyPortInt = Integer.parseInt(proxyPort);
                    	auth.setProxyCredentials(proxyServer, proxyPortInt, proxyUsername, proxyPassword);
                	}
                	QualysAPISecClient client = new QualysAPISecClient(auth, System.out);
	        		JsonArray dataList = client.getAppList();
	        		for(JsonElement  webapp : dataList) {
	        			JsonObject obj = webapp.getAsJsonObject();
	        			String id = obj.get("id").getAsString();
	        			String name = obj.get("name").getAsString();
	        			Option e = new Option(name, id);
	                	model.add(e);
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
        		@QueryParameter boolean useProxy, @AncestorInPath Item item) {
        	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
        	try {
            	int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
            	
            	String apiUser = "";
        		String apiPass = "";
        		String proxyUsername = "";
        		String proxyPassword = "";
        		String server = apiServer != null ? apiServer.trim() : "";
        		//set apiServer URL according to platform
            	if(!platform.equalsIgnoreCase("pcp")) {
            		Map<String, String> platformObj = Helper.platformsList.get(platform);
            		server = platformObj.get("url");
            		logger.info("Using qualys API Server URL: " + apiServer);
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
        		QualysAuth auth = new QualysAuth();
            	auth.setQualysCredentials(server, apiUser, apiPass);
            	if(useProxy) {
                	//int proxyPortInt = Integer.parseInt(proxyPort);
                	auth.setProxyCredentials(proxyServer, proxyPortInt, proxyUsername, proxyPassword);
            	}
            	QualysAPISecClient client = new QualysAPISecClient(auth, System.out);
            	QualysAPISecTestConnectionResponse resp = client.testConnection();
            	logger.info("Received response : " + resp);
            	if(!resp.success) {
            		return FormValidation.error(resp.message);
    	   		}
            	return FormValidation.ok("Connection test successful!");
                
            } catch (Exception e) {
            	logger.info("Exception in test connection: " + e.getMessage());
            	return FormValidation.error("Connection test failed. (Reason: Wrong inputs. Please check API Server and Proxy details.)");
            }
        }
        
        public FormValidation doCheckProxyServer(@QueryParameter String proxyServer) {
        	if(isNonUTF8String(proxyServer)) {
            	return FormValidation.error("Please provide valid UTF-8 string value.");
            }
        	try {
            	Pattern patt = Pattern.compile(PROXY_REGEX);
                Matcher matcher = patt.matcher(proxyServer);
            	
                if (!(matcher.matches())) {
                    return FormValidation.error("Enter valid server url!");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }
        
        public FormValidation doCheckProxyPort(@QueryParameter String proxyPort) {
        	try {
        		if (proxyPort != null && !proxyPort.isEmpty() && proxyPort.trim().length() > 0) {
        			int proxyPortInt = Integer.parseInt(proxyPort);
        			if(proxyPortInt < 1 || proxyPortInt > 65535) {
        				return FormValidation.error("Please enter a valid port number!");
        			}
        		}else {
        			return FormValidation.error("Please enter a valid port number!");
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
        				return FormValidation.error("Please enter a valid number!");
        			}
        		}else {
        			return FormValidation.error("Please enter a valid number!");
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckValidationGroupCount(@QueryParameter String validationGroupCount) {
        	try {
        		if (validationGroupCount != null && !validationGroupCount.isEmpty() && validationGroupCount.trim().length() > 0) {
        			int count = Integer.parseInt(validationGroupCount);
        			if(count < 0 ) {
        				return FormValidation.error("Please enter a valid number!");
        			}
        		}else {
        			return FormValidation.error("Please enter a valid number!");
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckSecurityGroupCount(@QueryParameter String securityGroupCount) {
        	try {
        		if (securityGroupCount != null && !securityGroupCount.isEmpty() && securityGroupCount.trim().length() > 0) {
        			int num = Integer.parseInt(securityGroupCount);
        			if(num < 0 ) {
        				return FormValidation.error("Please enter a valid number!");
        			}
        		}else {
        			return FormValidation.error("Please enter a valid number!");
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        @POST
        public ListBoxModel doFillSecurityCriticalityItems() {
        	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
        	ListBoxModel model = new ListBoxModel();
	    	for(int i=1; i<=5; i++) {
	    		Option e1 = new Option(Integer.toString(i), Integer.toString(i));
		    	model.add(e1);
	    	}
        	return model;
        }
        
        @POST
        public ListBoxModel doFillDataCriticalityItems() {
        	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
        	ListBoxModel model = new ListBoxModel();
	    	for(int i=1; i<=5; i++) {
	    		Option e1 = new Option(Integer.toString(i), Integer.toString(i));
		    	model.add(e1);
	    	}
        	return model;
        }
        
        @POST
        public ListBoxModel doFillValidationCriticalityItems() {
        	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
        	ListBoxModel model = new ListBoxModel();
	    	for(int i=1; i<=5; i++) {
	    		Option e1 = new Option(Integer.toString(i), Integer.toString(i));
		    	model.add(e1);
	    	}
        	return model;
        }
        
        @POST
        public ListBoxModel doFillProxyCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String proxyCredentialsId) {
        	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
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
        
    }

    public static final class APISecurityBuildExecution extends AbstractSynchronousNonBlockingStepExecution<String> {

        private static final long serialVersionUID = 1L;

        @Inject
        private transient APISecurityBuildStep step;

        @StepContextParameter
        private transient Run run;
        @StepContextParameter
        private transient FilePath ws;
        @StepContextParameter
        private transient Launcher launcher;
        @StepContextParameter
        private transient TaskListener taskListener;

        @Override
        protected String run() throws Exception {
        	APISecurityNotifier notifier = new APISecurityNotifier(step.getApiServer(), step.getCredsId());
    		notifier.setApiId(step.getApiId());
			notifier.setUseProxy(step.getUseProxy());
    		notifier.setProxyServer(step.getProxyServer());
            notifier.setProxyPort(step.getProxyPort());
            notifier.setProxyCredentialsId(step.getProxyCredentialsId());
            //notifier.setProxyPassword(step.getProxyPassword().getPlainText());
            notifier.setPlatform(step.getPlatform());
            notifier.setSwaggerPath(step.getSwaggerPath());
            notifier.setNewAppName(step.getNewAppName());
            
            notifier.setIsFailOnGrade(step.getIsFailOnGrade());
            notifier.setGrade(step.getGrade());
            notifier.setIsFailOnSecurityGroup(step.getIsFailOnSecurityGroup());
            notifier.setSecurityGroupCount(step.getSecurityGroupCount());
            notifier.setSecurityCriticality(step.getSecurityCriticality());
            
            notifier.setIsFailOnDataGroup(step.getIsFailOnDataGroup());
            notifier.setDataGroupCount(step.getDataGroupCount());
            notifier.setDataCriticality(step.getDataCriticality());
            
            notifier.setIsFailOnValidationGroup(step.getIsFailOnValidationGroup());
            notifier.setValidationGroupCount(step.getValidationGroupCount());
            notifier.setValidationCriticality(step.getValidationCriticality());
    		notifier.perform(run, ws, launcher, taskListener);
        	
    		return "SUCCESS";
        }
    }
}
