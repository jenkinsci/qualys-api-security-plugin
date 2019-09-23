package com.qualys.plugins.QualysAPISecurityPlugin.report;

import java.io.File;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.qualys.plugins.QualysAPISecurityPlugin.util.Helper;

import hudson.Extension;
import hudson.model.Action;
import hudson.model.Run;

@Extension
public class ReportAction implements Action {
	private Run<?, ?> run;
	private String apiId;
	private String portalUrl;
	private String swaggerPath;
	public String grade;
	public String swaggerState;
	public String criticality;
	public String issueCounter;
	public String sectionWiseIssueCount;
	public String buildEvaluationResult;
	public String findingIdWiseData;
	
	private final static Logger logger = Helper.getLogger(ReportAction.class.getName());
	
	public ReportAction() { }
	
	public ReportAction(Run<?, ?> run, String apiId, String portalUrl, String swaggerPath) {
		this.run = run;
		this.portalUrl = portalUrl;
		this.apiId = apiId;
		this.swaggerPath = swaggerPath;
		setResult();
	}
	
	public String getApiId() {
		return apiId;
	}
	
	public String getSwaggerPath() {
		return swaggerPath;
	}
	
	public String getGrade() {
		return grade;
	}
	
	public String getSwaggerState() {
		return swaggerState;
	}
	
	public String getCriticality() {
		return criticality;
	}
	
	public String getIssueCounter() {
		return issueCounter;
	}
	
	public String getSectionWiseIssueCount() {
		return sectionWiseIssueCount;
	}
	
	public String getBuildEvaluationResult() {
		return buildEvaluationResult;
	}
	
	public String getFindingIdWiseData() {
		return findingIdWiseData;
	}
	
	
	
	public void setResult() {
    	JsonObject respObj;
    	try {
    		String filename = run.getArtifactsDir().getAbsolutePath() + File.separator + "qualys_api_assess_result_" + apiId + ".json";
        	File f = new File(filename);
        	Gson gson = new Gson();
        	if(f.getCanonicalPath().startsWith(run.getArtifactsDir().getAbsolutePath()) && f.exists()){
        		String resultStr = FileUtils.readFileToString(f);
	    		respObj = gson.fromJson(resultStr, JsonObject.class);
	    		
	    		GsonBuilder builder = new GsonBuilder();
    			Gson gsonObject = builder.serializeNulls().create(); // for null values
    			
    			String resultString = gsonObject.toJson(respObj);
	    		
    			JsonObject ele = gsonObject.fromJson(resultString, JsonObject.class);
    			
    			//set values
    			grade = (ele.has("grade") && !ele.get("grade").isJsonNull()) ? ele.get("grade").getAsString() : "-";
    			swaggerState = (ele.has("swaggerState") && !ele.get("swaggerState").isJsonNull()) ? ele.get("swaggerState").getAsString() : "-";
    			criticality = (ele.has("criticality") && !ele.get("criticality").isJsonNull()) ? ele.get("criticality").getAsString() : "-";
    			issueCounter = (ele.has("issueCounter") && !ele.get("issueCounter").isJsonNull()) ? ele.get("issueCounter").getAsString() : "-";
    			JsonObject sectionWiseObj = (ele.has("sectionWiseIssueCount") && !ele.get("sectionWiseIssueCount").isJsonNull()) ? ele.get("sectionWiseIssueCount").getAsJsonObject() : new JsonObject();
    			JsonObject buildEvalObj= (ele.has("buildEvaluationResult") && !ele.get("buildEvaluationResult").isJsonNull()) ? ele.get("buildEvaluationResult").getAsJsonObject() : new JsonObject();
    			JsonArray findingsObj = (ele.has("findingIdWiseData") && !ele.get("findingIdWiseData").isJsonNull()) ? ele.get("findingIdWiseData").getAsJsonArray() : new JsonArray();
    			sectionWiseIssueCount = gsonObject.toJson(sectionWiseObj);
    			buildEvaluationResult = gsonObject.toJson(buildEvalObj);
    			findingIdWiseData = gsonObject.toJson(findingsObj);
        	}
    	} catch(Exception e) {
    		logger.info("Error getting report object. Message: " + e.getMessage());
    	}
	}

	@Override
	public String getIconFileName() {
		return "clipboard.png";
	}

	@Override
	public String getDisplayName() {
		return "Qualys Static Assessment Report";
	}

	@Override
	public String getUrlName() {
		return "qualys_assessment.html";
	}
}