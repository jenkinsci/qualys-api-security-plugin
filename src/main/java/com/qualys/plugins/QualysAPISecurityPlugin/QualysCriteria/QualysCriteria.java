package com.qualys.plugins.QualysAPISecurityPlugin.QualysCriteria;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import com.qualys.plugins.QualysAPISecurityPlugin.util.Helper;
import com.qualys.plugins.QualysAPISecurityPlugin.util.Severity;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.apache.commons.lang.ArrayUtils;

public class QualysCriteria {
	ArrayList<String> failedReasons  = new ArrayList<>(0);
	Gson gsonObject = new Gson();
	public JsonObject returnObject;
	public float grade;
	private boolean isGradeConfigured = false;
	private boolean isGroupCriticalityConfigured = false;
	private JsonObject groupCriticalityConfig;
	private Map<String, Map<String, Integer>> groupCriticalityCounts;
	Map<String,Integer> securityCountMap;
	Map<String,Integer> dataCountMap;
	Map<String,Integer> oasCountMap;
	String[] sevArray = {"Low","Medium","High"};
	
	private final static Logger logger = Helper.getLogger(QualysCriteria.class.getName());
	

	public QualysCriteria(String criteriaJson) throws InvalidCriteriaException {
		JsonParser jsonParser = new JsonParser();
		JsonElement jsonTree = jsonParser.parse(criteriaJson);
		if (!jsonTree.isJsonObject()) {
			throw new InvalidCriteriaException();
		}

		this.setDefaultValues();
		
		JsonObject jsonObject = jsonTree.getAsJsonObject();
		if (jsonObject.has("failConditions")) {
			JsonObject failConditions = jsonObject.getAsJsonObject("failConditions");
			//grade
			if (failConditions.has("grade") && !failConditions.get("grade").isJsonNull()) {
				String gradeStr = failConditions.get("grade").getAsString();
				grade = Float.parseFloat(gradeStr);
				isGradeConfigured = true;
				JsonObject conf = new JsonObject();
				conf.add("found", null);
				conf.addProperty("result", true);
				conf.addProperty("configured", gradeStr);
				returnObject.add("grade", conf);
			}
			
			// groupCriticality
			if (failConditions.has("groupCriticality") && !failConditions.get("groupCriticality").isJsonNull()) {
				JsonObject groupCriticalityConf = new JsonObject();
				JsonObject groupCriticality = failConditions.get("groupCriticality").getAsJsonObject();
				String[] fields = {"security" , "data validation", "oas violation"};
					
				for(String field: fields)
				{
					if (groupCriticality.has(field) && !groupCriticality.get(field).isJsonNull()) {
						JsonObject conf = new JsonObject();
						conf.add("found", null);
						conf.addProperty("result", true);
						JsonObject configured = groupCriticality.get(field).getAsJsonObject();
						conf.add("configured", configured);
						groupCriticalityConf.add(field, conf);
						isGroupCriticalityConfigured = true;
						groupCriticalityConfig.add(field, configured);
					}
					
				}
				returnObject.add("groupCriticality", groupCriticalityConf);
			}
		}
	}

	private void setDefaultValues() {
		this.returnObject = new JsonObject();
		
		securityCountMap = new LinkedHashMap<String,Integer>();
		dataCountMap = new LinkedHashMap<String,Integer>();
		oasCountMap = new LinkedHashMap<String,Integer>();
		
		for(Severity sev : Severity.values())
		{
			securityCountMap.put(sev.getValue(), 0);
			dataCountMap.put(sev.getValue(), 0);
			oasCountMap.put(sev.getValue(), 0);	
		}
		
		
		groupCriticalityCounts = new LinkedHashMap<String, Map<String, Integer>>();
		
		groupCriticalityCounts.put("security", securityCountMap);
		
		Gson gson = new Gson(); 
		String jsonString = gson.toJson(securityCountMap);
		
		Type type = new TypeToken<HashMap<String, Integer>>(){}.getType();
		groupCriticalityCounts.put("data validation", gson.fromJson(jsonString, type));
		groupCriticalityCounts.put("oas violation", gson.fromJson(jsonString, type));
		 
		
		groupCriticalityConfig = new JsonObject();
		groupCriticalityConfig.add("security", new JsonObject());
		groupCriticalityConfig.add("data validation", new JsonObject());
		groupCriticalityConfig.add("oas violation", new JsonObject());
	} // setDefaultValues

	public Boolean evaluate(JsonObject response) {
		boolean status = true;
		//evaluate for grade
		if (isGradeConfigured && response.has("grade") && !response.get("grade").isJsonNull()) {
			String confGradeStr = response.get("grade").getAsString();
			float foundGradeFloat = Float.parseFloat(confGradeStr);
			JsonObject conf = new JsonObject();
			conf.addProperty("found", confGradeStr);
			conf.addProperty("result", true);
			conf.addProperty("configured", grade);
			if(foundGradeFloat < grade) {
				conf.addProperty("result", false);
				status = false;
				failedReasons.add("Failing the build because grade configured is: " + grade +" and found: " + confGradeStr);
			}
			returnObject.add("grade", conf);
		}
		
		if (response.has("findingIdWiseData") && !response.get("findingIdWiseData").isJsonNull()) {
			JsonArray findingIds = response.get("findingIdWiseData").getAsJsonArray();			
			
			for (JsonElement ele : findingIds) {
				JsonObject obj = ele.getAsJsonObject();
				String group = obj.get("sectionType").getAsString().toLowerCase();
				if(obj.has("findings") && !obj.get("findings").isJsonNull()) {
					JsonArray findings = obj.get("findings").getAsJsonArray();
					for (JsonElement findingEle : findings) {
						JsonObject findingObj = findingEle.getAsJsonObject();
						//calculate for groupCriticality
						String criticalityFound = findingObj.get("criticality").getAsString();
						if(groupCriticalityCounts.containsKey(group) && groupCriticalityCounts.get(group) != null) 
						{
							criticalityFound = Helper.criticalityToSeverity(Integer.parseInt(criticalityFound));
							
							if(group.equals("security") && securityCountMap.containsKey(criticalityFound))
							{
								securityCountMap.put(criticalityFound,securityCountMap.get(criticalityFound) +1);
							}
							if(group.equals("data validation") && dataCountMap.containsKey(criticalityFound))
							{
								dataCountMap.put(criticalityFound,dataCountMap.get(criticalityFound) +1);
							}
							if(group.equals("oas violation") && oasCountMap.containsKey(criticalityFound))
							{
								oasCountMap.put(criticalityFound,oasCountMap.get(criticalityFound) +1);
							}
						}
					}
				}
			}
			
			groupCriticalityCounts.put("security",securityCountMap);
			groupCriticalityCounts.put("data validation",dataCountMap);
			groupCriticalityCounts.put("oas violation",oasCountMap);
			
			Gson gson = new Gson();
			returnObject.add("groupCriticalityCounts", gson.fromJson(gson.toJson(groupCriticalityCounts), JsonObject.class));
			//evaluate for groupCriticality
			if(isGroupCriticalityConfigured) {
				JsonObject result = new JsonObject();
				for (Map.Entry<String,JsonElement> entry : groupCriticalityConfig.entrySet()) {
					String group = entry.getKey();
					JsonObject obj = entry.getValue().getAsJsonObject();
					JsonElement countObj = obj.get("count");
					if(countObj!= null && !countObj.isJsonNull()) {
						String countStr = countObj.getAsString();
						int countConfigured = Integer.parseInt(countStr);
						String criticalityConfigured = obj.get("severity").getAsString();

						//default values
						JsonObject conf = new JsonObject();
						conf.addProperty("found", 0);
						conf.addProperty("result", true);
						JsonObject configured = new JsonObject();
						configured.addProperty("count", countConfigured);
						configured.addProperty("criticality", criticalityConfigured);
						conf.add("configured", configured);
						
						//evaluate
						int countFound = 0;
						if(groupCriticalityCounts.containsKey(group))
						{
							 for(int i=ArrayUtils.indexOf(sevArray, criticalityConfigured); i<3;i++)
							 {
								 countFound += groupCriticalityCounts.get(group).get(sevArray[i]);
							 }
						}
						conf.addProperty("found", countFound);
						if(countFound > countConfigured) {
							status = false;
							conf.addProperty("result", false);
							failedReasons.add("Failing the build because the number of issues found for '"+ group.toUpperCase() +"' with Severity: '"+ criticalityConfigured +" or above' is more than the configured count ; Configured: " + countStr + ", Found: " + countFound);
						}
						result.add(group, conf);
					}
					returnObject.add("groupCriticality", result);
				}
			}
		}
		
		return status;
	}
    
	
	public ArrayList<String> getBuildFailedReasons() {
		return (ArrayList<String>) this.failedReasons.stream().distinct().collect(Collectors.toList());
    }	
		
}
