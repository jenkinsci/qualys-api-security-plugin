package com.qualys.plugins.QualysAPISecurityPlugin.QualysCriteria;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import com.qualys.plugins.QualysAPISecurityPlugin.util.Helper;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class QualysCriteria {
	ArrayList<String> failedReasons  = new ArrayList<>(0);
	Gson gsonObject = new Gson();
	public JsonObject returnObject;
	public float grade;
	private boolean isGradeConfigured = false;
	private boolean isGroupCriticalityConfigured = false;
	private JsonObject groupCriticalityConfig;
	private HashMap<String, HashMap<String, Integer>> groupCriticalityCounts;
	
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
				if (groupCriticality.has("security") && !groupCriticality.get("security").isJsonNull()) {
					JsonObject conf = new JsonObject();
					conf.add("found", null);
					conf.addProperty("result", true);
					JsonObject configured = groupCriticality.get("security").getAsJsonObject();
					conf.add("configured", configured);
					groupCriticalityConf.add("security", conf);
					isGroupCriticalityConfigured = true;
					groupCriticalityConfig.add("security", configured);
				}
				if (groupCriticality.has("data") && !groupCriticality.get("data").isJsonNull()) {
					JsonObject conf = new JsonObject();
					conf.add("found", null);
					conf.addProperty("result", true);
					JsonObject configured = groupCriticality.get("data").getAsJsonObject();
					conf.add("configured", configured);
					groupCriticalityConf.add("data", conf);
					isGroupCriticalityConfigured = true;
					groupCriticalityConfig.add("data", configured);
				}
				if (groupCriticality.has("validation") && !groupCriticality.get("validation").isJsonNull()) {
					JsonObject conf = new JsonObject();
					conf.add("found", null);
					conf.addProperty("result", true);
					JsonObject configured = groupCriticality.get("validation").getAsJsonObject();
					conf.add("configured", configured);
					groupCriticalityConf.add("validation", conf);
					isGroupCriticalityConfigured = true;
					groupCriticalityConfig.add("validation", configured);
				}
				returnObject.add("groupCriticality", groupCriticalityConf);
			}
		}
	}

	private void setDefaultValues() {
		this.returnObject = new JsonObject();
		
		groupCriticalityCounts = new HashMap<String, HashMap<String, Integer>>();
		HashMap<String, Integer> counter = new HashMap<String, Integer>();
		counter.put("1", 0);
		counter.put("2", 0);
		counter.put("3", 0);
		counter.put("4", 0);
		counter.put("5", 0);
		groupCriticalityCounts.put("security", counter);
		
		Gson gson = new Gson();
		String jsonString = gson.toJson(counter);
		Type type = new TypeToken<HashMap<String, Integer>>(){}.getType();
		groupCriticalityCounts.put("data", gson.fromJson(jsonString, type));
		groupCriticalityCounts.put("validation", gson.fromJson(jsonString, type));
		
		groupCriticalityConfig = new JsonObject();
		groupCriticalityConfig.add("security", new JsonObject());
		groupCriticalityConfig.add("data", new JsonObject());
		groupCriticalityConfig.add("validation", new JsonObject());
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
				if(obj.has("findings") && !obj.get("findings").isJsonNull()) {
					JsonArray findings = obj.get("findings").getAsJsonArray();
					for (JsonElement findingEle : findings) {
						JsonObject findingObj = findingEle.getAsJsonObject();
						//calculate for groupCriticality
						String group = findingObj.get("group").getAsString().toLowerCase();
						String criticalityFound = findingObj.get("criticality").getAsString();
						if(groupCriticalityCounts.containsKey(group) && groupCriticalityCounts.get(group) != null) {
							int count = groupCriticalityCounts.get(group).get(criticalityFound);
							count++;
							groupCriticalityCounts.get(group).put(criticalityFound, count);
						}
					}
				}
			}
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
						String criticalityConfigured = obj.get("criticality").getAsString();
						int criticalityConfiguredInt = Integer.parseInt(criticalityConfigured);
						
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
						for(int i=criticalityConfiguredInt; i<=5; i++) {
							countFound += groupCriticalityCounts.get(group).get(Integer.toString(i));
						}
						conf.addProperty("found", countFound);
						if(countFound > countConfigured) {
							status = false;
							conf.addProperty("result", false);
							failedReasons.add("Failing the build because no. of findings for '"+ group + "' with criticality more than or equals to "+ criticalityConfigured + "; configured: " + countStr + ", Found: " + countFound);
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
