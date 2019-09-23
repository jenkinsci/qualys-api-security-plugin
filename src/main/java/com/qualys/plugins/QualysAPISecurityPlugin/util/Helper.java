package com.qualys.plugins.QualysAPISecurityPlugin.util;


import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import hudson.util.ListBoxModel.Option;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class Helper {
	
	private final static Logger logger = Logger.getLogger(Helper.class.getName());
	
	public static final Map<String, Map<String, String>> platformsList;
    static {
    	Map<String, Map<String, String>> aList = new LinkedHashMap<String,Map<String, String>>();
    	
    	Map<String, String> platform1 = new HashMap <String, String>();
    	platform1.put("name", "US Platform 1"); platform1.put("code", "US_PLATFORM_1"); platform1.put("url", "https://qualysapi.qualys.com");
    	platform1.put("portal", "https://qualysguard.qualys.com"); aList.put("US_PLATFORM_1", platform1);
    	
    	Map<String, String> platform2 = new HashMap <String, String>();
    	platform2.put("name", "US Platform 2"); platform2.put("code", "US_PLATFORM_2"); platform2.put("url", "https://qualysapi.qg2.apps.qualys.com"); 
    	platform2.put("portal", "https://qualysguard.qg2.apps.qualys.com"); aList.put("US_PLATFORM_2", platform2);
    	
    	Map<String, String> platform3 = new HashMap <String, String>();
    	platform3.put("name", "US Platform 3"); platform3.put("code", "US_PLATFORM_3"); platform3.put("url", "https://qualysapi.qg3.apps.qualys.com"); 
    	platform3.put("portal", "https://qualysguard.qg3.apps.qualys.com"); aList.put("US_PLATFORM_3", platform3);
    	
    	Map<String, String> platform4 = new HashMap <String, String>();
    	platform4.put("name", "US Platform 4"); platform4.put("code", "US_PLATFORM_4"); platform4.put("url", "https://qualysapi.qg4.apps.qualys.com");
    	platform4.put("portal", "https://qualysguard.qg4.apps.qualys.com"); aList.put("US_PLATFORM_4", platform4);
    	
    	Map<String, String> platform5 = new HashMap <String, String>();
    	platform5.put("name", "EU Platform 1"); platform5.put("code", "EU_PLATFORM_1"); platform5.put("url", "https://qualysapi.qualys.eu");
    	platform5.put("portal", "https://qualysguard.qualys.eu"); aList.put("EU_PLATFORM_1", platform5);
    	
    	Map<String, String> platform6 = new HashMap <String, String>();
    	platform6.put("name", "EU Platform 2"); platform6.put("code", "EU_PLATFORM_2"); platform6.put("url", "https://qualysapi.qg2.apps.qualys.eu");
    	platform6.put("portal", "https://qualysguard.qg2.apps.qualys.eu"); aList.put("EU_PLATFORM_2", platform6);
    	
    	Map<String, String> platform7 = new HashMap <String, String>();
    	platform7.put("name", "INDIA Platform"); platform7.put("code", "INDIA_PLATFORM"); platform7.put("url", "https://qualysapi.qg1.apps.qualys.in");
    	platform7.put("portal", "https://qualysguard.qg1.apps.qualys.in"); aList.put("INDIA_PLATFORM", platform7);
    	
    	Map<String, String> platform8 = new HashMap <String, String>();
    	platform8.put("name", "Private Cloud Platform"); platform8.put("code", "PCP"); platform8.put("url", "");
    	aList.put("PCP", platform8);
    	
    	platformsList = Collections.unmodifiableMap(aList);
    }
    
    public static void createNewFile(String rootDir, String filename, String content, PrintStream buildLogger) throws Exception {
	  	   	
    	File f = new File(rootDir + File.separator + filename + ".json");
	    if(!f.getParentFile().exists()){
	        f.getParentFile().mkdirs();
	    }
	    
	    if(!f.getCanonicalPath().startsWith(rootDir)) {
	    	throw new Exception("Can not create file due to security reasons. Suspecious filename - "+ f.getCanonicalPath() + ".");
	    }

	    if(!f.exists()){
	        try {
	            f.createNewFile();
	        } catch (Exception e) {
	            e.printStackTrace();
	            buildLogger.println("Failed creating file " + filename + ", reason =" + e.getMessage());
	        }
	    }
	    try {
	        File dir = new File(f.getParentFile(), f.getName());
	        PrintWriter writer = new PrintWriter(dir);
	        writer.print(content);
	        writer.close();
	    } catch (FileNotFoundException e) {
	    	e.printStackTrace();
	    	buildLogger.println("Failed writing to file " + filename + ", reason =" + e.getMessage());
	    }
    }
    
    public static void writeArtifactFile(String rootDir, String filename, PrintStream buildLogger,	JsonObject evalresult) throws Exception {
		Gson gson = new Gson();
		File f = new File(rootDir + File.separator + filename + ".json");
		if(!f.getCanonicalPath().startsWith(rootDir)) {
	    	throw new Exception("Can not write file due to security reasons. Suspecious filename - "+ f.getCanonicalPath() + ".");
	    }
		if(f.exists()){
    		String contentStr = FileUtils.readFileToString(f);
    		JsonObject respObj = gson.fromJson(contentStr, JsonObject.class);
    		
    		GsonBuilder builder = new GsonBuilder();
			gson = builder.serializeNulls().create(); // for null values
			
			String final_content = gson.toJson(evalresult);
			
    		try {
    	        File dir = new File(f.getParentFile(), f.getName());
    	        PrintWriter writer = new PrintWriter(dir);
    	        writer.print(final_content);
    	        writer.close();
    	    } catch (FileNotFoundException e) {
    	    	e.printStackTrace();
    	    	buildLogger.println("Failed writing to file " + filename + ", reason =" + e.getMessage());
    	    }
    	}
	}
	
	public static Logger getLogger(String loggerName) {
    	Logger pluginLogger = Logger.getLogger(loggerName);
    	try {
    		pluginLogger.setUseParentHandlers(false);
	    	QualysLogFormatter formatter = new QualysLogFormatter();
	    	Handler handler = new ConsoleHandler();
	    	handler.setFormatter(formatter);
	    	pluginLogger.addHandler(handler);
    	} catch(Exception e) {
    		logger.info("Error while formatting logger, reason: " + e.getMessage());
    	}
    	return pluginLogger;
    }
	
	public static Comparator<Option> OptionItemmsComparator = new Comparator<Option>() {
        @Override
        public int compare(Option e1, Option e2) {
            return e1.name.toLowerCase().compareTo(e2.name.toLowerCase());
        }
    };
	
	public static class QualysLogFormatter extends Formatter {
        // Create a DateFormat to format the logger timestamp.
        private static final DateFormat df = new SimpleDateFormat("MMM dd, yyyy hh:mm:ss a");

        public String format(LogRecord record) {
            StringBuilder builder = new StringBuilder(1000);
            builder.append(df.format(new Date(record.getMillis()))).append(" - ");
            builder.append("[").append(record.getSourceClassName()).append(".");
            builder.append(record.getSourceMethodName()).append("] - ");
            builder.append(record.getLevel()).append(": ");
            builder.append(formatMessage(record));
            builder.append("\n");
            return builder.toString();
        }

        public String getHead(Handler h) {
            return super.getHead(h);
        }

        public String getTail(Handler h) {
            return super.getTail(h);
        }
    }

}