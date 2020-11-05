package com.qualys.plugins.QualysAPISecurityPlugin.util;

public enum Severity 
{
	LOW("Low"), 
	MEDIUM("Medium"), 
	HIGH("High");
	
	
	private String value;
	
	private Severity(String value) 
	{ 
		this.value = value; 
	}
	
	public String getValue() {
        return value;
    }
	
	public static boolean containsValue(String val)
	{
		boolean found = false;
		for (Severity sevEnum : Severity.values()) {
	        if (sevEnum.getValue().equals(val)) 
			{
	        	found  = true;
	        }
	    }
		return found;
	}

}
