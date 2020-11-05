package com.qualys.plugins.QualysAPISecurityPlugin.util;

public class ValidateParameters 
{
	public static void validateFloat(String score) throws InvalidConfigurationException {
		if(score == null) {
			throw new InvalidConfigurationException();
		}
		try {
			float num = Float.parseFloat(score);
			if(num > 100.00 || num < 0.00)
			{
				throw new InvalidConfigurationException();
			}
		}
		catch(Exception e) {
			throw new InvalidConfigurationException();
		}
	}
	
	public static void validateSeverity(String sev) throws InvalidConfigurationException {
		boolean found = false;
		if(sev == null) {
			throw new InvalidConfigurationException();
		}
		try {
			if(!Severity.containsValue(sev)) {
				throw new InvalidConfigurationException();
			}
		}catch(Exception e) {
			e.printStackTrace();
			throw new InvalidConfigurationException();
		}
	}
	
	public static void validateGroupCountNumber(String count) throws InvalidConfigurationException {
		if(count == null) {
			throw new InvalidConfigurationException();
		}
		try {
			float num = Integer.parseInt(count);
			if(num < 0) {
				throw new InvalidConfigurationException();
			}
		}catch(Exception e) {
			throw new InvalidConfigurationException();
		}
	}
}