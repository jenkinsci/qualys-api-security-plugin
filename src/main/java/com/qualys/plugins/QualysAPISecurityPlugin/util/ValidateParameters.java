package com.qualys.plugins.QualysAPISecurityPlugin.util;

public class ValidateParameters {
	public static void validateFloat(String score) throws InvalidConfigurationExcetpion {
		if(score == null) {
			throw new InvalidConfigurationExcetpion();
		}
		try {
			float num = Float.parseFloat(score);
		}catch(Exception e) {
			throw new InvalidConfigurationExcetpion();
		}
	}
	
	public static void validateCriticalityNumber(String score) throws InvalidConfigurationExcetpion {
		if(score == null) {
			throw new InvalidConfigurationExcetpion();
		}
		try {
			float num = Integer.parseInt(score);
			if(num < 1 || num > 5) {
				throw new InvalidConfigurationExcetpion();
			}
		}catch(Exception e) {
			e.printStackTrace();
			throw new InvalidConfigurationExcetpion();
		}
	}
	
	public static void validateGroupCountNumber(String score) throws InvalidConfigurationExcetpion {
		if(score == null) {
			throw new InvalidConfigurationExcetpion();
		}
		try {
			float num = Integer.parseInt(score);
			if(num < 0) {
				throw new InvalidConfigurationExcetpion();
			}
		}catch(Exception e) {
			throw new InvalidConfigurationExcetpion();
		}
	}
}