package com.qualys.plugins.QualysAPISecurityPlugin.QualysAuth;

class InvalidUserException extends Exception {
    @Override
    public String toString() {
        return "Invalid User";
    }
}
