package com.qualys.plugins.QualysAPISecurityPlugin.QualysClient;

import com.google.gson.JsonObject;

public class QualysAPISecResponse extends QualysAPIResponse{
    public JsonObject response;

    public QualysAPISecResponse() {
        super();
        response = null;
    }
}
