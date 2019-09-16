# Qualys API Security Plugin

## About

The Qualys API Security Plugin for Jenkins empowers you to assess API in their existing CI/CD processes with help of Qualys API Security module. Integrating this assessment step will help you catch and eliminate API related flaws. This plugin supports pipeline as well as free-style projects.

## How this plugin works

When the plugin step starts, it uploads your swagger file to Qualys API Security module against the configured API record. Qualys API Security module quickly analyzes it and responds with findings and Grade score. If you have configured any pass/fail criteria, the plugin evaluates the response against that. If it finds something is not matching your criteria, it will cause exception to fail your build. Otherwise, your build job proceeds to next step (if any). 

## How to use this plugin

### Prerequisites

* A valid Qualys subscription with access to API Security module, and Qualys APIs.


### Where to use this plugin step

We recommend using this plugin step during "Build" phase of your job, right after you checkout your source code. 

### Configuration

If you are using pipeline, you should go to "Pipeline Syntax", and select `qualysAPIStaticAssessment` step.
If you are using freestyle, you should add `qualysAPIStaticAssessment` build step.

A form appears with several input fields. Now you are ready to configure the plugin. 

#### Qualys Credentials

1. Select your Qualys Portal from given dropdown. 
2. Select/Add your Qualys API Credentials.
3. If you need proxy to communicate to the Internet, set correct proxy settings. 
4. To confirm that Jenkins can communicate to Qualys Cloud Platform and APIs, use `Test Connection` button.

#### APIs to Scan

1. The "Select API to Scan" field lists all the API entries you have made to Qualys API Security module. Select the one for which you want to scan the swagger file. *Please note* that, the APIs are not automatically populated in this dropdown. You should have assessed the swagger file through the API Security module on the Qualys UI at least once before. 
2. In "Swagger file path" field, provide path to your swagger file relative to Jenkins' workspace directory for your project. 

#### Pass/Fail Criteria

You can optionally fail the build based on grade score or findings criticality. 

1. If you want to fail the build based on grade score, tick the checkbox for "Fail with less than Grade score" and configure minimum score acceptable to you. If score is below your value, plugin will fail the build. 
2. If you want to gail the build based on Security, Validation or Data findings, tick the appropriate checkbox and configure acceptable criticality value. If criticality found is more than configured value, plugin will fail the build. *Note that* a Qualys criticality `5` rating is the most dangerous vulnerability while criticality `1` is the least. 

### Genrate Pipeline Script *(for pipeline project only)*

If you are configuring pipeline project, click the `Generate Pipeline Script` button. It will give you a command which you can copy and paste in your project's pipeline script. 


