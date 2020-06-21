/** *******************************************************************************
*  Copyright 2019 T-Mobile, US
*   
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*  
*     http://www.apache.org/licenses/LICENSE-2.0
*  
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*  See the readme.txt file for additional language around disclaimer of warranties.
*********************************************************************************** */

package com.tmobile.cso.vault.api.controller;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;

import com.tmobile.cso.vault.api.model.*;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.exception.LogMessage;
import com.tmobile.cso.vault.api.exception.TVaultValidationException;
import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.process.Response;
import com.tmobile.cso.vault.api.utils.JSONUtil;
import com.tmobile.cso.vault.api.utils.ThreadLocalContext;
@Component
public final class ControllerUtil {
	
	private static RequestProcessor reqProcessor;
	public static final Logger log = LogManager.getLogger(ControllerUtil.class);

	@Value("${vault.auth.method}")
    private String tvaultAuthMethod;

	private static String vaultAuthMethod;
	
	@Value("${vault.secret.key.whitelistedchars:[a-z0-9_]+}")
    private String secretKeyWhitelistedCharacters;
	
	@Value("${vault.approle.name.whitelistedchars:[a-z0-9_]+}")
	private String approleWhitelistedCharacters;
	
	@Value("${vault.sdb.name.whitelistedchars:[a-z0-9_-]+}")
	private String sdbNameWhitelistedCharacters; 
	
	private static String secretKeyAllowedCharacters;
	
	private static String approleAllowedCharacters;
	
	private static String sdbNameAllowedCharacters="[a-z0-9_-]+";
	
	private static final String[] mountPaths = {"apps","shared","users"};
	private static final String[] permissions = {"read", "write", "deny", "sudo"};
	
	@Value("${selfservice.ssfilelocation}")
    private String sscredLocation;

	private static String ssUsername;
	private static String ssPassword;
	private static SSCred sscred = null;
	
	private static final String RECURSIVE_DELETE_MSG = "recursivedeletesdb";
	private static final String UNEXPECTED_ERROR_STRING = "{\"errors\":[\"Unexpected error :";
	private static final String SDB_LIST = "/sdb/list";
	private static final String PATH_STRING = "{\"path\":\"";
	private static final String READ_SECRETS = "/read";
	private static final String USERNAME_STR = "username";
	private static final String POLICIES_STR = "policies";
	private static final String UPDATE_METADATA_STR = "updateMetadata";
	private static final String ACCESS_STR = "access";
	private static final String METADATA_STR = "metadata/";
	private static final String DATA_STRING = "\",\"data\":";
	private static final String WRITE_SECRETS = "/write";
	private static final String UPDATE_USER_POLICY_STR = "updateUserPolicyAssociationOnSDBDelete";
	private static final String UPDATE_AWS_ROLE_POLICY_STR = "updateAwsRolePolicyAssociationOnSDBDelete";
	private static final String DELETE_AWS_ROLE_SDB_STR = "deleteAwsRoleOnSDBDelete";
	private static final String FAILED_LOWERCASE_CONVERSION_MSG = "Failed to convert [%s] to lowercase.";
	private static final String ROLE_REQUIRED_STR = "Role is required.";
	private static final String USERNAME_SSCRED_STR = "username:";
	private static final String PASSWRD_SSCRED_STR = "password:";
	

	@PostConstruct     
	private void initStatic () {
		vaultAuthMethod = this.tvaultAuthMethod;
		secretKeyAllowedCharacters = this.secretKeyWhitelistedCharacters;
		approleAllowedCharacters = this.approleWhitelistedCharacters;
		sdbNameAllowedCharacters = this.sdbNameWhitelistedCharacters;		
		readSSCredFile(this.sscredLocation, true);
	}

	@Autowired(required = true)
	public void setReqProcessor(RequestProcessor reqProcessor) {
		ControllerUtil.reqProcessor = reqProcessor;
	}

	/**
	 * Method to get requestProcessor
	 * @return
	 */
	public static RequestProcessor getReqProcessor() {
		return ControllerUtil.reqProcessor;
	}

	public static void recursivedeletesdb(String jsonstr,String token,  Response responseVO){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, RECURSIVE_DELETE_MSG).
				put(LogMessage.MESSAGE, "Trying recursive delete...").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		ObjectMapper objMapper =  new ObjectMapper();
		String path = TVaultConstants.EMPTY;
		try {
			path = objMapper.readTree(jsonstr).at("/path").asText();
		} catch (IOException e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, RECURSIVE_DELETE_MSG).
					put(LogMessage.MESSAGE, String.format ("recursivedeletesdb failed for [%s]", e.getMessage())).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			responseVO.setSuccess(false);
			responseVO.setHttpstatus(HttpStatus.INTERNAL_SERVER_ERROR);
			responseVO.setResponse(UNEXPECTED_ERROR_STRING+e.getMessage() +"\"]}");
		}
		
		Response lisresp = reqProcessor.process(SDB_LIST,jsonstr,token);
		if(HttpStatus.NOT_FOUND.equals(lisresp.getHttpstatus())){
			Response resp = reqProcessor.process("/delete",jsonstr,token);
			responseVO.setResponse(resp.getResponse());
			responseVO.setHttpstatus(resp.getHttpstatus());
		}else if ( HttpStatus.FORBIDDEN.equals(lisresp.getHttpstatus())){
			responseVO.setResponse(lisresp.getResponse());
			responseVO.setHttpstatus(lisresp.getHttpstatus());			
		}else{
			try {
				 JsonNode folders = objMapper.readTree(lisresp.getResponse()).get("keys");
				 for(JsonNode node : folders){
					recursivedeletesdb (PATH_STRING+path+"/"+node.asText()+"\"}" ,token,responseVO);
				 }
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, RECURSIVE_DELETE_MSG).
						put(LogMessage.MESSAGE, String.format ("recursivedeletesdb failed for [%s]", e.getMessage())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				responseVO.setSuccess(false);
				responseVO.setHttpstatus(HttpStatus.INTERNAL_SERVER_ERROR);
				responseVO.setResponse(UNEXPECTED_ERROR_STRING+e.getMessage() +"\"]}");
			}
			recursivedeletesdb (PATH_STRING+path+"\"}" ,token,responseVO);
		}
	}
	
	/**
	 * Gets path from jsonstr
	 * @param objMapper
	 * @param jsonstr
	 * @param responseVO
	 * @return
	 */
	private static String getPath(ObjectMapper objMapper, String jsonstr, Response responseVO) {

		String path = TVaultConstants.EMPTY;
		try {
			path = objMapper.readTree(jsonstr).at("/path").asText();
		} catch (IOException e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "getPath").
					put(LogMessage.MESSAGE, String.format ("getPath failed for [%s]", e.getMessage())).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			responseVO.setSuccess(false);
			responseVO.setHttpstatus(HttpStatus.INTERNAL_SERVER_ERROR);
			responseVO.setResponse(UNEXPECTED_ERROR_STRING+e.getMessage() +"\"]}");
		}
		return path;
	}
	

	/**
	 * Recursively reads the folders/secrets for a given path
	 * @param jsonstr
	 * @param token
	 * @param responseVO
	 * @param secretMap
	 */
	public static void recursiveRead(String jsonstr,String token,  Response responseVO, SafeNode safeNode){
		ObjectMapper objMapper =  new ObjectMapper();
		String path = getPath(objMapper, jsonstr, responseVO);
		/* Read the secrets for the given path */
		Response secresp = reqProcessor.process(READ_SECRETS,jsonstr,token);
		if (HttpStatus.OK.equals(secresp.getHttpstatus())) {
			responseVO.setResponse(secresp.getResponse());
			responseVO.setHttpstatus(secresp.getHttpstatus());
			SafeNode sn = new SafeNode();
			sn.setId(path);
			sn.setValue(secresp.getResponse());
			if (!TVaultConstants.SAFE.equals(safeNode.getType())) {
				sn.setType(TVaultConstants.SECRET);
				sn.setParentId(safeNode.getId());
				safeNode.addChild(sn);
			}
			else {
				safeNode.setValue(secresp.getResponse());
			}
		}
		/* Read the folders for the given path */
		Response lisresp = reqProcessor.process(SDB_LIST,jsonstr,token);
		if(HttpStatus.NOT_FOUND.equals(lisresp.getHttpstatus())){
			Response resp = reqProcessor.process(READ_SECRETS,jsonstr,token);
			responseVO.setResponse(resp.getResponse());
			responseVO.setHttpstatus(resp.getHttpstatus());			
		}else if ( HttpStatus.FORBIDDEN.equals(lisresp.getHttpstatus())){
			responseVO.setResponse(lisresp.getResponse());
			responseVO.setHttpstatus(lisresp.getHttpstatus());			
		}else{
			if (!lisresp.getResponse().contains("errors")) {
				readFoldersByPath(token, responseVO, safeNode, objMapper, path, lisresp);
			}
			else {
				log.error("Unable to recursively read the given path " + jsonstr);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "recursiveRead").
						put(LogMessage.MESSAGE, "Unable to recursively read the given path").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				responseVO.setSuccess(false);
				responseVO.setHttpstatus(HttpStatus.INTERNAL_SERVER_ERROR);
				responseVO.setResponse("{\"errors\":[\"Unable to recursively read the given path :"+jsonstr +"\"]}");
			}
		}
	}

	private static void readFoldersByPath(String token, Response responseVO, SafeNode safeNode, ObjectMapper objMapper,
			String path, Response lisresp) {
		String jsonstr;
		try {
			JsonNode folders = objMapper.readTree(lisresp.getResponse()).get("keys");
			for(JsonNode node : folders){
				jsonstr = PATH_STRING+path+"/"+node.asText()+"\"}";
				SafeNode sn = new SafeNode();
				sn.setId(path+"/"+node.asText());
				sn.setValue(path+"/"+node.asText());
				sn.setType(TVaultConstants.FOLDER);
				sn.setParentId(safeNode.getId());
				safeNode.addChild(sn);
				/* Recursively read the folders for the given folder/sub folders */
				recursiveRead ( jsonstr,token,responseVO, sn);
			}

		} catch (IOException e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "recursiveRead").
					put(LogMessage.MESSAGE, String.format ("recursiveRead failed for [%s]", e.getMessage())).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			responseVO.setSuccess(false);
			responseVO.setHttpstatus(HttpStatus.INTERNAL_SERVER_ERROR);
			responseVO.setResponse(UNEXPECTED_ERROR_STRING+e.getMessage() +"\"]}");
		}
	}

	/**
	 * Gets the folders and secrets for a given path
	 * @param jsonstr
	 * @param token
	 * @param responseVO
	 * @param secretMap
	 */
	public static void getFoldersAndSecrets(String jsonstr,String token,  Response responseVO, SafeNode safeNode){
		ObjectMapper objMapper =  new ObjectMapper();
		String path = getPath(objMapper, jsonstr, responseVO);
		/* Read the secrets for the given path */
		Response secresp = reqProcessor.process(READ_SECRETS,jsonstr,token);
		responseVO.setResponse(secresp.getResponse());
		responseVO.setHttpstatus(secresp.getHttpstatus());
		boolean secretsExist = false;
		secretsExist = readSecretsByPath(safeNode, path, secresp, secretsExist);

		/* Read the folders for the given path */
		Response lisresp = reqProcessor.process(SDB_LIST,jsonstr,token);
		if(HttpStatus.NOT_FOUND.equals(lisresp.getHttpstatus())){
			if (!secretsExist) {
				// No secrets and no folders
				if (TVaultConstants.SAFE.equals(safeNode.getType())) {
					responseVO.setResponse(TVaultConstants.EMPTY_JSON);
					responseVO.setHttpstatus(HttpStatus.OK);
				}
				else {
					responseVO.setResponse(lisresp.getResponse());
					responseVO.setHttpstatus(lisresp.getHttpstatus());
				}
			}			
		}else if ( HttpStatus.FORBIDDEN.equals(lisresp.getHttpstatus())){
			responseVO.setResponse(lisresp.getResponse());
			responseVO.setHttpstatus(lisresp.getHttpstatus());			
		}else{
			if (!lisresp.getResponse().contains("errors")) {
				readFolderAndSetSafeNode(responseVO, safeNode, objMapper, path, lisresp);
			}
			else {
				log.error("Unable to read the given path " + jsonstr);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "getFoldersAndSecrets").
						put(LogMessage.MESSAGE, String.format ("Unable to read the given path [%s]",jsonstr)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				responseVO.setSuccess(false);
				responseVO.setHttpstatus(HttpStatus.INTERNAL_SERVER_ERROR);
				responseVO.setResponse("{\"errors\":[\"Unable to read the given path :"+jsonstr +"\"]}");
			}
		}
	}

	private static boolean readSecretsByPath(SafeNode safeNode, String path, Response secresp, boolean secretsExist) {
		if (HttpStatus.OK.equals(secresp.getHttpstatus())) {
			SafeNode sn = new SafeNode();
			sn.setId(path);
			sn.setValue(secresp.getResponse());
			if (!TVaultConstants.SAFE.equals(safeNode.getType())) {
				secretsExist = true;
				sn.setType(TVaultConstants.SECRET);
				sn.setParentId(safeNode.getId());
				safeNode.addChild(sn);
			}
			else {
				safeNode.setValue(secresp.getResponse());
			}
		}
		return secretsExist;
	}

	private static void readFolderAndSetSafeNode(Response responseVO, SafeNode safeNode, ObjectMapper objMapper,
			String path, Response lisresp) {
		try {
			JsonNode folders = objMapper.readTree(lisresp.getResponse()).get("keys");
			for(JsonNode node : folders){						
				SafeNode sn = new SafeNode();
				sn.setId(path+"/"+node.asText());
				sn.setValue(path+"/"+node.asText());
				sn.setType(TVaultConstants.FOLDER);
				sn.setParentId(safeNode.getId());
				safeNode.addChild(sn);
			}
			responseVO.setSuccess(true);
			responseVO.setHttpstatus(HttpStatus.OK);

		} catch (IOException e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "getFoldersAndSecrets").
					put(LogMessage.MESSAGE, String.format ("Unable to getFoldersAndSecrets [%s]", e.getMessage())).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			responseVO.setSuccess(false);
			responseVO.setHttpstatus(HttpStatus.INTERNAL_SERVER_ERROR);
			responseVO.setResponse(UNEXPECTED_ERROR_STRING+e.getMessage() +"\"]}");
		}
	}
	
	public static Response configureLDAPUser(String userName,String policies,String groups,String token ){
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "configureLDAPUser").
				put(LogMessage.MESSAGE, String.format ("Trying configureLDAPUse with username [%s] policies [%s] and groups [%s] ", userName, policies, groups)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		ObjectMapper objMapper = new ObjectMapper();
		Map<String,String>configureUserMap = new HashMap<>();
		configureUserMap.put(USERNAME_STR, userName);
		configureUserMap.put(POLICIES_STR, policies);
		configureUserMap.put("groups", groups);
		String ldapUserConfigJson ="";
		try {
			ldapUserConfigJson = objMapper.writeValueAsString(configureUserMap);
		} catch (JsonProcessingException e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "configureLDAPUser").
					put(LogMessage.MESSAGE, String.format ("Unable to create ldapUserConfigJson [%s] with username [%s] policies [%s] and groups [%s] ", e.getMessage(), userName, policies, groups)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return reqProcessor.process("/auth/ldap/users/configure",ldapUserConfigJson,token);
	}

	public static Response configureUserpassUser(String userName,String policies,String token ){
		ObjectMapper objMapper = new ObjectMapper();
		Map<String,String>configureUserMap = new HashMap<>();
		configureUserMap.put(USERNAME_STR, userName);
		configureUserMap.put(POLICIES_STR, policies);
		String userpassUserConfigJson =TVaultConstants.EMPTY;
		try {
			userpassUserConfigJson = objMapper.writeValueAsString(configureUserMap);
		} catch (JsonProcessingException e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "configureUserpassUser").
					put(LogMessage.MESSAGE, String.format ("Unable to create userpassUserConfigJson [%s] with userName [%s] policies [%s] ", e.getMessage(), userName, policies)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));

		}
		return reqProcessor.process("/auth/userpass/updatepolicy",userpassUserConfigJson,token);
	}
	
	public static Response configureLDAPGroup(String groupName,String policies,String token ){
		ObjectMapper objMapper = new ObjectMapper();
		Map<String,String>configureGrouMap = new HashMap<>();
		configureGrouMap.put("groupname", groupName);
		configureGrouMap.put(POLICIES_STR, policies);
		String ldapConfigJson ="";
		try {
			ldapConfigJson = objMapper.writeValueAsString(configureGrouMap);
		} catch (JsonProcessingException e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "configureLDAPGroup").
					put(LogMessage.MESSAGE, String.format ("Unable to create ldapConfigJson [%s] with groupName [%s] policies [%s] ", e.getMessage(), groupName, policies)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return reqProcessor.process("/auth/ldap/groups/configure",ldapConfigJson,token);
	}
	
	public static Response configureAWSRole(String roleName,String policies,String token ){
		ObjectMapper objMapper = new ObjectMapper();
		Map<String,String>configureRoleMap = new HashMap<>();
		configureRoleMap.put("role", roleName);
		configureRoleMap.put(POLICIES_STR, policies);
		String awsConfigJson ="";
		try {
			awsConfigJson = objMapper.writeValueAsString(configureRoleMap);
		} catch (JsonProcessingException e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "configureAWSRole").
					put(LogMessage.MESSAGE, String.format ("Unable to create awsConfigJson [%s] with roleName [%s] policies [%s] ", e.getMessage(), roleName, policies)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return reqProcessor.process("/auth/aws/roles/update",awsConfigJson,token);
	}
	
	public static Response configureAWSIAMRole(String roleName,String policies,String token ){
		ObjectMapper objMapper = new ObjectMapper();
		Map<String,String>configureRoleMap = new HashMap<>();
		configureRoleMap.put("role", roleName);
		configureRoleMap.put(POLICIES_STR, policies);
		String awsConfigJson ="";
		try {
			awsConfigJson = objMapper.writeValueAsString(configureRoleMap);
		} catch (JsonProcessingException e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "configureAWSIAMRole").
					put(LogMessage.MESSAGE, String.format ("Unable to create awsConfigJson with message [%s] for roleName [%s] policies [%s] ", e.getMessage(), roleName, policies)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return reqProcessor.process("/auth/aws/iam/roles/update",awsConfigJson,token);
	}	
	
	public static Response updateMetadata(Map<String,String> params,String token){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, UPDATE_METADATA_STR).
				put(LogMessage.MESSAGE, "Trying to upate metadata with params").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		String metaDataType = params.get("type");
		String name = params.get("name");
		String access = params.get(ACCESS_STR);
		String path = params.get("path");
		path = METADATA_STR+path;
		
		ObjectMapper objMapper = new ObjectMapper();
		String pathjson =PATH_STRING+path+"\"}";
		// Read info for the path
		Response metadataResponse = reqProcessor.process(READ_SECRETS,pathjson,token);
		Map<String,Object> metaDataResponseMap = null;
		if(HttpStatus.OK.equals(metadataResponse.getHttpstatus())){
			try {
				metaDataResponseMap = objMapper.readValue(metadataResponse.getResponse(), new TypeReference<Map<String,Object>>() {});
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, UPDATE_METADATA_STR).
						put(LogMessage.MESSAGE, String.format ("Error creating _metadataMap for type [%s], name [%s], access [%s] and path [%s] message [%s]", metaDataType, name, access, path, e.getMessage())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
			}			
			
			if(metaDataResponseMap != null) {
				Map<String,Object> metadataMap = (Map<String,Object>) metaDataResponseMap.get("data");
				
				@SuppressWarnings("unchecked")
				Map<String,String> dataMap = (Map<String,String>) metadataMap.get(metaDataType);
				if(dataMap == null) { dataMap = new HashMap<>(); metadataMap.put(metaDataType, dataMap);}
				
				dataMap.remove(name);
				if(!"delete".equals(access))
					dataMap.put(name, access);
				
				
				String metadataJson = "";
				try {
					metadataJson = objMapper.writeValueAsString(metadataMap);
				} catch (JsonProcessingException e) {
					log.error(e);
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, UPDATE_METADATA_STR).
							put(LogMessage.MESSAGE, String.format ("Error in creating metadataJson for type [%s], name [%s], access [%s] and path [%s] with message [%s]", metaDataType, name, access, path, e.getMessage())).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}
				
				String writeJson =  PATH_STRING+path+DATA_STRING+ metadataJson +"}";
				metadataResponse = reqProcessor.process(WRITE_SECRETS,writeJson,token);
			}
			return metadataResponse;
		}
		return null;
	}
	
	public static Response updateMetaDataOnConfigChanges(String name, String type,String currentPolicies, String latestPolicies, String token){
		
		List<String> currentPoliciesList = Arrays.asList(currentPolicies.split(","));
		List<String> latestPoliciesList = Arrays.asList(latestPolicies.split(","));
		List<String> newPolicyList = new ArrayList<>();
		List<String> deletePolicyList = new ArrayList<>();
		for(String currPolicy : currentPoliciesList){
			if(!latestPoliciesList.contains(currPolicy)){
				deletePolicyList.add(currPolicy);
			}
		}
		
		for(String latest : latestPoliciesList){
			if(!currentPoliciesList.contains(latest)){
				newPolicyList.add(latest);
			}
		}
		
		Map<String,String> sdbAccessMap = new HashMap<>();
		
		createSdbAccessMapForNewPolicyList(newPolicyList, sdbAccessMap);
		
		createSdbAccessMapForDeletePolicyList(deletePolicyList, sdbAccessMap);
		
		Iterator<Entry<String,String>> itr = sdbAccessMap.entrySet().iterator();
		List<String> failed = new ArrayList<>();
		while(itr.hasNext()){
			Entry<String,String> entry = itr.next();
			Map<String,String> params = new HashMap<>();
			params.put("type", type);
			params.put("name", name);
			params.put("path", entry.getKey());
			params.put(ACCESS_STR, entry.getValue());
			Response rsp = updateMetadata(params, token);
			if(rsp == null || !HttpStatus.NO_CONTENT.equals(rsp.getHttpstatus())){
				failed.add(entry.getKey());
			}
		}
		Response response = new Response();
		if(failed.isEmpty()){
			response.setHttpstatus(HttpStatus.OK);
		}else{
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "updateMetaDataOnConfigChanges").
					put(LogMessage.MESSAGE, "updateMetaDataOnConfigChanges failed ").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			response.setHttpstatus(HttpStatus.MULTI_STATUS);
			response.setResponse("Meta data update failed for "+failed.toString() );
		}
		return response;
	}

	private static void createSdbAccessMapForDeletePolicyList(List<String> deletePolicyList,
			Map<String, String> sdbAccessMap) {
		for(String policy : deletePolicyList){
			String[] policyInfo = policy.split("_");
			if(policyInfo.length==3){
				String path = policyInfo[1]+'/'+policyInfo[2];
				if(!sdbAccessMap.containsKey(path)){
					sdbAccessMap.put(path, "delete");
				}
			}
		}
	}

	private static void createSdbAccessMapForNewPolicyList(List<String> newPolicyList,
			Map<String, String> sdbAccessMap) {
		for(String policy : newPolicyList){
			String[] policyInfo = policy.split("_");
			if(policyInfo.length==3){
				String access ="" ;
				switch(policyInfo[0]) {
					case "r" : 	access = TVaultConstants.READ_POLICY; break;
					case "w" : 	access = TVaultConstants.WRITE_POLICY; break;
					default:	access= TVaultConstants.DENY_POLICY ;break;
				}
				String path = policyInfo[1]+'/'+policyInfo[2];
				sdbAccessMap.put(path, access);
			}
		}
	}

	/**
	 * Update metadata on service account update
	 * @param params
	 * @param token
	 * @return
	 */
	public static Response updateMetadataOnSvcUpdate(String path, ServiceAccount serviceAccount, String token) {
		String metaDataPath = METADATA_STR + path;
		ObjectMapper objMapper = new ObjectMapper();
		String pathjson =PATH_STRING+metaDataPath+"\"}";

		Response metadataResponse = reqProcessor.process(READ_SECRETS,pathjson,token);
		Map<String,Object> metaDataResponseMap = null;
		if(HttpStatus.OK.equals(metadataResponse.getHttpstatus())){
			try {
				metaDataResponseMap = objMapper.readValue(metadataResponse.getResponse(), new TypeReference<Map<String,Object>>() {});
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, UPDATE_METADATA_STR).
						put(LogMessage.MESSAGE, String.format ("Error creating _metadataMap for type service account update, name [%s], and path [%s] message [%s]", serviceAccount.getName(), metaDataPath, e.getMessage())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
			}
			
			if(metaDataResponseMap != null) {
				@SuppressWarnings("unchecked")			
				Map<String,Object> metadataMap = (Map<String,Object>) metaDataResponseMap.get("data");
	
				metadataMap.put("adGroup", serviceAccount.getAdGroup());
				metadataMap.put("appName", serviceAccount.getAppName());
				metadataMap.put("appID", serviceAccount.getAppID());
				metadataMap.put("appTag", serviceAccount.getAppTag());
				if (serviceAccount.getOwner() != null && !serviceAccount.getOwner().equals(TVaultConstants.EMPTY) && !metadataMap.get("managedBy").equals(serviceAccount.getOwner())) {
					metadataMap.put("managedBy", serviceAccount.getOwner());
				}
				String metadataJson = "";
				try {
					metadataJson = objMapper.writeValueAsString(metadataMap);
				} catch (JsonProcessingException e) {
					log.error(e);
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, UPDATE_METADATA_STR).
							put(LogMessage.MESSAGE, String.format ("Error creating _metadataMap for type service account update, name [%s], and path [%s] message [%s]", serviceAccount.getName(), metaDataPath, e.getMessage())).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}
	
				String writeJson =  PATH_STRING+metaDataPath+DATA_STRING+ metadataJson +"}";
				metadataResponse = reqProcessor.process(WRITE_SECRETS,writeJson,token);
			}
			return metadataResponse;
		}
		return null;

	}

	/**
	 * Update metadata for the service account on password reset
	 * @param params
	 * @param token
	 * @return
	 */
	public static Response updateMetadataOnSvcaccPwdReset(Map<String,String> params,String token){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, UPDATE_METADATA_STR).
				put(LogMessage.MESSAGE, "Trying to upate metadata on Service account password reset").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		String metaDataType = params.get("type");
		String path = params.get("path");
		path = METADATA_STR+path;

		ObjectMapper objMapper = new ObjectMapper();
		String pathjson =PATH_STRING+path+"\"}";
		// Read info for the path
		Response metadataResponse = reqProcessor.process(READ_SECRETS,pathjson,token);
		Map<String,Object> metaDataResponseMap = null;
		if(HttpStatus.OK.equals(metadataResponse.getHttpstatus())){
			try {
				metaDataResponseMap = objMapper.readValue(metadataResponse.getResponse(), new TypeReference<Map<String,Object>>() {});
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, UPDATE_METADATA_STR).
						put(LogMessage.MESSAGE, String.format ("Error creating _metadataMap for type [%s] and path [%s] message [%s]", metaDataType, path, e.getMessage())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
			}

			if(metaDataResponseMap != null) {
				@SuppressWarnings("unchecked")
				Map<String,Object> metadataMap = (Map<String,Object>) metaDataResponseMap.get("data");	
				
				boolean initialPasswwordReset = (boolean) metadataMap.get(metaDataType);
				if(StringUtils.isEmpty(initialPasswwordReset) || !initialPasswwordReset) {
					metadataMap.put(metaDataType, true);
					String metadataJson = "";
					try {
						metadataJson = objMapper.writeValueAsString(metadataMap);
					} catch (JsonProcessingException e) {
						log.error(e);
						log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
								put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
								put(LogMessage.ACTION, UPDATE_METADATA_STR).
								put(LogMessage.MESSAGE, String.format ("Error in creating metadataJson for type [%s] and path [%s] with message [%s]", metaDataType, path, e.getMessage())).
								put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								build()));
					}
	
					String writeJson =  PATH_STRING+path+DATA_STRING+ metadataJson +"}";
					metadataResponse = reqProcessor.process(WRITE_SECRETS,writeJson,token);
					return metadataResponse;
				}
			}
            return metadataResponse;
		}
		return null;
	}
	/**
	 * 
	 * @param jsonString
	 * @return
	 */
	public static Map<String,Object> parseJson (String jsonString){
		Map<String, Object> response = new HashMap<>(); 
		try {
			if(jsonString !=null )
				response = new ObjectMapper().readValue(jsonString, new TypeReference<Map<String, Object>>(){});
		} catch (Exception e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "parseJson").
					put(LogMessage.MESSAGE, "parseJson failed ").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return response;
	}
	
	public static String convetToJson (Map<String,Object> jsonMap){
		String jsonStr = TVaultConstants.EMPTY_JSON;
		try {
			jsonStr = new ObjectMapper().writeValueAsString(jsonMap);
		} catch (JsonProcessingException e) {			
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "convetToJson").
					put(LogMessage.MESSAGE, "convetToJson failed ").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
	
		return jsonStr;
	}
	/**
	 * Convenient method to get policies as comma separated String
	 * @param objMapper
	 * @param policyJson
	 * @return
	 * @throws JsonProcessingException
	 * @throws IOException
	 */
	public static String getPoliciesAsStringFromJson(ObjectMapper objMapper, String policyJson) throws IOException{
		StringBuilder currentpolicies = new StringBuilder("");		
		JsonNode policiesNode = objMapper.readTree(policyJson).get("data").get(POLICIES_STR);
		if (policiesNode.isContainerNode()) {
			Iterator<JsonNode> elementsIterator = policiesNode.elements();
		       while (elementsIterator.hasNext()) {
		    	   JsonNode element = elementsIterator.next();
		    	   currentpolicies.append(element.asText()+",");
		       }
		} else {
			currentpolicies.append(policiesNode.asText());
		}
		if (currentpolicies.length() > 0 && currentpolicies.toString().endsWith(",")) {			
			currentpolicies.deleteCharAt( currentpolicies.length() - 1 );
		}		
		return currentpolicies.toString();
	}

	/**
	 * Convenient method to get policies as list
	 * @param objMapper
	 * @param policyJson
	 * @return
	 * @throws JsonProcessingException
	 * @throws IOException
	 */
	public static List<String> getPoliciesAsListFromJson(ObjectMapper objMapper, String policyJson) throws IOException{
		List<String> currentpolicies = new ArrayList<>();
		JsonNode policiesNode = objMapper.readTree(policyJson).get("data").get(POLICIES_STR);
		if (policiesNode.isContainerNode()) {
			Iterator<JsonNode> elementsIterator = policiesNode.elements();
			while (elementsIterator.hasNext()) {
				JsonNode element = elementsIterator.next();
				currentpolicies.add(element.asText());
			}
		}
		else {
			currentpolicies.add(policiesNode.asText());
		}
		return currentpolicies;
	}

	public static void updateUserPolicyAssociationOnSDBDelete(String sdb,Map<String,String> acessInfo,String token){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, UPDATE_USER_POLICY_STR).
				put(LogMessage.MESSAGE, "trying updateUserPolicyAssociationOnSDBDelete").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		log.debug ("updateUserPolicyAssociationOnSDBDelete...for auth method " + vaultAuthMethod);
		if(acessInfo!=null){
			String[] folders = sdb.split("[/]+");
			StringBuilder readPolicy = new StringBuilder("r_");
			StringBuilder writePolicy = new StringBuilder("w_");
			StringBuilder deletePolicy = new StringBuilder("d_");
			StringBuilder sPolicy = new StringBuilder("s_");

			generateUserPolicyString(folders, readPolicy, writePolicy, deletePolicy, sPolicy);
			
			Set<String> users = acessInfo.keySet();
			ObjectMapper objMapper = new ObjectMapper();
			for(String userName : users){
				
				Response userResponse;
				userResponse = getUserResponse(token, userName);	
				
				String responseJson="";
				String groups="";
				List<String> policies = new ArrayList<>();
				List<String> currentpolicies = new ArrayList<>();

				if(HttpStatus.OK.equals(userResponse.getHttpstatus())){
					responseJson = userResponse.getResponse();	
					try {						
						currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
						if (!(TVaultConstants.USERPASS.equals(vaultAuthMethod))) {
							groups = objMapper.readTree(responseJson).get("data").get("groups").asText();
						}
					} catch (IOException e) {
						log.error(e);
						log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
								put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
								put(LogMessage.ACTION, UPDATE_USER_POLICY_STR).
								put(LogMessage.MESSAGE, String.format ("updateUserPolicyAssociationOnSDBDelete failed [%s]", e.getMessage())).
								put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								build()));
					}
					policies.addAll(currentpolicies);
					policies.remove(readPolicy.toString());
					policies.remove(writePolicy.toString());
					policies.remove(deletePolicy.toString());
					policies.remove(sPolicy.toString());

					configureLDAPorUserpassUser(token, userName, groups, policies);
				}
				
			}
		}
	}

	private static Response getUserResponse(String token, String userName) {
		Response userResponse;
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			userResponse = reqProcessor.process("/auth/userpass/read","{\"username\":\""+userName+"\"}",token);
		}
		else {
			userResponse = reqProcessor.process("/auth/ldap/users","{\"username\":\""+userName+"\"}",token);
		}
		return userResponse;
	}

	private static void configureLDAPorUserpassUser(String token, String userName, String groups,
			List<String> policies) {
		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, UPDATE_USER_POLICY_STR).
				put(LogMessage.MESSAGE, String.format ("Current policies [%s]", policies )).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			log.debug ("Inside userpass");
			ControllerUtil.configureUserpassUser(userName,policiesString,token);
		}
		else {
			log.debug ("Inside non-userpass");
			ControllerUtil.configureLDAPUser(userName,policiesString,groups,token);
		}
	}

	private static void generateUserPolicyString(String[] folders, StringBuilder readPolicy, StringBuilder writePolicy,
			StringBuilder deletePolicy, StringBuilder sPolicy) {
		if (folders.length > 0) {
			for (int index = 0; index < folders.length; index++) {
				if (index == folders.length -1 ) {
					readPolicy.append(folders[index]);
					writePolicy.append(folders[index]);
					deletePolicy.append(folders[index]);
					sPolicy.append(folders[index]);
				}
				else {						
					readPolicy.append(folders[index] +"_");
					writePolicy.append(folders[index] +"_");
					deletePolicy.append(folders[index] +"_");
					sPolicy.append(folders[index] +"_");
				}
			}
		}
	}
	public static void updateGroupPolicyAssociationOnSDBDelete(String sdb,Map<String,String> acessInfo,String token){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "updateGroupPolicyAssociationOnSDBDelete").
				put(LogMessage.MESSAGE, "trying updateGroupPolicyAssociationOnSDBDelete").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			log.debug ("Inside userpass of updateGroupPolicyAssociationOnSDBDelete...Just Returning...");
			return;
		}
		if(acessInfo!=null){
			String[] folders = sdb.split("[/]+");
			
			StringBuilder readPolicy = new StringBuilder("r_");
			StringBuilder writePolicy = new StringBuilder("w_");
			StringBuilder deletePolicy = new StringBuilder("d_");
			
			generatePolicyString(folders, readPolicy, writePolicy, deletePolicy);	
			
			Set<String> groups = acessInfo.keySet();
			ObjectMapper objMapper = new ObjectMapper();
			for(String groupName : groups){
				Response response = reqProcessor.process("/auth/ldap/groups","{\"groupname\":\""+groupName+"\"}",token);
				String responseJson="";
				List<String> policies = new ArrayList<>();
				List<String> currentpolicies = new ArrayList<>();
				if(HttpStatus.OK.equals(response.getHttpstatus())){
					responseJson = response.getResponse();	
					try {						
						currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
					} catch (IOException e) {
						log.error(e);
						log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
								put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
								put(LogMessage.ACTION, UPDATE_USER_POLICY_STR).
								put(LogMessage.MESSAGE, String.format ("updateUserPolicyAssociationOnSDBDelete failed [%s]", e.getMessage())).
								put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								build()));
					}
					policies.addAll(currentpolicies);
					policies.remove(readPolicy.toString());
					policies.remove(writePolicy.toString());
					policies.remove(deletePolicy.toString());
					String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, UPDATE_USER_POLICY_STR).
							put(LogMessage.MESSAGE, String.format ("Current policies [%s]", policies )).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					ControllerUtil.configureLDAPGroup(groupName,policiesString,token);
				}
			}
		}
	}

	private static void generatePolicyString(String[] folders, StringBuilder readPolicy, StringBuilder writePolicy,
			StringBuilder deletePolicy) {
		if (folders.length > 0) {
			for (int index = 0; index < folders.length; index++) {
				if (index == folders.length -1 ) {						
					readPolicy.append(folders[index]);
					writePolicy.append(folders[index]);
					deletePolicy.append(folders[index]);
				}
				else {						
					readPolicy.append(folders[index] +"_");
					writePolicy.append(folders[index] +"_");
					deletePolicy.append(folders[index] +"_");
				}
			}
		}
	}
	
	// Not using this method and decided to delete the role instead with the concept that you cant have same role used by different safe.S
	public static void updateAwsRolePolicyAssociationOnSDBDelete(String sdb,Map<String,String> acessInfo,String token){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, UPDATE_AWS_ROLE_POLICY_STR).
				put(LogMessage.MESSAGE, "trying updateAwsRolePolicyAssociationOnSDBDelete").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		if(acessInfo!=null){
			String[] folders = sdb.split("[/]+");
			StringBuilder readPolicy = new StringBuilder("r_");
			StringBuilder writePolicy = new StringBuilder("w_");
			StringBuilder deletePolicy = new StringBuilder("d_");
			
			generatePolicyString(folders, readPolicy, writePolicy, deletePolicy);				

			Set<String> roles = acessInfo.keySet();
			ObjectMapper objMapper = new ObjectMapper();
			for(String role : roles){
				Response roleResponse = reqProcessor.process("/auth/aws/roles","{\"role\":\""+role+"\"}",token);
				String responseJson="";
				String policies ="";
				String currentpolicies ="";
				
				if(HttpStatus.OK.equals(roleResponse.getHttpstatus())){
					responseJson = roleResponse.getResponse();	
					currentpolicies = generateCurrentPolicies(objMapper, responseJson, currentpolicies);
					policies = currentpolicies;
					policies = policies.replaceAll(readPolicy.toString(), "");
					policies = policies.replaceAll(writePolicy.toString(), "");
					policies = policies.replaceAll(deletePolicy.toString(), "");
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, UPDATE_AWS_ROLE_POLICY_STR).
							put(LogMessage.MESSAGE, String.format ("currentpolicies [%s]",policies)).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					ControllerUtil.configureAWSRole(role, policies, token);
				}
			}
		}
	}

	private static String generateCurrentPolicies(ObjectMapper objMapper, String responseJson, String currentpolicies) {
		try {
			JsonNode policiesArry =objMapper.readTree(responseJson).get(POLICIES_STR);
			for(JsonNode policyNode : policiesArry){
				currentpolicies =	(currentpolicies.equals("")) ? currentpolicies+policyNode.asText():currentpolicies+","+policyNode.asText();
			}
		} catch (IOException e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, UPDATE_AWS_ROLE_POLICY_STR).
					put(LogMessage.MESSAGE, String.format ("Generation of currentpolicies failed for [%s]", e.getMessage())).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return currentpolicies;
	}
	
	public static void deleteAwsRoleOnSDBDelete(String sdb,Map<String,String> acessInfo,String token){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, DELETE_AWS_ROLE_SDB_STR).
				put(LogMessage.MESSAGE, "Trying to deleteAwsRoleOnSDBDelete").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			log.debug ("Inside userpass of deleteAwsRoleOnSDBDelete...Just Returning...");
			return;
		}
		if(acessInfo!=null){
			Set<String> roles = acessInfo.keySet();
			for(String role : roles){
				Response response = reqProcessor.process("/auth/aws/roles/delete","{\"role\":\""+role+"\"}",token);
				if(response.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
					log.debug(role +" , AWS Role is deleted as part of sdb delete. SDB path "+ sdb );
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, DELETE_AWS_ROLE_SDB_STR).
							put(LogMessage.MESSAGE, String.format ("%s, AWS Role is deleted as part of sdb delete. SDB path %s ", role, sdb)).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}else{
					log.debug(role +" , AWS Role deletion as part of sdb delete failed . SDB path "+ sdb );
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, DELETE_AWS_ROLE_SDB_STR).
							put(LogMessage.MESSAGE, String.format ("%s, AWS Role is deletion failed. SDB path %s ", role, sdb)).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}
			}
		}
	}
	public static boolean isValidDataPath(String path){
		String[] paths =  path.split("/");
		if(paths.length==3){
			String safeType =  paths[0];
			if(!(TVaultConstants.APPS.equals(safeType)||TVaultConstants.SHARED.equals(safeType)||TVaultConstants.USERS.equals(safeType))){
				return false;
			}
		}else{
			return false;
		}
		return true;
	}
	
	public static boolean isPathValid(String path){
		String[] paths =  path.split("/");
		if(paths.length > 0){
			String safeType =  paths[0];
			if(!(TVaultConstants.APPS.equals(safeType)||TVaultConstants.SHARED.equals(safeType)||TVaultConstants.USERS.equals(safeType))){
				return false;
			}
		}else{
			return false;
		}
		return true;
	}
	
	public static boolean isValidSafePath(String path){
		String[] paths =  path.split("/");
		if(paths.length==2){
			String safeType =  paths[0];
			if(!(TVaultConstants.APPS.equals(safeType)||TVaultConstants.SHARED.equals(safeType)||TVaultConstants.USERS.equals(safeType))){
				return false;
			}
		}else{
			return false;
		}
		return true;
	}
	public static String getSafePath(String path){
		String[] paths =  path.split("/");
		return paths[0]+"/"+paths[1];
	}
	/**
	 * Gets the safe type for a given path
	 * @param path
	 * @return
	 */
	public static String getSafeType(String path){
		String safeType = TVaultConstants.UNKNOWN;
		if (!StringUtils.isEmpty(path)) {
			String[] paths =  path.split("/");
			if (paths != null && paths.length > 0) {
				safeType = paths[0];
			}
		}
		return safeType;
	}
	/**
	 * Gets the safe type for a given path
	 * @param path
	 * @return
	 */
	public static String getSafeName(String path){
		String safeName = TVaultConstants.EMPTY;
		if (!StringUtils.isEmpty(path)) {
			String[] paths =  path.split("/");
			if (paths != null && paths.length > 1) {
				safeName = paths[1];
			}
		}
		return safeName;
	}
	/**
	 * Decides whether a user can be added to a safe or not
	 * @param path
	 * @param token
	 * @return
	 */
	public static boolean canAddPermission(String path,String token) {
		String safeType = ControllerUtil.getSafeType(path);
		String safeName = ControllerUtil.getSafeName(path);
		boolean isValid = true;
		List<String> existingSafeNames = getAllExistingSafeNames(safeType, token);
		List<String> duplicateSafeNames = new ArrayList<>();
		int count=0;
		for (String existingSafeName: existingSafeNames) {
			if (existingSafeName.equalsIgnoreCase(safeName)) {
				count++;
				duplicateSafeNames.add(existingSafeName);
			}
		}
		if (count == 1) {
			// There is one valid safe, Hence permission can be added
			// Exact match
			isValid = true;
		}
		else {
			// There are no safes or more than one and hence permission can't be added
			isValid = false;
		}
		return isValid;
	}

	/**
	 * Checks whether a safe exists in given path
	 * @param path
	 * @param token
	 * @return
	 */
	public static boolean isValidSafe(String path,String token){
		String safePath = getSafePath(path);
		String metaDataPath = METADATA_STR+safePath;
		Response response = reqProcessor.process("/sdb",PATH_STRING+metaDataPath+"\"}",token);
		return (HttpStatus.OK.equals(response.getHttpstatus()));
	}
	/**
	 * Checks whether a given sdb name is vaild
	 * @param sdbName
	 * @return
	 */
	private static boolean isSdbNameValid(String sdbName) {
		return Pattern.matches(sdbNameAllowedCharacters, sdbName);		
	}
	
	/**
	 * Validates inputs values required for SDB creation
	 * @param requestParams
	 * @return
	 */
	public static boolean areSDBInputsValid(Map<String, Object> requestParams) {
		LinkedHashMap<String, Object> map = (LinkedHashMap<String, Object>) requestParams.get("data");
		if (MapUtils.isEmpty(map)) {
			return false;
		}
		String sdbName = (String) map.get("name");
		String sdbOwner = (String) map.get("owner");
		String sdbDescription = (String) map.get("description");
		String path = (String) requestParams.get("path");
		if (StringUtils.isEmpty(sdbName) 
				|| StringUtils.isEmpty(sdbOwner) 
				|| StringUtils.isEmpty(sdbDescription) 
				|| StringUtils.isEmpty(path) 
				) {
			return false;
		}
		if (!isSdbNameValid(sdbName) || sdbName.length() > 40 || !sdbName.equalsIgnoreCase(sdbName)) {
			return false;
		}
		boolean isValid = true;
		String safeName = getSafeName(path);
		if (!sdbName.equals(safeName)) {			
			isValid = false;
		}
		
		if (!EmailValidator.getInstance().isValid(sdbOwner)) {
			isValid = false;
		}
		return isValid;
	}
	
	/**
	 * Validates inputs values required for SDB creation
	 * @param safe
	 * @return
	 */
	public static boolean areSDBInputsValid(Safe safe) {
		if (safe == null) {
			return false;
		}
		SafeBasicDetails safeBasicDetails = safe.getSafeBasicDetails();
		if (safeBasicDetails == null) {
			return false;
		}
		String sdbName = safeBasicDetails.getName();
		String sdbOwner = safeBasicDetails.getOwner();
		String sdbDescription = safeBasicDetails.getDescription();
		String path = safe.getPath();
		if (StringUtils.isEmpty(sdbName) 
				|| StringUtils.isEmpty(sdbOwner) 
				|| StringUtils.isEmpty(sdbDescription) 
				|| StringUtils.isEmpty(path) 
				) {
			return false;
		}
		if (!isSdbNameValid(sdbName) || sdbName.length() > 40 || !sdbName.equalsIgnoreCase(sdbName)) {
			return false;
		}
		boolean isValid = true;
		String safeName = getSafeName(path);
		if (!sdbName.equals(safeName)) {
			isValid = false;
		}
		
		if (!EmailValidator.getInstance().isValid(sdbOwner)) {
			isValid = false;
		}
		return isValid;
	}
	
	/**
	 * Validates inputs values required for SDB creation
	 * @param requestParams
	 * @return
	 */
	public static boolean areSDBInputsValidForUpdate(Map<String, Object> requestParams) {
		@SuppressWarnings("unchecked")
		LinkedHashMap<String, Object> map = (LinkedHashMap<String, Object>) requestParams.get("data");
		if (MapUtils.isEmpty(map)) {
			return false;
		}
		String sdbName = (String) map.get("name");
		String sdbOwner = (String) map.get("owner");
		String sdbDescription = (String) map.get("description");
		String path = (String) requestParams.get("path");
		if (StringUtils.isEmpty(sdbName) 
				|| StringUtils.isEmpty(sdbOwner) 
				|| StringUtils.isEmpty(sdbDescription) 
				|| StringUtils.isEmpty(path) 
				) {
			return false;
		}
		if (sdbName.length() > 40) {
			return false;
		}
		boolean isValid = true;
		String safeName = getSafeName(path);
		if (!sdbName.equalsIgnoreCase(safeName)) {
			isValid = false;
		}
		if (!EmailValidator.getInstance().isValid(sdbOwner)) {
			isValid = false;
		}
		return isValid;
	}

	/**
	 * Validates Safe Group Inputs
	 * @param requestMap
	 * @return
	 */
	public static boolean areSafeGroupInputsValid(Map<String,String> requestMap) {
		if (MapUtils.isEmpty(requestMap)) {
			return false;
		}
		if (ObjectUtils.isEmpty(requestMap.get("groupname"))
				|| ObjectUtils.isEmpty(requestMap.get("path"))
				|| ObjectUtils.isEmpty(requestMap.get(ACCESS_STR))
				) {
			return false;
		}
		String path = requestMap.get("path");
		boolean isValid = true;
		if (!isPathValid(path)) {
			isValid = false;
		}
		String access = requestMap.get(ACCESS_STR);
		if (!ArrayUtils.contains(permissions, access)) {
			isValid = false;
		}
		return isValid;
	}
	/**
	 * Validates AWS Role User inputs
	 * @param requestMap
	 * @return
	 */
	public static boolean areAWSRoleInputsValid(Map<String, String> requestMap) {
		if (MapUtils.isEmpty(requestMap)) {
			return false;
		}
		if (ObjectUtils.isEmpty(requestMap.get("role"))
				|| ObjectUtils.isEmpty(requestMap.get("path"))
				|| ObjectUtils.isEmpty(requestMap.get(ACCESS_STR))
				) {
			return false;
		}
		String path = requestMap.get("path");
		boolean isValid = true;
		if (!isPathValid(path)) {
			isValid = false;
		}
		String access = requestMap.get(ACCESS_STR);
		if (!ArrayUtils.contains(permissions, access)) {
			isValid = false;
		}
		return isValid;
	}
	/**
	 * Validates Safe User inputs
	 * @param safeUser
	 * @return
	 */
	public static boolean areSafeUserInputsValid(SafeUser safeUser) {
		if (ObjectUtils.isEmpty(safeUser)) {
			return false;
		}
		if (ObjectUtils.isEmpty(safeUser.getUsername())
				|| ObjectUtils.isEmpty(safeUser.getAccess())
				|| ObjectUtils.isEmpty(safeUser.getPath())
				) {
			return false;
		}
		String path = safeUser.getPath();
		boolean isValid = true;
		if (!isPathValid(path)) {
			isValid = false;
		}
		String access = safeUser.getAccess();
		if (!ArrayUtils.contains(permissions, access)) {
			isValid = false;
		}
		return isValid;
	}
	/**
	 * Validates Safe User inputs
	 * @param requestMap
	 * @return
	 */
	public static boolean areSafeUserInputsValid(Map<String,Object> requestMap) {
		if (MapUtils.isEmpty(requestMap)) {
			return false;
		}
		if (ObjectUtils.isEmpty(requestMap.get(USERNAME_STR))
				|| ObjectUtils.isEmpty(requestMap.get("path"))
				|| ObjectUtils.isEmpty(requestMap.get(ACCESS_STR))
				) {
			return false;
		}
		String path = (String) requestMap.get("path");
		boolean isValid = true;
		if (!isPathValid(path)) {
			isValid = false;
		}
		String access = (String) requestMap.get(ACCESS_STR);
		if (!ArrayUtils.contains(permissions, access)) {
			isValid = false;
		}
		return isValid;
	}
	
	/**
	 * Validates Safe Group inputs
	 * @param safeUser
	 * @return
	 */
	public static boolean areSafeGroupInputsValid(SafeGroup safeGroup) {
		if (ObjectUtils.isEmpty(safeGroup)) {
			return false;
		}
		if (ObjectUtils.isEmpty(safeGroup.getGroupname())
				|| ObjectUtils.isEmpty(safeGroup.getAccess())
				|| ObjectUtils.isEmpty(safeGroup.getPath())
				) {
			return false;
		}
		String path = safeGroup.getPath();
		boolean isValid = true;
		if (!isPathValid(path)) {
			isValid = false;
		}
		String access = safeGroup.getAccess();
		if (!ArrayUtils.contains(permissions, access)) {
			isValid = false;
		}
		return isValid;
	}
	
	/**
	 * Validates Safe User inputs for AppRole association
	 * @param requestMap
	 * @return
	 */
	public static boolean areSafeAppRoleInputsValid(Map<String,Object> requestMap) {
		if (MapUtils.isEmpty(requestMap)) {
			return false;
		}
		if (ObjectUtils.isEmpty(requestMap.get("role_name"))
				|| ObjectUtils.isEmpty(requestMap.get("path"))
				|| ObjectUtils.isEmpty(requestMap.get(ACCESS_STR))
				) {
			return false;
		}
		String path = (String) requestMap.get("path");
		boolean isValid = true;
		if (!isPathValid(path)) {
			isValid = false;
		}
		String access = (String) requestMap.get(ACCESS_STR);
		if (!ArrayUtils.contains(permissions, access)) {
			isValid = false;
		}
		return isValid;
	}
	
	/**
	 * Validates AWS Role Group inputs
	 * @param safeUser
	 * @return
	 */
	public static boolean areAWSRoleInputsValid(AWSRole awsRole) {
		if (ObjectUtils.isEmpty(awsRole)) {
			return false;
		}
		if (ObjectUtils.isEmpty(awsRole.getRole())
				|| ObjectUtils.isEmpty(awsRole.getAccess())
				|| ObjectUtils.isEmpty(awsRole.getPath())
				) {
			return false;
		}
		String path = awsRole.getPath();
		boolean isValid = true;
		if (!isPathValid(path)) {
			isValid = false;
		}
		String access = awsRole.getAccess();
		if (!ArrayUtils.contains(permissions, access)) {
			isValid = false;
		}
		return isValid;
	}
	
	public static String converSDBInputsToLowerCase(String jsonStr) {
		try {
			Safe safe = (Safe)JSONUtil.getObj(jsonStr, Safe.class);
			safe.getSafeBasicDetails().setName(safe.getSafeBasicDetails().getName().toLowerCase());
			safe.setPath(safe.getPath().toLowerCase());
			jsonStr = JSONUtil.getJSON(safe);
			return jsonStr;
		} catch (Exception e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "converSDBInputsToLowerCase").
				      put(LogMessage.MESSAGE, String.format (FAILED_LOWERCASE_CONVERSION_MSG, jsonStr)).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return jsonStr;
		}
	}
	/**
	 * 
	 * @param safe
	 */
	public static void converSDBInputsToLowerCase(Safe safe) {
		try {
			safe.getSafeBasicDetails().setName(safe.getSafeBasicDetails().getName().toLowerCase());
			safe.setPath(safe.getPath().toLowerCase());
		} catch (Exception e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "converSDBInputsToLowerCase").
				      put(LogMessage.MESSAGE, "Failed while converting safe details to lowercase.").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
		}
	}
	/**
	 * Converts the appRole Inputs to lower case
	 * @param jsonstr
	 * @return
	 */
	public static String convertAppRoleInputsToLowerCase(String jsonstr) {
		try {
			AppRole appRole = (AppRole)JSONUtil.getObj(jsonstr, AppRole.class);
			appRole.setRole_name(appRole.getRole_name());
			jsonstr = JSONUtil.getJSON(appRole);
			return jsonstr;
		} catch (Exception e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "convertAppRoleInputsToLowerCase").
				      put(LogMessage.MESSAGE, String.format (FAILED_LOWERCASE_CONVERSION_MSG, jsonstr)).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return jsonstr;
		}
	}
	
	public static String convertSafeAppRoleAccessToLowerCase(String jsonstr) {
		try {
			SafeAppRoleAccess safeAppRoleAccess = (SafeAppRoleAccess)JSONUtil.getObj(jsonstr, SafeAppRoleAccess.class);
			if (!StringUtils.isEmpty(safeAppRoleAccess.getRole_name())) {
				safeAppRoleAccess.setRole_name(safeAppRoleAccess.getRole_name().toLowerCase());
			}
			if (!StringUtils.isEmpty(safeAppRoleAccess.getAccess())) {
				safeAppRoleAccess.setAccess(safeAppRoleAccess.getAccess().toLowerCase());
			}
			jsonstr = JSONUtil.getJSON(safeAppRoleAccess);
			return jsonstr;
		} catch (Exception e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "convertSafeAppRoleAccessToLowerCase").
				      put(LogMessage.MESSAGE, String.format (FAILED_LOWERCASE_CONVERSION_MSG, jsonstr)).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return jsonstr;
		}
	}
	
	public static String convertAppRoleSecretIdToLowerCase(String jsonstr) {
		try {
			AppRoleSecretData appRoleSecretData = (AppRoleSecretData)JSONUtil.getObj(jsonstr, AppRoleSecretData.class);
			if (!StringUtils.isEmpty(appRoleSecretData.getRole_name())) {
				appRoleSecretData.setRole_name(appRoleSecretData.getRole_name().toLowerCase());
			}
			jsonstr = JSONUtil.getJSON(appRoleSecretData);
			return jsonstr;
		} catch (Exception e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "convertAppRoleSecretIdToLowerCase").
				      put(LogMessage.MESSAGE, String.format (FAILED_LOWERCASE_CONVERSION_MSG, jsonstr)).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return jsonstr;
		}
	}
	
	/**
	 * Validates the SecretKey
	 * @return
	 */
	public static boolean isSecretKeyValid(String jsonString) {
		Pattern pattern = Pattern.compile(secretKeyAllowedCharacters, Pattern.CASE_INSENSITIVE);
		String secretKey = getSecretKey(jsonString);
		if (StringUtils.isEmpty(secretKey)) {
			return false;
		}
		Matcher matcher = pattern.matcher(secretKey);
		boolean valid = matcher.find();
		return !valid;
	}
	/**
	 * Checks whether the given approle is valid
	 * @param approleName
	 * @return
	 */
	private static boolean isAppRoleNameValid(String approleName) {
		return Pattern.matches(approleAllowedCharacters, approleName);
	}
	/**
	 * Validates the approle inputs
	 * @param requestParams
	 * @return
	 */
	public static boolean areAppRoleInputsValid(String jsonstr) {
		AppRole approle = getAppRoleObjFromString(jsonstr);
		return (areAppRoleInputsValid(approle));
	}
	/**
	 * Validates the approle inputs
	 * @param approle
	 * @return
	 */
	public static boolean areAppRoleInputsValid(AppRole approle) {
		boolean isValid = true;
		if (!ObjectUtils.isEmpty(approle)) {
			String approleName = approle.getRole_name();
			if (StringUtils.isEmpty(approleName) || !isAppRoleNameValid(approleName)) {
				isValid = false;
			}			
		}else {
			isValid = false;
		}
		return isValid;
	}
	/**
	 * Generates AppRole object from JSON
	 * @param jsonstr
	 * @return
	 */
	public static AppRole getAppRoleObjFromString(String jsonstr) {
		try {
			return (AppRole)JSONUtil.getObj(jsonstr, AppRole.class);
		} catch (Exception e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "getAppRoleObjFromString").
				      put(LogMessage.MESSAGE, String.format ("Failed to convert [%s] to AppRole object.", jsonstr)).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return null;
		}
	}
	/**
	 * Validates one or more SecretKeys
	 * @return
	 */
	public static boolean areSecretKeysValid(String jsonString) {
		boolean isValid = true;
		Map<String, Boolean> validationMap = new HashMap<>();
		ArrayList<String> secretKeys = getSecretKeys(jsonString);
		for (String secretKey : secretKeys) {
			if (StringUtils.isEmpty(secretKey)) {
				return false;
			}
			boolean valid = Pattern.matches(secretKeyAllowedCharacters, secretKey);
			// Collect validation result for all.
			validationMap.put(secretKey, valid);
		}
		if (validationMap.values().contains(false)) {
			isValid = false;
		}
		return isValid;
	}
	
	private static String getSecretKey(String jsonString) {
		String secretKey = null ;
		try {
			Map<String, Object> requestParams = new ObjectMapper().readValue(jsonString, new TypeReference<Map<String, Object>>(){});
			LinkedHashMap<String, Object> map = (LinkedHashMap<String, Object>) requestParams.get("data");
			for (Object key : map.keySet()) {
				secretKey = (String) key;
				if(!ObjectUtils.isEmpty(key)) {
					break;
				}
			}
			return secretKey;
		} catch (IOException e) {
			return secretKey;
		}
	}
	/**
	 * 
	 * @param jsonString
	 * @return
	 */
	private static ArrayList<String> getSecretKeys(String jsonString) {
		ArrayList<String> secretKeys = new ArrayList<>() ;
		try {
			Map<String, Object> requestParams = new ObjectMapper().readValue(jsonString, new TypeReference<Map<String, Object>>(){});
			@SuppressWarnings("unchecked")
			LinkedHashMap<String, Object> map = (LinkedHashMap<String, Object>) requestParams.get("data");
			for (Object key : map.keySet()) {
				secretKeys.add((String) key);
			  }
			return secretKeys;
		} catch (IOException e) {
			return secretKeys;
		}
	}
	/**
	 * 
	 * @param jsonString
	 * @return
	 */
	public static String  addDefaultSecretKey(String jsonString) {
		try {
			Map<String, Object> requestParams = new ObjectMapper().readValue(jsonString, new TypeReference<Map<String, Object>>(){});
			@SuppressWarnings("unchecked")
			LinkedHashMap<String, Object> map = (LinkedHashMap<String, Object>) requestParams.get("data");
			if (map.isEmpty()) {
				map.put("default", "default");
			}
			return JSONUtil.getJSON(requestParams);
		} catch (IOException e) {
			return jsonString;
		}
	}
	/**
	 * Validate the AWS Login inputs
	 * @param authType
	 * @return
	 */
	public static boolean areAwsLoginInputsValid(AWSAuthType authType, AWSAuthLogin awsAuthLogin) {
		if (awsAuthLogin == null) {
			return false;
		}
		if (StringUtils.isEmpty(awsAuthLogin.getRole())) {
			return false;
		}

		if (AWSAuthType.EC2.equals(authType)) {
			if (!StringUtils.isEmpty(awsAuthLogin.getPkcs7())) {
				return true;
			}
		} else if ((AWSAuthType.IAM.equals(authType))
				&& (!StringUtils.isEmpty(awsAuthLogin.getIam_http_request_method())
						|| !StringUtils.isEmpty(awsAuthLogin.getIam_request_body())
						|| !StringUtils.isEmpty(awsAuthLogin.getIam_request_headers())
						|| !StringUtils.isEmpty(awsAuthLogin.getIam_request_url()))) {
			return true;

		}
		return false;
	}
	/**
	 * validate EC2Role inputs
	 * @param awsLoginRole
	 * @return
	 */
	public static boolean areAWSEC2RoleInputsValid(AWSLoginRole awsLoginRole) throws TVaultValidationException {
		if (awsLoginRole == null) {
			return false;
		}
		if (StringUtils.isEmpty(awsLoginRole.getRole())) {
			throw new TVaultValidationException(ROLE_REQUIRED_STR);
		}
		else if (StringUtils.isEmpty(awsLoginRole.getAuth_type()) || !awsLoginRole.getAuth_type().equalsIgnoreCase("ec2")) {
			throw new TVaultValidationException("auth_type is required and it should be ec2.");
		}
		else if (!StringUtils.isEmpty(awsLoginRole.getBound_account_id()) 
				|| !StringUtils.isEmpty(awsLoginRole.getBound_ami_id()) 
				|| !StringUtils.isEmpty(awsLoginRole.getBound_iam_instance_profile_arn()) 
				|| !StringUtils.isEmpty(awsLoginRole.getBound_iam_role_arn()) 
				|| !StringUtils.isEmpty(awsLoginRole.getBound_region()) 
				|| !StringUtils.isEmpty(awsLoginRole.getBound_subnet_id()) 
				|| !StringUtils.isEmpty(awsLoginRole.getBound_vpc_id()) 
			) {
			return true;
		}
		throw new TVaultValidationException("At least one bound parameter should be specified.");
	}
	
	public static boolean areAWSEC2RoleInputsValid(String jsonStr) throws TVaultValidationException {
		
		Map<String,String> map = null;
		try {
			ObjectMapper objMapper = new ObjectMapper();
			map = objMapper.readValue(jsonStr, new TypeReference<Map<String,String>>() {});
		} catch (IOException e) {
			throw new TVaultValidationException("Invalid Inputs");
		}

		if (MapUtils.isEmpty(map)) {
			return false;
		}
		
		if (StringUtils.isEmpty(map.get("role"))) {
			throw new TVaultValidationException(ROLE_REQUIRED_STR);
		}
		else if (StringUtils.isEmpty(map.get("auth_type")) || !"ec2".equalsIgnoreCase(map.get("auth_type"))) {
			throw new TVaultValidationException("auth_type is required and it should be ec2.");
		}
		else if (!StringUtils.isEmpty(map.get("bound_account_id")) 
				|| !StringUtils.isEmpty(map.get("bound_ami_id")) 
				|| !StringUtils.isEmpty(map.get("bound_iam_instance_profile_arn")) 
				|| !StringUtils.isEmpty(map.get("bound_iam_role_arn")) 
				|| !StringUtils.isEmpty(map.get("bound_region")) 
				|| !StringUtils.isEmpty(map.get("bound_subnet_id")) 
				|| !StringUtils.isEmpty(map.get("bound_vpc_id")) 
			) {
			return true;
		}
		throw new TVaultValidationException("At least one bound parameter should be specified.");
	}
	/**
	 * Validate IAM role inputs
	 * @param awsiamRole
	 * @return
	 */
	public static boolean areAWSIAMRoleInputsValid(AWSIAMRole awsiamRole) throws TVaultValidationException{
		if (awsiamRole == null) {
			return false;
		}
		if (StringUtils.isEmpty(awsiamRole.getRole())) {
			throw new TVaultValidationException(ROLE_REQUIRED_STR);
		}
		else if (StringUtils.isEmpty(awsiamRole.getAuth_type()) || !awsiamRole.getAuth_type().equalsIgnoreCase("iam")) {
			throw new TVaultValidationException("auth_type is required and it should be iam.");
		}
		else if (ArrayUtils.isNotEmpty(awsiamRole.getBound_iam_principal_arn())
			) {
			boolean containsEmptyString = Stream.of(awsiamRole.getBound_iam_principal_arn())
		            .anyMatch(string -> string == null || string.isEmpty());
			if(containsEmptyString) {
				throw new TVaultValidationException("Invalid value specified for bound_iam_principal_arn.");
			}
			else {
				return true;
			}
		}
		throw new TVaultValidationException("Bound parameter should be specified.");
	}
	/**
	 * Get the map of all existing safe names.
	 * @return
	 */
	public static HashMap<String, List<String>> getAllExistingSafeNames(String token) {
		HashMap<String, List<String>> allExistingSafeNames = new HashMap<>();
		for (String mountPath : mountPaths) {
			List<String> safeNames = getAllExistingSafeNames(mountPath, token);
			allExistingSafeNames.put(mountPath, safeNames);
		}
		return allExistingSafeNames;
	}
	
	/**
	 * Get the map of all existing safe names for a given type.
	 * @return
	 */
	public static List<String> getAllExistingSafeNames(String type, String token) {
		List<String> safeNames = new ArrayList<>();
		String path = METADATA_STR + type;
		Response response = reqProcessor.process(SDB_LIST,PATH_STRING+path+"\"}",token);
		if(response.getHttpstatus().equals(HttpStatus.OK)){
			try {
				Map<String, Object> requestParams = new ObjectMapper().readValue(response.getResponse(), new TypeReference<Map<String, Object>>(){});
				safeNames = (ArrayList<String>) requestParams.get("keys");
			} catch (Exception e) {
				log.error("Unable to get list of safes.");
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "getAllExistingSafeNames").
						put(LogMessage.MESSAGE, String.format ("Unable to get list of safes due to [%s] ",e.getMessage())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
			}
		}
		return safeNames;
	}
	/**
	 * Get the count of redundant safe names...
	 * @param safeName
	 * @return
	 */
	public static int getCountOfSafesForGivenSafeName(String safeName, String token) {
		HashMap<String, List<String>> allExistingSafeNames = getAllExistingSafeNames(token);
		int count = 0;
		for (Map.Entry<String, List<String>> entry : allExistingSafeNames.entrySet()) {
			List<String> existingSafeNames = entry.getValue();
			for (String existingSafeName: existingSafeNames) {
				// Note: SafeName is duplicate if it is found in any type (Shared/User/Apps). Hence no need to compare by prefixing with SafeType
				if (safeName.equalsIgnoreCase(existingSafeName)) {
					count++;
				}
			}
		}
		return count;
	}
	/**
	 * Get the count of redundant safe names...
	 * @param safeName
	 * @param safeType
	 * @param token
	 * @return
	 */
	public static int getCountOfSafesForGivenSafeName(String safeName, String safeType, String token) {
		List<String> existingSafeNames = getAllExistingSafeNames(safeType, token);
		int count = 0;
		for (String existingSafeName: existingSafeNames) {
			if (safeName.equalsIgnoreCase(existingSafeName)) {
				count++;
			}
		}
		return count;
	}
	
	public  static String generateSafePath(String safeName, String safeType) {
		String safePath = "";
		if (StringUtils.isEmpty(safeName) || StringUtils.isEmpty(safeType)) {
			return safePath;
		}
		switch (safeType) {
		case TVaultConstants.USERS: case "User Safe":
			safePath = "users/"+safeName;
			break;
		case TVaultConstants.SHARED: case "Shared Safe":
			safePath = "shared/"+safeName;
			break;
		case TVaultConstants.APPS	: case "Application Safe":
			safePath = "apps/"+safeName;
			break;
		default:
			
		}

		return safePath;
	}

	/**
	 * Populate aws metadata json
	 * @param appRoleName
	 * @param username
	 * @return
	 */
	public static String populateAWSMetaJson(String appRoleName, String username) {
		String metaDataPath = TVaultConstants.AWSROLE_METADATA_MOUNT_PATH + '/' + appRoleName;
		AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails(appRoleName);
		appRoleMetadataDetails.setCreatedBy(username);
		AppRoleMetadata appRoleMetadata =  new AppRoleMetadata(metaDataPath, appRoleMetadataDetails);
		String jsonStr = JSONUtil.getJSON(appRoleMetadata);
		Map<String,Object> rqstParams = ControllerUtil.parseJson(jsonStr);
		rqstParams.put("path",metaDataPath);
		return ControllerUtil.convetToJson(rqstParams);
	}

	/**
	 * Create metadata
	 * @param metadataJson
	 * @param token
	 * @return
	 */
	public static boolean createMetadata(String metadataJson, String token) {
		Response response = reqProcessor.process(WRITE_SECRETS,metadataJson,token);
		boolean isMetaDataUpdated = false;

		if(response.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
			isMetaDataUpdated = true;
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "createMetadata").
					put(LogMessage.MESSAGE, "Metadata created successfully ").
					put(LogMessage.STATUS, response.getHttpstatus().toString()).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "createMetadata").
					put(LogMessage.MESSAGE, "Failed to create metadata").
					put(LogMessage.STATUS, response.getHttpstatus().toString()).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return isMetaDataUpdated;
	}

	/**
	 * Check whether the current user can delete a role
	 * @param approle
	 * @param token
	 * @param userDetails
	 * @return
	 */
	public static Response canDeleteRole(String roleName, String token, UserDetails userDetails, String metadataPath) {
		Response response = new Response();
		String userMetaDataPath = metadataPath + '/' + roleName;
		Response readResponse = reqProcessor.process(READ_SECRETS,PATH_STRING+userMetaDataPath+"\"}",token);
		Map<String, Object> responseMap = null;
		if(HttpStatus.OK.equals(readResponse.getHttpstatus())) {
			responseMap = ControllerUtil.parseJson(readResponse.getResponse());
			if(responseMap.isEmpty()) {
				response.setHttpstatus(HttpStatus.INTERNAL_SERVER_ERROR);
				response.setResponse("Error reading role info");
				response.setSuccess(false);
				return response;
			}
			// Safeadmin can always delete any role
			if (userDetails.isAdmin()) {
				response.setHttpstatus(HttpStatus.OK);
				response.setResponse(TVaultConstants.EMPTY);
				response.setSuccess(true);
				return response;
			}
			// normal users
			Map<String,Object> metadataMap = (Map<String,Object>)responseMap.get("data");
			if (userDetails.getUsername().equalsIgnoreCase((String)metadataMap.get("createdBy"))) {
				response.setHttpstatus(HttpStatus.OK);
				response.setResponse(TVaultConstants.EMPTY);
				response.setSuccess(true);
				return response;
			}
		} else if (HttpStatus.NOT_FOUND.equals(readResponse.getHttpstatus()) && userDetails.isAdmin()) {
			response.setHttpstatus(HttpStatus.OK);
			response.setResponse(TVaultConstants.EMPTY);
			response.setSuccess(true);
			return response;
		}
		response.setHttpstatus(HttpStatus.UNAUTHORIZED);
		response.setResponse("Access denied: no permission to remove the role");
		response.setSuccess(false);
		return response;
	}

    /**
     * Populate approle metadata json
     * @param appRoleName
     * @param username
     * @return
     */
    public static  String populateAppRoleMetaJson(String appRoleName, String username) {
        String metaDataPath = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + '/' + appRoleName;
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails(appRoleName);
        appRoleMetadataDetails.setCreatedBy(username);
        AppRoleMetadata appRoleMetadata =  new AppRoleMetadata(metaDataPath, appRoleMetadataDetails);
        String jsonStr = JSONUtil.getJSON(appRoleMetadata);
        Map<String,Object> rqstParams = ControllerUtil.parseJson(jsonStr);
        rqstParams.put("path",metaDataPath);
        return ControllerUtil.convetToJson(rqstParams);
    }
    /**
     * Populate approle metadata json with the user information
     * @param appRoleName
     * @param username
     * @return
     */
    public static  String populateUserMetaJson(String appRoleName, String username) {
        String metaDataPath = TVaultConstants.APPROLE_USERS_METADATA_MOUNT_PATH + '/' + username +'/' + appRoleName;
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails(appRoleName);
        appRoleMetadataDetails.setCreatedBy(username);
        AppRoleMetadata appRoleMetadata =  new AppRoleMetadata(metaDataPath, appRoleMetadataDetails);
        String jsonStr = JSONUtil.getJSON(appRoleMetadata);
        Map<String,Object> rqstParams = ControllerUtil.parseJson(jsonStr);
        rqstParams.put("path",metaDataPath);
        return ControllerUtil.convetToJson(rqstParams);
    }
	/**
	 * Reads the SSCred from the location
	 * @param fileLocation
	 * @param isDelete
	 * @return sscred 
	 */
	public static SSCred readSSCredFile(String fileLocation, boolean isDelete)  {
		File ssFile = null;
		log.debug("Trying to read sscred file");
		try {
			ssFile = new File(fileLocation+"/sscred");
			if (ssFile.exists()) {
				sscred = new SSCred();
				Scanner sc = new Scanner(ssFile); 
				while (sc.hasNextLine()) {
					String line = sc.nextLine();
					if (line.startsWith(USERNAME_SSCRED_STR)) {
						ssUsername = line.substring(USERNAME_SSCRED_STR.length(), line.length());
						sscred.setUsername(line.substring(USERNAME_SSCRED_STR.length(), line.length()));
						log.debug("Successfully read username: from sscred file");
					}
					else if (line.startsWith(PASSWRD_SSCRED_STR)) {
						ssPassword = line.substring(PASSWRD_SSCRED_STR.length(), line.length());
						sscred.setPassword(line.substring(PASSWRD_SSCRED_STR.length(), line.length()));
						log.debug("Successfully read password: from sscred file");
					}
				}
				sc.close();
			}
		} catch (IOException e) {
			log.error(String.format("Unable to read sscred file: [%s]", e.getMessage()));
		}
		try {
			if (ssFile.exists() && isDelete) {
				Path path = Paths.get(fileLocation+"/sscred");				
				Files.delete(path);
				log.debug("Successfully deleted sscred file");				
			}
		} catch (IOException e) {
			log.error(String.format("Unable to get delete sscred file: [%s]", e.getMessage()));
		}
		return sscred;
	}

	/**
	 * @return the ssUsername
	 */
	public static String getSsUsername() {
		return ssUsername;
	}

	/**
	 * @return the ssPassword
	 */
	public static String getSsPassword() {
		return ssPassword;
	}

	/**
	 * @return the sscred
	 */
	public static SSCred getSscred() {
		return sscred;
	}

    /**
     * To hide the master approle from responses to UI
     * @param response
     * @return
     */
    public static Response hideMasterAppRoleFromResponse(Response response) {
        ObjectMapper objMapper = new ObjectMapper();
        String jsonStr = response.getResponse();
        Map<String,String[]> requestMap = null;
        try {
            requestMap = objMapper.readValue(jsonStr, new TypeReference<Map<String,String[]>>() {});
        } catch (IOException e) {
            log.error(e);
        }
        if (requestMap != null && null != requestMap.get("keys")) {
			List<String> policyList = new ArrayList<>(Arrays.asList((String[]) requestMap.get("keys")));
			policyList.remove(TVaultConstants.SELF_SERVICE_APPROLE_NAME);
			String policies = policyList.stream().collect(Collectors.joining("\", \""));
			if (StringUtils.isEmpty(policies)) {
				response.setResponse("{\"keys\": []}");
			}
			else {
				response.setResponse("{\"keys\": [\"" + policies + "\"]}");
			}
		}
        return response;
    }

}
