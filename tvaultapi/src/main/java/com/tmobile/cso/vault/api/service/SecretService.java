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

package com.tmobile.cso.vault.api.service;

import java.io.IOException;
import java.util.Arrays;

import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.model.Secret;
import com.tmobile.cso.vault.api.model.UserDetails;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.tmobile.cso.vault.api.controller.ControllerUtil;
import com.tmobile.cso.vault.api.exception.LogMessage;
import com.tmobile.cso.vault.api.model.SafeNode;
import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.process.Response;
import com.tmobile.cso.vault.api.utils.JSONUtil;
import com.tmobile.cso.vault.api.utils.ThreadLocalContext;

@Component
public class  SecretService {

	@Value("${vault.port}")
	private String vaultPort;

	@Autowired
	private RequestProcessor reqProcessor;

	@Value("${vault.auth.method}")
	private String vaultAuthMethod;

	private static Logger log = LogManager.getLogger(SecretService.class);	
	
	private static final String PATH_STRING = "{\"path\":\"";
	private static final String WRITE_SECRET = "Write Secret";
	private static final String DELETE_SECRET = "Delete Secret";
	private static final String WRITE_SECRET_MSG = "Writing secret [%s] failed";
	
	/**
	 * To read secret from vault
	 * @param token
	 * @param path
	 * @return
	 */
	public ResponseEntity<String> readFromVault(String token, String path){
	    log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                put(LogMessage.ACTION, "Read Secret").
                put(LogMessage.MESSAGE, String.format("Trying to read secret [%s]", path)).
                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                build()));
              Response response = reqProcessor.process("/read",PATH_STRING+path+"\"}",token);
              log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                        put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                        put(LogMessage.ACTION, "Read Secret").
                        put(LogMessage.MESSAGE, String.format("Reading secret [%s] completed succssfully", path)).
                        put(LogMessage.STATUS, response.getHttpstatus().toString()).
                        put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                        build()));
              return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
	}
	/**
	 * Write a secret into vault
	 * @param token
	 * @param secret
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> write(String token, Secret secret, UserDetails userDetails){
		String jsonStr = JSONUtil.getJSON(secret);
		String path="";
		try {
			path = new ObjectMapper().readTree(jsonStr).at("/path").asText();
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, WRITE_SECRET).
				      put(LogMessage.MESSAGE, String.format("Trying to write secret [%s]", path)).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			jsonStr = ControllerUtil.addDefaultSecretKey(jsonStr);
			if (!ControllerUtil.areSecretKeysValid(jsonStr)) {
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid request.Check json data\"]}");
			}
		} catch (IOException e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid request.Check json data\"]}");
		}
		if(ControllerUtil.isPathValid(path)){
		    // Check if the user has explicit write permission. Safe owners (implicit write permission) will be denied from write operation
			if (!hasExplicitWritePermission(userDetails, secret.getPath())) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, WRITE_SECRET).
						put(LogMessage.MESSAGE, String.format(WRITE_SECRET_MSG, path)).
						put(LogMessage.RESPONSE, "No permisison to write secret in this safe").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("{\"errors\":[\"No permisison to write secret in this safe\"]}");
			}
			Response response = reqProcessor.process("/write",jsonStr,token);
			if(response.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						  put(LogMessage.ACTION, WRITE_SECRET).
					      put(LogMessage.MESSAGE, String.format("Writing secret [%s] completed succssfully", path)).
					      put(LogMessage.STATUS, response.getHttpstatus().toString()).
					      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					      build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Secret saved to vault\"]}");
			}
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, WRITE_SECRET).
				      put(LogMessage.MESSAGE, String.format(WRITE_SECRET_MSG, path)).
				      put(LogMessage.RESPONSE, response.getResponse()).
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}else{
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, WRITE_SECRET).
				      put(LogMessage.MESSAGE, String.format(WRITE_SECRET_MSG, path)).
				      put(LogMessage.RESPONSE, "Invalid path").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid path\"]}");
		}
	}

	/**
	 * To check if user has explicit write permission
	 * @param token
	 * @param userName
	 * @param path
	 * @return
	 */
	private boolean hasExplicitWritePermission(UserDetails userDetails, String path) {
		String policy = "w_"+ ControllerUtil.getSafeType(path) + "_" + ControllerUtil.getSafeName(path);
		return Arrays.stream(userDetails.getPolicies()).anyMatch(policy::equals);
	}

	/**
	 * Delete secret from vault
	 * @param token
	 * @param path
	 * @return
	 */
	public ResponseEntity<String> deleteFromVault(String token, String path){
		if(ControllerUtil.isValidDataPath(path)){
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, DELETE_SECRET).
				      put(LogMessage.MESSAGE, String.format("Trying to delete secret [%s]", path)).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
				Response response = reqProcessor.process("/delete",PATH_STRING+path+"\"}",token);
				if(response.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							  put(LogMessage.ACTION, DELETE_SECRET).
						      put(LogMessage.MESSAGE, String.format("Deleting secret [%s] completed", path)).
						      put(LogMessage.STATUS, response.getHttpstatus().toString()).
						      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						      build()));
					return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Secrets deleted\"]}");
				}
				return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}else{
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, DELETE_SECRET).
				      put(LogMessage.MESSAGE, String.format("Deleting secret [%s] failed", path)).
				      put(LogMessage.RESPONSE, "Invalid path").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid path\"]}");
		}
	}
	/**
	 * Read vault folders and secrets recursively
	 * @param token
	 * @param path
	 * @return
	 */
	public ResponseEntity<String> readFromVaultRecursive(String token, String path){
		Response response = new Response(); 
		SafeNode safeNode = new SafeNode();
		safeNode.setId(path);
		if (ControllerUtil.isValidSafePath(path)) {
			safeNode.setType(TVaultConstants.SAFE);
		}
		else {
			safeNode.setType(TVaultConstants.FOLDER);
		}
		ControllerUtil.recursiveRead(PATH_STRING+path+"\"}",token,response, safeNode);
		ObjectMapper mapper = new ObjectMapper();
		try {
			String res = mapper.writeValueAsString(safeNode);
			return ResponseEntity.status(response.getHttpstatus()).body(res);
		} catch (JsonProcessingException e) {
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}
	}
	/**
	 * Read Folder and Secrets for a given folder
	 * @param token
	 * @param path
	 * @return
	 */
	public ResponseEntity<String> readFoldersAndSecrets(String token, String path){
		Response response = new Response(); 
		SafeNode safeNode = new SafeNode();
		safeNode.setId(path);
		if (ControllerUtil.isValidSafePath(path)) {
			safeNode.setType(TVaultConstants.SAFE);
		}
		else {
			safeNode.setType(TVaultConstants.FOLDER);
		}
		ControllerUtil.getFoldersAndSecrets(PATH_STRING+path+"\"}",token,response, safeNode);
		ObjectMapper mapper = new ObjectMapper();
		try {
			String res = mapper.writeValueAsString(safeNode);
			return ResponseEntity.status(response.getHttpstatus()).body(res);
		} catch (JsonProcessingException e) {
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}
	}
}
