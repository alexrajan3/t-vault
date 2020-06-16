// =========================================================================
// Copyright 2019 T-Mobile, US
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// See the readme.txt file for additional language around disclaimer of warranties.
// =========================================================================

package com.tmobile.cso.vault.api.service;

import java.util.List;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.ldap.filter.LikeFilter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.google.common.collect.ImmutableMap;
import com.tmobile.cso.vault.api.exception.LogMessage;
import com.tmobile.cso.vault.api.model.DirectoryGroup;
import com.tmobile.cso.vault.api.model.DirectoryObjects;
import com.tmobile.cso.vault.api.model.DirectoryObjectsList;
import com.tmobile.cso.vault.api.model.DirectoryUser;
import com.tmobile.cso.vault.api.utils.JSONUtil;
import com.tmobile.cso.vault.api.utils.ThreadLocalContext;

@Component
public class  DirectoryService {

	@Value("${vault.port}")
	private String vaultPort;

	@Value("${vault.auth.method}")
	private String vaultAuthMethod;

	private static Logger log = LogManager.getLogger(DirectoryService.class);
	
	public static final String DISPLAY_NAME="displayname";
	public static final String OBJECT_CLASS="objectClass";
	

	@Autowired
	private LdapTemplate ldapTemplate;

	/**
	 * Gets the list of users from Directory Server based on UPN
	 * @param UserPrincipalName
	 * @return
	 */
	public ResponseEntity<DirectoryObjects> searchByUPN(String userPrincipalName) {
		AndFilter andFilter = new AndFilter();
		andFilter.and(new LikeFilter("userPrincipalName", userPrincipalName+"*"));
		andFilter.and(new EqualsFilter(OBJECT_CLASS, "user"));

		List<DirectoryUser> allPersons = getAllPersons(andFilter);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(allPersons.toArray(new DirectoryUser[allPersons.size()]));
		users.setData(usersList);
		return ResponseEntity.status(HttpStatus.OK).body(users);
	}
	
	/**
	 * 
	 * @param UserPrincipalName
	 * @return
	 */
	public ResponseEntity<DirectoryObjects> searchByCorpId(String corpId) {
		AndFilter andFilter = new AndFilter();
		andFilter.and(new LikeFilter("cn", corpId+"*"));
		andFilter.and(new EqualsFilter(OBJECT_CLASS, "user"));

		List<DirectoryUser> allPersons = getAllPersons(andFilter);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(allPersons.toArray(new DirectoryUser[allPersons.size()]));
		users.setData(usersList);
		return ResponseEntity.status(HttpStatus.OK).body(users);
	}

	/**
	 * Gets the list of users from Directory Server
	 * @param filter
	 * @return
	 */
	private List<DirectoryUser> getAllPersons(Filter filter) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "GetAllUsers").
				put(LogMessage.MESSAGE, String.format("Trying to get list of users from directory server")).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		return ldapTemplate.search("", filter.encode(), new AttributesMapper<DirectoryUser>() {
			@Override
			public DirectoryUser mapFromAttributes(Attributes attr) throws NamingException {
				DirectoryUser person = new DirectoryUser();
				if (attr != null) {
					String mail = ""; 
					if(attr.get("mail") != null) {
						mail = ((String) attr.get("mail").get());
					}
					String userId = ((String) attr.get("name").get());
					// Assign first part of the email id for use with UPN authentication
					if (!StringUtils.isEmpty(mail)) {
						userId = mail.substring(0, mail.indexOf('@'));
					}
					person.setUserId(userId);
					if (attr.get(DISPLAY_NAME) != null) {
						person.setDisplayName(((String) attr.get(DISPLAY_NAME).get()));
					}
					if (attr.get("givenname") != null) {
						person.setGivenName(((String) attr.get("givenname").get()));
					}

					if (attr.get("mail") != null) {
						person.setUserEmail(((String) attr.get("mail").get()));
					}

					if (attr.get("name") != null) {
						person.setUserName(((String) attr.get("name").get()));
					}
				}
				return person;
			}
		});
	}

	/**
	 * Gets the list of LDAP groups 
	 * @param groupName
	 * @return
	 */
	public ResponseEntity<DirectoryObjects> searchByGroupName(String groupName) {
		AndFilter andFilter = new AndFilter();
		andFilter.and(new EqualsFilter(OBJECT_CLASS, "group"));
		andFilter.and(new LikeFilter("CN", groupName+"*"));
		List<DirectoryGroup> allGroups = getAllGroups(andFilter);
		DirectoryObjects groups = new DirectoryObjects();
		DirectoryObjectsList groupsList = new DirectoryObjectsList();
		groupsList.setValues(allGroups.toArray(new DirectoryGroup[allGroups.size()]));
		groups.setData(groupsList);
		return ResponseEntity.status(HttpStatus.OK).body(groups);
		
	}

	/**
	 * Get the list of groups
	 * @param filter
	 * @return
	 */
	private List<DirectoryGroup> getAllGroups(Filter filter) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "GetAllGroups").
				put(LogMessage.MESSAGE, String.format("Trying to get list of groups from directory server")).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		return ldapTemplate.search("", filter.encode(), new AttributesMapper<DirectoryGroup>() {
			@Override
			public DirectoryGroup mapFromAttributes(Attributes attr) throws NamingException {
				DirectoryGroup dirGrp = new DirectoryGroup();
				if (attr.get("name") != null) {
					dirGrp.setGroupName(((String) attr.get("name").get()));
				}
				if (attr.get(DISPLAY_NAME) != null) {
					dirGrp.setDisplayName(((String) attr.get(DISPLAY_NAME).get()));
				}
				if (attr.get("mail") != null) {
					dirGrp.setEmail(((String) attr.get("mail").get()));
				}
				return dirGrp;
			}
		});
	}

}
