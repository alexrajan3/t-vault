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

import java.io.*;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

import com.fasterxml.jackson.databind.JsonNode;
import com.tmobile.cso.vault.api.exception.TVaultValidationException;
import com.tmobile.cso.vault.api.model.*;
import com.tmobile.cso.vault.api.utils.*;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.*;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.controller.ControllerUtil;
import com.tmobile.cso.vault.api.exception.LogMessage;
import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.process.Response;

@Component
public class  ServiceAccountsService {

	@Value("${vault.port}")
	private String vaultPort;

	@Value("${ad.notification.fromemail}")
	private String supportEmail;

	@Value("${ad.notification.mail.subject}")
	private String subject;

	@Value("${ad.notification.mail.body.groupcontent}")
	private String mailAdGroupContent;

	private static Logger log = LogManager.getLogger(ServiceAccountsService.class);	

	@Autowired
	@Qualifier(value = "svcAccLdapTemplate")
	private LdapTemplate ldapTemplate;

	@Autowired
	@Qualifier(value = "adUserLdapTemplate")
	private LdapTemplate adUserLdapTemplate;

	@Autowired
	private AccessService accessService;

	@Autowired
	private RequestProcessor reqProcessor;

	@Autowired
	private AppRoleService appRoleService;

	@Autowired
	private AWSAuthService awsAuthService;

	@Autowired
	private AWSIAMAuthService awsiamAuthService;

	@Autowired
	private PolicyUtils policyUtils;

	@Value("${ad.svc.acc.suffix:clouddev.corporate.t-mobile.com}")
	private String serviceAccountSuffix;
	
	@Value("${vault.auth.method}")
	private String vaultAuthMethod;
	
	@Value("${ad.username}")
	private String adMasterServiveAccount;

    @Autowired
    private TokenUtils tokenUtils;

    @Autowired
	private EmailUtils emailUtils;
    
    private static final String RESET_STRING = "reset";    
    private static final String DISPLAY_NAME_STRING = "displayname";
    private static final String GIVEN_NAME_STRING = "givenname";
    private static final String LOCKED_OUT_STRING = "lockedout";
    private static final String MANAGED_BY_STRING = "managedBy";
    private static final String ACCESS_STRING = "access";
    private static final String DELETE_STRING = "delete";
    private static final String CURRENT_PASSWRD_STRING = "current_password";
    private static final String USERNAME_STRING = "username";
    private static final String LAST_PASSWRD_STRING = "last_password";
    private static final String POLICIES_STRING = "policies";    
    
    private static final String ONBOARD_SERVICE_ACCOUNT = "onboardServiceAccount";
    private static final String CREATE_ACCOUNT_ROLE_STRING = "createAccountRole";
    private static final String OFFBOARD_SERVICE_ACCOUNT = "offboardServiceAccount";
    private static final String ADD_USER_SERVICE_ACCOUNT = "Add User to ServiceAccount";
    private static final String REMOVE_USER_SERVICE_ACCOUNT = "Remove User from ServiceAccount";
    private static final String RESET_SVCACC_PASSWRD = "resetSvcAccPassword";
    private static final String READ_SVCACC_PASSWRD = "readSvcAccPassword";
    private static final String ADD_GROUP_TO_SERVICE_ACCOUNT = "Add Group to Service Account";
    private static final String ADD_APPROLE_TO_SERVICE_ACCOUNT = "Add Approle to Service Account";
    private static final String UPDATE_USER_POLICY_SVCACC = "updateUserPolicyAssociationOnSvcaccDelete";   
    private static final String UPDATE_GROUP_POLICY_SVCACC = "updateGroupPolicyAssociationOnSvcaccDelete";
    private static final String DELETE_AWS_ROLE_SVCACC = "deleteAwsRoleAssociateionOnSvcaccDelete";
    private static final String UPDATE_APPROLE_POLICY_SVCACC = "updateApprolePolicyAssociationOnSvcaccDelete";   
    private static final String REMOVE_APPROLE_SERVICE_ACCOUNT = "Remove AppRole from Service Account";
    private static final String ADD_AWS_ROLE_SERVICE_ACCOUNT = "Add AWS Role to Service Account";
    private static final String REMOVE_AWS_ROLE_SERVICE_ACCOUNT = "Remove AWS Role from Service Account";
    private static final String UPDATE_ONBOARDED_SERVICE_ACCOUNT = "Update onboarded Service Account";
    private static final String REMOVE_OLD_USER_PERMISSIONS = "removeOldUserPermissions";
    private static final String INITIAL_PASSWRD_RESET = "initialPasswordReset";
    
    private static final String POLICY_MSG_STRING = "policy is [%s]";
    private static final String POLICIES_MSG_STRING = "Policies are, read - [%s], write - [%s], deny -[%s], owner - [%s]";
    private static final String USERNAME_FORMAT_STRING = "{\"username\":\"";
    private static final String USER_RESPONSE_MSG_STRING = "userResponse status is [%s]";  
    private static final String UNABLE_TO_RESET_PASSWRD_STRING = "Unable to reset password for [%s]";
    private static final String ROLE_NAME_FORMAT_STRING = "{\"role_name\":\"";
    private static final String GROUP_NAME_STRING = "{\"groupname\":\"";
    private static final String CURRENT_POLICIES_MSG = "Current policies [%s]";
    private static final String ROLE_STRING = "{\"role\":\"";
    private static final String POLICIES_CONFIGURED_MSG = " is being configured";
    
    private static final String ERROR_PASSWRD_EXPIRY_MSG = "Password Expiration Time [%s] is greater the Maximum expiration time (MAX_TTL) [%s]";
    private static final String ERROR_INVALID_VALUE_MSG = "{\"errors\":[\"Invalid value specified for access. Valid values are read, reset, deny\"]}";
    private static final String ERROR_POLICY_GROUP_MSG = "Exception while creating currentpolicies or groups";
    private static final String ERROR_UNABLE_GET_PASSWRD_MSG = "{\"errors\":[\"Unable to get password details for the given service account\"]}";    
    
    private static final String AUTH_USERPASS_READ = "/auth/userpass/read";
    private static final String AUTH_LDAP_USERS = "/auth/ldap/users";    
    private static final String AUTH_LDAP_GROUPS = "/auth/ldap/groups";
    private static final String READ_APPROLE_ROLE = "/auth/approle/role/read"; 
    
    private static final String[] permissions = {"read", RESET_STRING, "deny", "sudo"};
    
	/**
	 * Gets the list of users from Directory Server based on UPN
	 * @param UserPrincipalName
	 * @return
	 */
	public ResponseEntity<ADServiceAccountObjects> getADServiceAccounts(String token, UserDetails userDetails, String userPrincipalName, boolean excludeOnboarded) {
		AndFilter andFilter = new AndFilter();
		andFilter.and(new LikeFilter("userPrincipalName", userPrincipalName+"*"));
		andFilter.and(new EqualsFilter("objectClass", "user"));
		andFilter.and(new NotFilter(new EqualsFilter("CN", adMasterServiveAccount)));
		if (excludeOnboarded) {
			ResponseEntity<String> responseEntity = getOnboardedServiceAccounts(token, userDetails);
			if (HttpStatus.OK.equals(responseEntity.getStatusCode())) {
				String response = responseEntity.getBody();
				List<String> onboardedSvcAccs = new ArrayList<>();
				try {
					Map<String, Object> requestParams = new ObjectMapper().readValue(response, new TypeReference<Map<String, Object>>(){});
					onboardedSvcAccs = (ArrayList<String>) requestParams.get("keys");
				}
				catch(Exception ex) {
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, "getADServiceAccounts").
							put(LogMessage.MESSAGE, "There are no service accounts currently onboarded or error in retrieving onboarded service accounts").
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}
				for (String onboardedSvcAcc: onboardedSvcAccs) {
					andFilter.and(new NotFilter(new EqualsFilter("CN", onboardedSvcAcc)));
				}
			}
		}
		List<ADServiceAccount> allServiceAccounts = getADServiceAccounts(andFilter);
		// get the managed_by details
		if (allServiceAccounts != null && !allServiceAccounts.isEmpty()) {
			List<String> ownerlist = allServiceAccounts.stream().map(m -> m.getManagedBy().getUserName()).collect(Collectors.toList());
			// remove duplicate usernames
			ownerlist = new ArrayList<>(new HashSet<>(ownerlist));

			// remove empty manager names if any
            ownerlist.removeAll(Collections.singleton(TVaultConstants.EMPTY));
            ownerlist.removeAll(Collections.singleton(null));

			buildSearchQuery(allServiceAccounts, ownerlist);
		}
		ADServiceAccountObjects adServiceAccountObjects = new ADServiceAccountObjects();
		ADServiceAccountObjectsList adServiceAccountObjectsList = new ADServiceAccountObjectsList();
		Object[] values = new Object[] {};
		if (allServiceAccounts !=null && !CollectionUtils.isEmpty(allServiceAccounts)) {
			values = allServiceAccounts.toArray(new ADServiceAccount[allServiceAccounts.size()]);
		}
		adServiceAccountObjectsList.setValues(values);
		adServiceAccountObjects.setData(adServiceAccountObjectsList);
		return ResponseEntity.status(HttpStatus.OK).body(adServiceAccountObjects);
	}

	private void buildSearchQuery(List<ADServiceAccount> allServiceAccounts, List<String> ownerlist) {
		// build the search query
		if (!ownerlist.isEmpty()) {
			StringBuilder filterQuery = new StringBuilder();
			filterQuery.append("(&(objectclass=user)(|");
			for (String owner : ownerlist) {
				filterQuery.append("(cn=" + owner + ")");
			}
			filterQuery.append("))");
			List<ADUserAccount> managedServiceAccounts = getServiceAccountManagerDetails(filterQuery.toString());

			// Update the managedBy withe ADUserAccount object
			for (ADServiceAccount adServiceAccount : allServiceAccounts) {
				if (!StringUtils.isEmpty(adServiceAccount.getManagedBy().getUserName())) {
					List<ADUserAccount> adUserAccount = managedServiceAccounts.stream().filter(f -> (f.getUserName()!=null && f.getUserName().equalsIgnoreCase(adServiceAccount.getManagedBy().getUserName()))).collect(Collectors.toList());
					if (!adUserAccount.isEmpty()) {
						adServiceAccount.setManagedBy(adUserAccount.get(0));
					}
				}
			}
		}
	}

	/**
	 * Gets the list of ADAccounts from AD Server
	 * @param filter
	 * @return
	 */
	private List<ADServiceAccount> getADServiceAccounts(Filter filter) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "getAllAccounts").
				put(LogMessage.MESSAGE, "Trying to get list of user accounts from AD server").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		return ldapTemplate.search("", filter.encode(), new AttributesMapper<ADServiceAccount>() {
			@Override
			public ADServiceAccount mapFromAttributes(Attributes attr) throws NamingException {
				ADServiceAccount adServiceAccount = new ADServiceAccount();
				if (attr != null) {
					String userId = ((String) attr.get("name").get());
					adServiceAccount.setUserId(userId);
					if (attr.get(DISPLAY_NAME_STRING) != null) {
						adServiceAccount.setDisplayName(((String) attr.get(DISPLAY_NAME_STRING).get()));
					}
					if (attr.get(GIVEN_NAME_STRING) != null) {
						adServiceAccount.setGivenName(((String) attr.get(GIVEN_NAME_STRING).get()));
					}

					if (attr.get("mail") != null) {
						adServiceAccount.setUserEmail(((String) attr.get("mail").get()));
					}
					if (attr.get("name") != null) {
						adServiceAccount.setUserName((String) attr.get("name").get());
					}
					if (attr.get("whenCreated") != null) {
						String rawDateTime = (String) attr.get("whenCreated").get();
						DateTimeFormatter fmt = DateTimeFormatter.ofPattern ( "uuuuMMddHHmmss[,S][.S]X" );
						OffsetDateTime odt = OffsetDateTime.parse (rawDateTime, fmt);
						Instant instant = odt.toInstant();
						adServiceAccount.setWhenCreated(instant);
					}
					ADUserAccount adUserAccount = new ADUserAccount();
					adServiceAccount.setManagedBy(adUserAccount);
					adServiceAccount.setOwner(null);
					if (attr.get("manager") != null) {
						String managedBy = "";
						String managedByStr = (String) attr.get("manager").get();
						if (!StringUtils.isEmpty(managedByStr)) {
							managedBy= managedByStr.substring(3, managedByStr.indexOf(','));
						}
						adUserAccount.setUserName(managedBy);
						adServiceAccount.setOwner(managedBy.toLowerCase());
					}
					if (attr.get("accountExpires") != null) {
						String rawExpDateTime = (String) attr.get("accountExpires").get();
						adServiceAccount.setAccountExpires(rawExpDateTime);
					}
					if (attr.get("passwrdLastSet") != null) {
						String pwdLastSet = (String) attr.get("passwrdLastSet").get();
						adServiceAccount.setPasswrdLastSet(pwdLastSet);
					}
					if (attr.get("memberof") != null) {
						String memberof = (String) attr.get("memberof").get();
						adServiceAccount.setMemberOf(memberof);
					}

					if (attr.get(LOCKED_OUT_STRING) != null) {
						String memberof = (String) attr.get(LOCKED_OUT_STRING).get();
						adServiceAccount.setMemberOf(memberof);
					}
					// lock status
					adServiceAccount.setLockStatus("unlocked");
					if (attr.get(LOCKED_OUT_STRING) != null) {
						boolean lockedOut = (boolean) attr.get(LOCKED_OUT_STRING).get();
						if (lockedOut) {
							adServiceAccount.setLockStatus("locked");
						}
					}
					if (attr.get("description") != null) {
						adServiceAccount.setPurpose((String) attr.get("description").get());
					}
				}
				return adServiceAccount;
			}
		});
	}

	/**
	 * Onboards an AD service account into TVault for password rotation
	 * @param serviceAccount
	 * @return
	 */
	public ResponseEntity<String> onboardServiceAccount(String token, ServiceAccount serviceAccount, UserDetails userDetails) {
		List<String> onboardedList = getOnboardedServiceAccountList(token, userDetails);
		if (onboardedList.contains(serviceAccount.getName())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ONBOARD_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Failed to onboard Service Account. Service account is already onboarded").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to onboard Service Account. Service account is already onboarded\"]}");
		}
        // get the maxPwdAge for this service account
        List<ADServiceAccount> allServiceAccounts = getADServiceAccount(serviceAccount.getName());
        if (allServiceAccounts == null || allServiceAccounts.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to onboard Service Account. Unable to read Service account details\"]}");
        }
        if (TVaultConstants.EXPIRED.equalsIgnoreCase(allServiceAccounts.get(0).getAccountStatus())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to onboard Service Account. Service account expired\"]}");
        }
        int maxPwdAge = allServiceAccounts.get(0).getMaxPwdAge();
		serviceAccount.setOwner(allServiceAccounts.get(0).getOwner());
		if (serviceAccount.isAutoRotate()) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ONBOARD_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Auto-Rotate of password has been turned on").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
            if (null == serviceAccount.getMax_ttl()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid or no value has been provided for MAX_TTL\"]}");
            }
            if (null == serviceAccount.getTtl()) {
				serviceAccount.setTtl(maxPwdAge - 1L);
			}
			if (serviceAccount.getTtl() > maxPwdAge) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, ONBOARD_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, String.format (ERROR_PASSWRD_EXPIRY_MSG, serviceAccount.getTtl(), maxPwdAge)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid value provided for Password Expiration Time. This can't be more than "+maxPwdAge+" for this Service Account\"]}");
            }
			if (serviceAccount.getTtl() > serviceAccount.getMax_ttl()) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, ONBOARD_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, String.format (ERROR_PASSWRD_EXPIRY_MSG, serviceAccount.getTtl(), serviceAccount.getMax_ttl())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Password Expiration Time can't be more than Maximum expiration time (MAX_TTL) for this Service Account\"]}");
			}
		}
		else {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ONBOARD_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Auto-Rotate of password has been turned off").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			// ttl defaults to configuration ttl
			serviceAccount.setTtl(TVaultConstants.MAX_TTL);
		}
		return createAccountroleForServiceAccount(token, serviceAccount, userDetails);
	}

	private ResponseEntity<String> createAccountroleForServiceAccount(String token, ServiceAccount serviceAccount,
			UserDetails userDetails) {
		ResponseEntity<String> accountRoleCreationResponse = createAccountRole(token, serviceAccount);
		if(accountRoleCreationResponse.getStatusCode().equals(HttpStatus.OK)) {
			// Create Metadata
			return createMetaDataForServiceAccount(token, serviceAccount, userDetails);
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ONBOARD_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Failed to onboard AD service account into TVault for password rotation.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to onboard AD service account into TVault for password rotation.\"]}");
		}
	}

	private ResponseEntity<String> createMetaDataForServiceAccount(String token, ServiceAccount serviceAccount,
			UserDetails userDetails) {
		ResponseEntity<String> metadataCreationResponse = createMetadata(token, serviceAccount);
		if (HttpStatus.OK.equals(metadataCreationResponse.getStatusCode())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ONBOARD_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Successfully created Metadata for the Service Account").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ONBOARD_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Successfully created Service Account Role. However creation of Metadata failed.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"errors\":[\"Successfully created Service Account Role. However creation of Metadata failed.\"]}");
		}
		String svcAccName = serviceAccount.getName();
		ResponseEntity<String> svcAccPolicyCreationResponse = createServiceAccountPolicies(token, svcAccName);
		return validateSvcAccPolicyCreationResponse(token, serviceAccount, userDetails, svcAccName,
				svcAccPolicyCreationResponse);
	}

	private ResponseEntity<String> validateSvcAccPolicyCreationResponse(String token, ServiceAccount serviceAccount,
			UserDetails userDetails, String svcAccName, ResponseEntity<String> svcAccPolicyCreationResponse) {
		if (HttpStatus.OK.equals(svcAccPolicyCreationResponse.getStatusCode())) {
			ServiceAccountUser serviceAccountUser = new ServiceAccountUser(svcAccName, serviceAccount.getOwner(), TVaultConstants.SUDO_POLICY);
			ResponseEntity<String> addUserToServiceAccountResponse = addUserToServiceAccount(token, serviceAccountUser, userDetails, true);
			if (HttpStatus.OK.equals(addUserToServiceAccountResponse.getStatusCode())) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, ONBOARD_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, "Successfully completed onboarding of AD service account into TVault for password rotation.").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));

				// send email notification to service account owner
				sendEmailNotificationToOwner(serviceAccount, svcAccName);
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully completed onboarding of AD service account into TVault for password rotation.\"]}");
			}
			else {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, ONBOARD_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, "Successfully created Service Account Role and policies. However the association of owner information failed.").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"messages\":[\"Successfully created Service Account Role and policies. However the association of owner information failed.\"]}");
			}
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ONBOARD_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Failed to onboard AD service account into TVault for password rotation.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			OnboardedServiceAccount serviceAccountToRevert = new OnboardedServiceAccount(serviceAccount.getName(),serviceAccount.getOwner());
			ResponseEntity<String> accountRoleDeletionResponse = deleteAccountRole(token, serviceAccountToRevert);
			if (accountRoleDeletionResponse!=null && HttpStatus.OK.equals(accountRoleDeletionResponse.getStatusCode())) {
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to onboard AD service account into TVault for password rotation.\"]}");
			} else {
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to create Service Account policies. Revert service account role creation failed.\"]}");
			}
		}
	}

	private void sendEmailNotificationToOwner(ServiceAccount serviceAccount, String svcAccName) {
		// get service account owner email
		String filterQuery = "(&(objectclass=user)(|(cn=" + serviceAccount.getOwner() + ")))";
		List<ADUserAccount> managerDetails = getServiceAccountManagerDetails(filterQuery);
		if (!managerDetails.isEmpty() && !StringUtils.isEmpty(managerDetails.get(0).getUserEmail())) {
			String from = supportEmail;
			List<String> to = new ArrayList<>();
			to.add(managerDetails.get(0).getUserEmail());
			String mailSubject = String.format(subject, svcAccName);
			String groupContent = TVaultConstants.EMPTY;

			// set template variables
			Map<String, String> mailTemplateVariables = new HashMap<>();
			mailTemplateVariables.put("name", managerDetails.get(0).getDisplayName());
			mailTemplateVariables.put("svcAccName", svcAccName);
			if (serviceAccount.getAdGroup() != null && !serviceAccount.getAdGroup().equals("")) {
				groupContent = String.format(mailAdGroupContent, serviceAccount.getAdGroup());
			}
			mailTemplateVariables.put("groupContent", groupContent);
			mailTemplateVariables.put("contactLink", supportEmail);
			emailUtils.sendHtmlEmalFromTemplate(from, to, mailSubject, mailTemplateVariables);
		}
	}

    /**
     * Get the AD details for a given service account
     * @param serviceAccount
     * @return
     */
    private List<ADServiceAccount> getADServiceAccount(String serviceAccount) {
        AndFilter andFilter = new AndFilter();
        andFilter.and(new LikeFilter("userPrincipalName", serviceAccount+"*"));
        andFilter.and(new EqualsFilter("objectClass", "user"));
        andFilter.and(new NotFilter(new EqualsFilter("CN", adMasterServiveAccount)));
        return getADServiceAccounts(andFilter);
    }

	/**
	 * To create Metadata for the Service Account
	 * @param token
	 * @param serviceAccount
	 * @return
	 */
	private ResponseEntity<String> createMetadata(String token, ServiceAccount serviceAccount) {
		String svcAccMetaDataJson = populateSvcAccMetaJson(serviceAccount);
		boolean svcAccMetaDataCreationStatus = ControllerUtil.createMetadata(svcAccMetaDataJson, token);
		if(svcAccMetaDataCreationStatus){
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "createMetadata").
					put(LogMessage.MESSAGE, String.format("Successfully created metadata for the Service Account [%s]", serviceAccount.getName())).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created Metadata for the Service Account\"]}");
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, CREATE_ACCOUNT_ROLE_STRING).
					put(LogMessage.MESSAGE, "Unable to create Metadata for the Service Account").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to create Metadata for the Service Account\"]}");
	}
	/**
	 * To delete metadata for the service account
	 * @param token
	 * @param serviceAccount
	 * @return
	 */
	private ResponseEntity<String> deleteMetadata(String token, OnboardedServiceAccount serviceAccount) {
		String svcAccMetaDataJson = populateSvcAccMetaJson(serviceAccount.getName(), serviceAccount.getOwner());
		Response svcAccMetaDataJsonDeletionResponse = reqProcessor.process("/delete",svcAccMetaDataJson,token);
		if(HttpStatus.OK.equals(svcAccMetaDataJsonDeletionResponse.getHttpstatus()) || HttpStatus.NO_CONTENT.equals(svcAccMetaDataJsonDeletionResponse.getHttpstatus())){
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "deleteMetadata").
					put(LogMessage.MESSAGE, String.format("Successfully deleted metadata for the Service Account [%s]", serviceAccount.getName())).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully deleted Metadata for the Service Account\"]}");
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "deleteMetadata").
					put(LogMessage.MESSAGE, "Unable to delete Metadata for the Service Account").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to delete Metadata for the Service Account\"]}");
	}

	/**
	 * Helper to generate input JSON for Service Account metadata
	 * @param svcAccName
	 * @param username
	 * @return
	 */
	private String populateSvcAccMetaJson(String svcAccName, String username) {
		String metaDataPath = TVaultConstants.SVC_ACC_ROLES_METADATA_MOUNT_PATH + svcAccName;
		ServiceAccountMetadataDetails serviceAccountMetadataDetails = new ServiceAccountMetadataDetails(svcAccName);
		serviceAccountMetadataDetails.setManagedBy(username);
		serviceAccountMetadataDetails.setInitialPasswordReset(false);
		return populateSvcAccJsonString(metaDataPath, serviceAccountMetadataDetails);
	}

	/**
	 * Helper to generate input JSON for Service Account metadata
	 * @param serviceAccount
	 * @return
	 */
	private String populateSvcAccMetaJson(ServiceAccount serviceAccount) {
		String metaDataPath = TVaultConstants.SVC_ACC_ROLES_METADATA_MOUNT_PATH + serviceAccount.getName();
		ServiceAccountMetadataDetails serviceAccountMetadataDetails = new ServiceAccountMetadataDetails(serviceAccount.getName());
		serviceAccountMetadataDetails.setManagedBy(serviceAccount.getOwner());
		serviceAccountMetadataDetails.setInitialPasswordReset(false);
		serviceAccountMetadataDetails.setAdGroup(serviceAccount.getAdGroup());
		serviceAccountMetadataDetails.setAppName(serviceAccount.getAppName());
		serviceAccountMetadataDetails.setAppID(serviceAccount.getAppID());
		serviceAccountMetadataDetails.setAppTag(serviceAccount.getAppTag());
		return populateSvcAccJsonString(metaDataPath, serviceAccountMetadataDetails);
	}

	/**
	 * To generate json string for service account metadata
	 * @return
	 */
	String populateSvcAccJsonString(String path, ServiceAccountMetadataDetails serviceAccountMetadataDetails) {
		ServiceAccountMetadata serviceAccountMetadata =  new ServiceAccountMetadata(path, serviceAccountMetadataDetails);
		String jsonStr = JSONUtil.getJSON(serviceAccountMetadata);
		Map<String,Object> rqstParams = ControllerUtil.parseJson(jsonStr);
		rqstParams.put("path",path);
		return ControllerUtil.convetToJson(rqstParams);
	}

	/**
	 * Offboards an AD service account from TVault for password rotation
	 * @param token
	 * @param serviceAccount
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> offboardServiceAccount(String token, OnboardedServiceAccount serviceAccount) {
		String managedBy = "";
		String svcAccName = serviceAccount.getName();
		ResponseEntity<String> svcAccPolicyDeletionResponse = deleteServiceAccountPolicies(token, svcAccName);
		if (!HttpStatus.OK.equals(svcAccPolicyDeletionResponse.getStatusCode())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, OFFBOARD_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Failed to delete some of the policies for service account").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		// delete users,groups,aws-roles,app-roles from service account
		String metaDataPath = TVaultConstants.SVC_ACC_ROLES_METADATA_MOUNT_PATH + '/' + svcAccName;
		Response metaResponse = reqProcessor.process("/sdb","{\"path\":\""+metaDataPath+"\"}",token);
		Map<String, Object> responseMap = null;
		try {
			responseMap = new ObjectMapper().readValue(metaResponse.getResponse(), new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			log.error(e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Error Fetching existing service account info \"]}");
		}
		if(responseMap!=null && responseMap.get("data")!=null){
			Map<String,Object> metadataMap = (Map<String,Object>)responseMap.get("data");
			Map<String,String> awsroles = (Map<String, String>)metadataMap.get("aws-roles");
			Map<String,String> approles = (Map<String, String>)metadataMap.get("app-roles");
			Map<String,String> groups = (Map<String, String>)metadataMap.get("groups");
			Map<String,String> users = (Map<String, String>) metadataMap.get("users");
			// always add owner to the users list whose policy should be updated
			managedBy = (String) metadataMap.get(MANAGED_BY_STRING);
			if (!org.apache.commons.lang3.StringUtils.isEmpty(managedBy)) {
                if (null == users) {
                    users = new HashMap<>();
                }
				users.put(managedBy, "sudo");
			}
			updateUserPolicyAssociationOnSvcaccDelete(svcAccName,users,token);
			updateGroupPolicyAssociationOnSvcaccDelete(svcAccName,groups,token);
            deleteAwsRoleonOnSvcaccDelete(awsroles,token);
            updateApprolePolicyAssociationOnSvcaccDelete(svcAccName,approles,token);
		}
		ResponseEntity<String> accountRoleDeletionResponse = deleteAccountRole(token, serviceAccount);
		if (HttpStatus.OK.equals(accountRoleDeletionResponse.getStatusCode())) {
			// Remove metadata...
			serviceAccount.setOwner(managedBy);
			ResponseEntity<String> metadataUpdateResponse =  deleteMetadata(token, serviceAccount);
			if (HttpStatus.OK.equals(metadataUpdateResponse.getStatusCode())) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, OFFBOARD_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, "Successfully completed offboarding of AD service account from TVault for password rotation.").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully completed offboarding of AD service account from TVault for password rotation.\"]}");
			}
			else {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, OFFBOARD_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, "Unable to delete Metadata for the Service Account").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"errors\":[\"Failed to offboard AD service account from TVault for password rotation.\"]}");
			}
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, OFFBOARD_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Failed to offboard AD service account from TVault for password rotation.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"errors\":[\"Failed to offboard AD service account from TVault for password rotation.\"]}");
		}
	}

	/**
	 * Create Service Account Role
	 * @param token
	 * @param serviceAccount
	 * @return
	 */
	private ResponseEntity<String> createAccountRole(String token, ServiceAccount serviceAccount) {
		ServiceAccountTTL serviceAccountTTL = new ServiceAccountTTL();
		serviceAccountTTL.setRole_name(serviceAccount.getName());
		serviceAccountTTL.setService_account_name(serviceAccount.getName() + "@"+ serviceAccountSuffix) ;
		serviceAccountTTL.setTtl(serviceAccount.getTtl());
		String svcAccountPayload = JSONUtil.getJSON(serviceAccountTTL);
		Response onboardingResponse = reqProcessor.process("/ad/serviceaccount/onboard", svcAccountPayload, token);
		if(onboardingResponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || onboardingResponse.getHttpstatus().equals(HttpStatus.OK)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, CREATE_ACCOUNT_ROLE_STRING).
					put(LogMessage.MESSAGE, "Successfully created service account role.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created service account role.\"]}");
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, CREATE_ACCOUNT_ROLE_STRING).
					put(LogMessage.MESSAGE, "Failed to create service account role.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to create service account role.\"]}");
		}
	}
	/**
	 * Deletes the Account Role
	 * @param token
	 * @param serviceAccount
	 * @return
	 */
	private ResponseEntity<String> deleteAccountRole(String token, OnboardedServiceAccount serviceAccount) {
		ServiceAccountTTL serviceAccountTTL = new ServiceAccountTTL();
		serviceAccountTTL.setRole_name(serviceAccount.getName());
		serviceAccountTTL.setService_account_name(serviceAccount.getName() + "@"+ serviceAccountSuffix) ;
		String svcAccountPayload = JSONUtil.getJSON(serviceAccountTTL);
		Response onboardingResponse = reqProcessor.process("/ad/serviceaccount/offboard", svcAccountPayload, token);
		if(onboardingResponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || onboardingResponse.getHttpstatus().equals(HttpStatus.OK)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "deleteAccountRole").
					put(LogMessage.MESSAGE, "Successfully deleted service account role.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully deleted service account role.\"]}");
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "deleteAccountRole").
					put(LogMessage.MESSAGE, "Failed to delete service account role.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to delete service account role.\"]}");
		}
	}

	/**
	 * Create policies for service account
	 * @param token
	 * @param svcAccName
	 * @return
	 */
	private  ResponseEntity<String> createServiceAccountPolicies(String token, String svcAccName) {
		int succssCount = 0;
		for (String policyPrefix : TVaultConstants.getSvcAccPolicies().keySet()) {
			AccessPolicy accessPolicy = new AccessPolicy();
			String accessId = new StringBuffer().append(policyPrefix).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
			accessPolicy.setAccessid(accessId);
			HashMap<String,String> accessMap = new HashMap<>();
			String svcAccCredsPath=new StringBuffer().append(TVaultConstants.SVC_ACC_CREDS_PATH).append(svcAccName).toString();
			accessMap.put(svcAccCredsPath, TVaultConstants.getSvcAccPolicies().get(policyPrefix));
			// Attaching write permissions for owner
			if (TVaultConstants.getSvcAccPolicies().get(policyPrefix).equals(TVaultConstants.SUDO_POLICY)) {
				accessMap.put(TVaultConstants.SVC_ACC_ROLES_PATH + svcAccName, TVaultConstants.WRITE_POLICY);
				accessMap.put(TVaultConstants.SVC_ACC_ROLES_METADATA_MOUNT_PATH + svcAccName, TVaultConstants.WRITE_POLICY);
			}
			if (TVaultConstants.getSvcAccPolicies().get(policyPrefix).equals(TVaultConstants.WRITE_POLICY)) {
				accessMap.put(TVaultConstants.SVC_ACC_ROLES_PATH + svcAccName, TVaultConstants.WRITE_POLICY);
				accessMap.put(TVaultConstants.SVC_ACC_ROLES_METADATA_MOUNT_PATH + svcAccName, TVaultConstants.WRITE_POLICY);
			}
			accessPolicy.setAccess(accessMap);
			ResponseEntity<String> policyCreationStatus = accessService.createPolicy(token, accessPolicy);
			if (HttpStatus.OK.equals(policyCreationStatus.getStatusCode())) {
				succssCount++;
			}
		}
		if (succssCount == TVaultConstants.getSvcAccPolicies().size()) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "createServiceAccountPolicies").
					put(LogMessage.MESSAGE, "Successfully created policies for service account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created policies for service account\"]}");
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "createServiceAccountPolicies").
				put(LogMessage.MESSAGE, "Failed to create some of the policies for service account.").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"messages\":[\"Failed to create some of the policies for service account\"]}");
	}
	/**
	 * Deletes Service Account policies
	 * @param token
	 * @param svcAccName
	 * @return
	 */
	private  ResponseEntity<String> deleteServiceAccountPolicies(String token, String svcAccName) {
		int succssCount = 0;
		for (String policyPrefix : TVaultConstants.getSvcAccPolicies().keySet()) {
			String accessId = new StringBuffer().append(policyPrefix).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
			ResponseEntity<String> policyCreationStatus = accessService.deletePolicyInfo(token, accessId);
			if (HttpStatus.OK.equals(policyCreationStatus.getStatusCode())) {
				succssCount++;
			}
		}
		if (succssCount == TVaultConstants.getSvcAccPolicies().size()) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "deleteServiceAccountPolicies").
					put(LogMessage.MESSAGE, "Successfully created policies for service account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully removed policies for service account\"]}");
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "deleteServiceAccountPolicies").
				put(LogMessage.MESSAGE, "Failed to delete some of the policies for service account.").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"messages\":[\"Failed to delete some of the policies for service account\"]}");
	}
	/**
	 * Adds the user to a service account
	 * @param token
	 * @param serviceAccount
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> addUserToServiceAccount(String token, ServiceAccountUser serviceAccountUser, UserDetails userDetails, boolean isPartOfSvcAccOnboard) {
        if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, ADD_USER_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, "Trying to add user to ServiceAccount").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

		if(!isSvcaccPermissionInputValid(serviceAccountUser.getAccess())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERROR_INVALID_VALUE_MSG);
		}
		if (serviceAccountUser.getAccess().equalsIgnoreCase(RESET_STRING)) {
			serviceAccountUser.setAccess(TVaultConstants.WRITE_POLICY);
		}

		String userName = serviceAccountUser.getUsername();
		String svcAccName = serviceAccountUser.getSvcAccName();
		String access = serviceAccountUser.getAccess();


		userName = (userName !=null) ? userName.toLowerCase() : userName;
		access = (access != null) ? access.toLowerCase(): access;

		boolean isAuthorized = true;
		
		isAuthorized = hasAddUserPermission(userDetails, svcAccName, token, isPartOfSvcAccOnboard);		

		if(isAuthorized){
			return processForAddingUserToServiceAccount(token, serviceAccountUser, userDetails, userName, svcAccName,
					access);
			
		}else{
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to users to this service account\"]}");
		}
	}

	private ResponseEntity<String> processForAddingUserToServiceAccount(String token,
			ServiceAccountUser serviceAccountUser, UserDetails userDetails, String userName, String svcAccName,
			String access) {
		if (!ifInitialPwdReset(token, userDetails, serviceAccountUser.getSvcAccName()) && !TVaultConstants.SUDO_POLICY.equals(serviceAccountUser.getAccess())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ADD_USER_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Failed to add user permission to Service account. Initial password reset is pending for this Service Account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to add user permission to Service account. Initial password reset is pending for this Service Account. Please reset the password and try again.\"]}");
		}
		String policy = "";
		policy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(access)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "Add User to Service Account").
				put(LogMessage.MESSAGE, String.format (POLICY_MSG_STRING, policy)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		Response userResponse = processVaultAuthRequestByMethod(token, userName, readPolicy, writePolicy,
				denyPolicy, sudoPolicy);

		String responseJson="";
		String groups="";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();

		if(HttpStatus.OK.equals(userResponse.getHttpstatus())){
			responseJson = userResponse.getResponse();	
			try {
				ObjectMapper objMapper = new ObjectMapper();
				currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
				if (!(TVaultConstants.USERPASS.equals(vaultAuthMethod))) {
					groups =objMapper.readTree(responseJson).get("data").get("groups").asText();
				}
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, ADD_USER_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, ERROR_POLICY_GROUP_MSG).
						put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
			}

			policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
			policies.add(policy);
		}else{
			// New user to be configured
			policies.add(policy);
		}
		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, ADD_USER_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format ("policies [%s] before calling configureUserpassUser/configureLDAPUser", policies)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		Response ldapConfigresponse;
		ldapConfigresponse = configureServiceAccountToUser(token, userName, groups, policiesString);
		if(ldapConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || ldapConfigresponse.getHttpstatus().equals(HttpStatus.OK)){
			// User has been associated with Service Account. Now metadata has to be created
			return updateMetaDataForUserWithServiceAccount(token, serviceAccountUser, userName, svcAccName, access,
					groups, currentpoliciesString);
		}
		else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to add user to the Service Account\"]}");
		}
	}

	private Response processVaultAuthRequestByMethod(String token, String userName, String readPolicy,
			String writePolicy, String denyPolicy, String sudoPolicy) {
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "Add User to Service Account").
				put(LogMessage.MESSAGE, String.format (POLICIES_MSG_STRING, readPolicy, writePolicy, denyPolicy, sudoPolicy)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		Response userResponse;
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			userResponse = reqProcessor.process(AUTH_USERPASS_READ,USERNAME_FORMAT_STRING+userName+"\"}",token);	
		}
		else {
			userResponse = reqProcessor.process(AUTH_LDAP_USERS,USERNAME_FORMAT_STRING+userName+"\"}",token);
		}
		return userResponse;
	}

	private Response configureServiceAccountToUser(String token, String userName, String groups,
			String policiesString) {
		Response ldapConfigresponse;
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			ldapConfigresponse = ControllerUtil.configureUserpassUser(userName,policiesString,token);
		}
		else {
			ldapConfigresponse = ControllerUtil.configureLDAPUser(userName,policiesString,groups,token);
		}
		return ldapConfigresponse;
	}

	private ResponseEntity<String> updateMetaDataForUserWithServiceAccount(String token,
			ServiceAccountUser serviceAccountUser, String userName, String svcAccName, String access, String groups,
			String currentpoliciesString) {
		String path = new StringBuffer(TVaultConstants.SVC_ACC_ROLES_PATH).append(svcAccName).toString();
		Map<String,String> params = new HashMap<>();
		params.put("type", "users");
		params.put("name",serviceAccountUser.getUsername());
		params.put("path",path);
		params.put(ACCESS_STRING,access);
		Response metadataResponse = ControllerUtil.updateMetadata(params,token);
		if(metadataResponse != null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ADD_USER_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "User is successfully associated with Service Account").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully added user to the Service Account\"]}");
		} else{
			return revertMetaDataCreationForUser(token, userName, groups, currentpoliciesString);
		}
	}

	private ResponseEntity<String> revertMetaDataCreationForUser(String token, String userName, String groups,
			String currentpoliciesString) {
		Response ldapConfigresponse;
		//Revert the user association...
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, ADD_USER_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, "Metadata creation for user association with service account failed").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		ldapConfigresponse = configureServiceAccountToUser(token, userName, groups, currentpoliciesString);
		if(ldapConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || ldapConfigresponse.getHttpstatus().equals(HttpStatus.OK)) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"messages\":[\"Failed to add user to the Service Account. Metadata update failed\"]}");
		} else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"messages\":[\"Failed to revert user association on Service Account\"]}");
		}
	}

    /**
     * To check the initial password reset status
     * @param token
     * @param userDetails
     * @param svcAccName
     * @return
     */
	private boolean ifInitialPwdReset(String token, UserDetails userDetails, String svcAccName) {
		String metaDataPath = TVaultConstants.SVC_ACC_ROLES_PATH + svcAccName;
		boolean initialResetStatus = false;
		Response metaResponse = getMetadata(token, userDetails, metaDataPath);
		try {
            JsonNode resetStatus = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get(INITIAL_PASSWRD_RESET);
            if (resetStatus != null) {
                initialResetStatus = Boolean.parseBoolean(resetStatus.asText());
            }
		} catch (IOException e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "ifInitialPwdReset").
					put(LogMessage.MESSAGE, String.format ("Failed to get Initial password status for the Service account [%s]", svcAccName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return initialResetStatus;
	}

	/**
	 * Removes user from service account
	 * @param token
	 * @param safeUser
	 * @return
	 */
	public ResponseEntity<String> removeUserFromServiceAccount(String token, ServiceAccountUser serviceAccountUser, UserDetails userDetails) {
		if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
		if(!isSvcaccPermissionInputValid(serviceAccountUser.getAccess())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERROR_INVALID_VALUE_MSG);
		}
		if (serviceAccountUser.getAccess().equalsIgnoreCase(RESET_STRING)) {
			serviceAccountUser.setAccess(TVaultConstants.WRITE_POLICY);
		}
		String userName = serviceAccountUser.getUsername().toLowerCase();
		String svcAccName = serviceAccountUser.getSvcAccName();		

		boolean isAuthorized = true;
		
		isAuthorized = hasAddOrRemovePermission(userDetails, serviceAccountUser.getSvcAccName(), token);
		
		if(isAuthorized){
			return processForRemovingUserFromServiceAccount(token, serviceAccountUser, userDetails, userName,
					svcAccName);	
		}
		else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to remove user from this service account\"]}");
		}
	}

	private ResponseEntity<String> processForRemovingUserFromServiceAccount(String token,
			ServiceAccountUser serviceAccountUser, UserDetails userDetails, String userName, String svcAccName) {
		if (!ifInitialPwdReset(token, userDetails, serviceAccountUser.getSvcAccName())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, REMOVE_USER_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Failed to remove user permission from Service account. Initial password reset is pending for this Service Account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to remove user permission from Service account. Initial password reset is pending for this Service Account. Please reset the password and try again.\"]}");
		}
		String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "Remove user from Service Account").
				put(LogMessage.MESSAGE, String.format (POLICIES_MSG_STRING, readPolicy, writePolicy, denyPolicy, sudoPolicy)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		Response userResponse;
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			userResponse = reqProcessor.process(AUTH_USERPASS_READ,USERNAME_FORMAT_STRING+userName+"\"}",token);	
		}
		else {
			userResponse = reqProcessor.process(AUTH_LDAP_USERS,USERNAME_FORMAT_STRING+userName+"\"}",token);
		}

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, REMOVE_USER_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format (USER_RESPONSE_MSG_STRING, userResponse.getHttpstatus())).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

		String responseJson="";
		String groups="";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();
		if(HttpStatus.OK.equals(userResponse.getHttpstatus())){
			responseJson = userResponse.getResponse();	
			try {
				ObjectMapper objMapper = new ObjectMapper();
				currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
				if (!(TVaultConstants.USERPASS.equals(vaultAuthMethod))) {
					groups =objMapper.readTree(responseJson).get("data").get("groups").asText();
				}
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, REMOVE_USER_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, ERROR_POLICY_GROUP_MSG).
						put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
			}
			policies.addAll(currentpolicies);				
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
		}
		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");
		Response ldapConfigresponse;
		ldapConfigresponse = configureServiceAccountToUser(token, userName, groups, policiesString);
		return updateMetaDataAfterRemovedUserFromServiceAccount(token, userName, svcAccName, groups,
				currentpoliciesString, ldapConfigresponse);
	}

	private ResponseEntity<String> updateMetaDataAfterRemovedUserFromServiceAccount(String token, String userName,
			String svcAccName, String groups, String currentpoliciesString, Response ldapConfigresponse) {
		if(ldapConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || ldapConfigresponse.getHttpstatus().equals(HttpStatus.OK)){
			// User has been associated with Service Account. Now metadata has to be deleted
			String path = new StringBuffer(TVaultConstants.SVC_ACC_ROLES_PATH).append(svcAccName).toString();
			Map<String,String> params = new HashMap<>();
			params.put("type", "users");
			params.put("name",userName);
			params.put("path",path);
			params.put(ACCESS_STRING,DELETE_STRING);
			Response metadataResponse = ControllerUtil.updateMetadata(params,token);
			if(metadataResponse != null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, REMOVE_USER_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, "User is successfully Removed from Service Account").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully removed user from the Service Account\"]}");
			} else {
				ldapConfigresponse = configureServiceAccountToUser(token, userName, groups, currentpoliciesString);
				if(ldapConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || ldapConfigresponse.getHttpstatus().equals(HttpStatus.OK)) {
					return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to remove the user from the Service Account. Metadata update failed\"]}");
				} else {
					return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to revert user association on Service Account\"]}");
				}
			}
		}
		else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to remvoe the user from the Service Account\"]}");
		}
	}
	/**
	 * Temporarily sleep for a second
	 */
	private void sleep() {
		try {
			Thread.sleep(1000);
		}
		catch(InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
	}

	/**
	 * To reset Service Account Password
	 * @param token
	 * @param svcAccName
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> resetSvcAccPassword(String token, String svcAccName, UserDetails userDetails){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, RESET_SVCACC_PASSWRD).
				put(LogMessage.MESSAGE, String.format("Trying to reset service account password [%s]", svcAccName)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		OnboardedServiceAccountDetails onbSvcAccDtls = getOnboarderdServiceAccountDetails(token, svcAccName);
		if (onbSvcAccDtls == null) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, RESET_SVCACC_PASSWRD).
					put(LogMessage.MESSAGE, String.format(UNABLE_TO_RESET_PASSWRD_STRING, svcAccName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Unable to reset password details for the given service account\"]}");
		}

		long ttl = onbSvcAccDtls.getTtl();
		ServiceAccount serviceAccount = new ServiceAccount();
		serviceAccount.setName(svcAccName);
		serviceAccount.setAutoRotate(true);
		serviceAccount.setTtl(1L); // set ttl to 1 second to temporarily so that it can be rotated immediately

		ResponseEntity<String> roleCreationResetResponse = createAccountRole(token, serviceAccount);
		if(roleCreationResetResponse.getStatusCode().equals(HttpStatus.OK)) {
			sleep();
			//Reset the password now...
			Response resetResponse = reqProcessor.process("/ad/serviceaccount/resetpwd",ROLE_NAME_FORMAT_STRING+svcAccName+"\"}",token);
			if(HttpStatus.OK.equals(resetResponse.getHttpstatus())) {
				//Reset ttl to 90 days (or based on password policy) long ttl = 7776000L; // 90 days...
				serviceAccount.setTtl(ttl);
				ResponseEntity<String> roleCreationResponse = createAccountRole(token, serviceAccount);
				if(roleCreationResponse.getStatusCode().equals(HttpStatus.OK)) {
					// Read the password to get the updated one.
					Response response = reqProcessor.process("/ad/serviceaccount/readpwd",ROLE_NAME_FORMAT_STRING+svcAccName+"\"}",token);
					return readPasswordAndUpdateMetaDataInfo(token, svcAccName, userDetails, response);
				}
				else {
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, RESET_SVCACC_PASSWRD).
							put(LogMessage.MESSAGE, String.format(UNABLE_TO_RESET_PASSWRD_STRING, svcAccName)).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Unable to reset password details for the given service account. Failed to reset the service account with original ttl.\"]}");
				}
			}
			else {
				return revertSvcAccRole(token, svcAccName, ttl, serviceAccount, resetResponse);
			}
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, RESET_SVCACC_PASSWRD).
				put(LogMessage.MESSAGE, String.format(UNABLE_TO_RESET_PASSWRD_STRING, svcAccName)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Unable to reset password details for the given service account\"]}");
	}

	private ResponseEntity<String> readPasswordAndUpdateMetaDataInfo(String token, String svcAccName,
			UserDetails userDetails, Response response) {
		if(HttpStatus.OK.equals(response.getHttpstatus())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, RESET_SVCACC_PASSWRD).
					put(LogMessage.MESSAGE, String.format("Successfully reset service account password for [%s]", svcAccName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			try {
				ADServiceAccountCreds adServiceAccountCreds = new ADServiceAccountCreds();
				Map<String, Object> requestParams = new ObjectMapper().readValue(response.getResponse(), new TypeReference<Map<String, Object>>(){});
				if (requestParams.get(CURRENT_PASSWRD_STRING) != null) {
					adServiceAccountCreds.setCurrent_password((String) requestParams.get(CURRENT_PASSWRD_STRING));
				}
				if (requestParams.get(USERNAME_STRING) != null) {
					adServiceAccountCreds.setUsername((String) requestParams.get(USERNAME_STRING));
				}
				if (requestParams.get(LAST_PASSWRD_STRING) != null ) {
					adServiceAccountCreds.setLast_password((String) requestParams.get(LAST_PASSWRD_STRING));
				}

				// Check metadata to get the owner information
				Response metaDataResponse = getMetadata(token, userDetails, TVaultConstants.SVC_ACC_ROLES_PATH + svcAccName);
				if (metaDataResponse!=null) {
					updateMetaDataOnSvcAccPasswrdReset(token, svcAccName, userDetails, metaDataResponse);
				}
				else {
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, RESET_SVCACC_PASSWRD).
							put(LogMessage.MESSAGE, String.format ("Failed to get metadata for the Service account [%s]", svcAccName)).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}
				return ResponseEntity.status(HttpStatus.OK).body(JSONUtil.getJSON(adServiceAccountCreds));
			}
			catch(Exception ex) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, READ_SVCACC_PASSWRD).
						put(LogMessage.MESSAGE, String.format("There are no service accounts currently onboarded or error in retrieving credentials for the onboarded service account [%s]", svcAccName)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));

			}
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERROR_UNABLE_GET_PASSWRD_MSG);
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, RESET_SVCACC_PASSWRD).
					put(LogMessage.MESSAGE, String.format(UNABLE_TO_RESET_PASSWRD_STRING, svcAccName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Unable to reset password details for the given service account. Failed to read the updated password.\"]}");
		}
	}

	private ResponseEntity<String> revertSvcAccRole(String token, String svcAccName, long ttl,
			ServiceAccount serviceAccount, Response resetResponse) {
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, RESET_SVCACC_PASSWRD).
				put(LogMessage.MESSAGE, String.format(UNABLE_TO_RESET_PASSWRD_STRING, svcAccName)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		//Reset ttl to 90 days (or based on password policy) long ttl = 7776000L; // 90 days...
		serviceAccount.setTtl(ttl);
		ResponseEntity<String> roleCreationResponse = createAccountRole(token, serviceAccount);
		if(roleCreationResponse.getStatusCode().equals(HttpStatus.OK)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, RESET_SVCACC_PASSWRD).
					put(LogMessage.MESSAGE, String.format("Unable to reset password for [%s]. Role updated back to the correct ttl", svcAccName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		if (HttpStatus.FORBIDDEN.equals(resetResponse.getHttpstatus())) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body("{\"errors\":[\"Access denied: Unable to reset password details for the given service account.\"]}");
		}
		else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Unable to reset password details for the given service account. Failed to read the updated password after setting ttl to 1 second.\"]}");
		}
	}

	private void updateMetaDataOnSvcAccPasswrdReset(String token, String svcAccName, UserDetails userDetails,
			Response metaDataResponse) {
		try {
			JsonNode metaNode = new ObjectMapper().readTree(metaDataResponse.getResponse()).get("data").get(INITIAL_PASSWRD_RESET);
			if (metaNode != null) {
				boolean initialResetStatus = false;

				initialResetStatus = Boolean.parseBoolean(metaNode.asText());
				if (!initialResetStatus) {

					// update metadata for initial password reset
					String path = new StringBuffer(TVaultConstants.SVC_ACC_ROLES_PATH).append(svcAccName).toString();
					Map<String,String> params = new HashMap<>();
					params.put("type", INITIAL_PASSWRD_RESET);
					params.put("path",path);
					params.put("value","true");
					Response metadataResponse = ControllerUtil.updateMetadataOnSvcaccPwdReset(params,token);
					if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
						log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
								put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
								put(LogMessage.ACTION, "Update metadata on password reset").
								put(LogMessage.MESSAGE, "Metadata update Success.").
								put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
								put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								build()));
					}
					else {
						log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
								put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
								put(LogMessage.ACTION, "Update metadata on password reset").
								put(LogMessage.MESSAGE, "Metadata update failed.").
								put(LogMessage.STATUS, metadataResponse!=null?metadataResponse.getHttpstatus().toString():HttpStatus.BAD_REQUEST.toString()).
								put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								build()));
					}

					addReadAndResetPermissionToServiceAccount(token, svcAccName, userDetails, metaDataResponse);
				}

			}
		} catch (IOException e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, RESET_SVCACC_PASSWRD).
					put(LogMessage.MESSAGE, String.format ("Failed to get metadata for the Service account [%s]", svcAccName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
	}

	private void addReadAndResetPermissionToServiceAccount(String token, String svcAccName, UserDetails userDetails,
			Response metaDataResponse) throws IOException {
		JsonNode metaNode;
		metaNode = new ObjectMapper().readTree(metaDataResponse.getResponse()).get("data").get(MANAGED_BY_STRING);
		String svcOwner = metaNode.asText();
		// Adding read and reset permisison to Service account by default. (At the time of initial password reset)
		ServiceAccountUser serviceAccountOwner = new ServiceAccountUser(svcAccName, svcOwner, TVaultConstants.RESET_POLICY);
		ResponseEntity<String> addOwnerWriteToServiceAccountResponse = addUserToServiceAccount(token, serviceAccountOwner, userDetails, false);
		if (addOwnerWriteToServiceAccountResponse!= null && HttpStatus.NO_CONTENT.equals(addOwnerWriteToServiceAccountResponse.getStatusCode())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, READ_SVCACC_PASSWRD).
					put(LogMessage.MESSAGE, "Updated write permission to Service account owner as part of initial reset.").
					put(LogMessage.STATUS, addOwnerWriteToServiceAccountResponse.getStatusCode().toString()).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
	}

	/**
	 * Gets service account password
	 * @param token
	 * @param svcAccName
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> readSvcAccPassword(String token, String svcAccName, UserDetails userDetails){

		// Restricting owner from reading password before activation. Owner can read/reset password after activation.
		ServiceAccountMetadataDetails metadataDetails = getServiceAccountMetadataDetails(token, userDetails, svcAccName);
		if (userDetails.getUsername().equalsIgnoreCase(metadataDetails.getManagedBy()) && !metadataDetails.getInitialPasswordReset()) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, READ_SVCACC_PASSWRD).
					put(LogMessage.MESSAGE, "Failed to read service account password. Initial password reset is pending for this Service Account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to read service account password. Initial password reset is pending for this Service Account. Please reset the password and try again.\"]}");
		}

		Response response = reqProcessor.process("/ad/serviceaccount/readpwd",ROLE_NAME_FORMAT_STRING+svcAccName+"\"}",token);
		ADServiceAccountCreds adServiceAccountCreds = null;
		if (HttpStatus.OK.equals(response.getHttpstatus())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, READ_SVCACC_PASSWRD).
					put(LogMessage.MESSAGE, String.format("Successfully read the password details for the service account [%s]", svcAccName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			try {
				adServiceAccountCreds = new ADServiceAccountCreds();
				Map<String, Object> requestParams = new ObjectMapper().readValue(response.getResponse(), new TypeReference<Map<String, Object>>(){});
				if (requestParams.get(CURRENT_PASSWRD_STRING) != null) {
					adServiceAccountCreds.setCurrent_password((String) requestParams.get(CURRENT_PASSWRD_STRING));
				}
				if (requestParams.get(USERNAME_STRING) != null) {
					adServiceAccountCreds.setUsername((String) requestParams.get(USERNAME_STRING));
				}
				if (requestParams.get(LAST_PASSWRD_STRING) != null ) {
					adServiceAccountCreds.setLast_password((String) requestParams.get(LAST_PASSWRD_STRING));
				}
				return ResponseEntity.status(HttpStatus.OK).body(JSONUtil.getJSON(adServiceAccountCreds));
			}
			catch(Exception ex) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, READ_SVCACC_PASSWRD).
						put(LogMessage.MESSAGE, String.format("There are no service accounts currently onboarded or error in retrieving credentials for the onboarded service account [%s]", svcAccName)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));

			}
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERROR_UNABLE_GET_PASSWRD_MSG);
		}
		else if (HttpStatus.FORBIDDEN.equals(response.getHttpstatus())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, READ_SVCACC_PASSWRD).
					put(LogMessage.MESSAGE, String.format("Permission denied to read password for [%s]", svcAccName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body("{\"errors\":[\"Access denied: no permission to read the password details for the given service account\"]}");

		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, READ_SVCACC_PASSWRD).
					put(LogMessage.MESSAGE, String.format("Unable to read password for [%s]", svcAccName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERROR_UNABLE_GET_PASSWRD_MSG);
		}
	}

	/**
	 * Gets the details of a service account that is already onboarded into TVault
	 * @param token
	 * @param svcAccName
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> getOnboarderdServiceAccount(String token, String svcAccName){
		OnboardedServiceAccountDetails onbSvcAccDtls = getOnboarderdServiceAccountDetails(token, svcAccName);
		if (onbSvcAccDtls != null) {
			String onbSvcAccDtlsJson = JSONUtil.getJSON(onbSvcAccDtls);
			return ResponseEntity.status(HttpStatus.OK).body(onbSvcAccDtlsJson);
		}
		else {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"errors\":[\"Either Service Account is not onbaorderd or you don't have enough permission to read\"]}");
		}
	}
	/**
	 * Gets the details of an onboarded service account
	 * @return
	 */
	private OnboardedServiceAccountDetails getOnboarderdServiceAccountDetails(String token, String svcAccName) {
		OnboardedServiceAccountDetails onbSvcAccDtls = null;
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "getOnboardedServiceAccountDetails").
			      put(LogMessage.MESSAGE, "Trying to get onboaded service account details").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		Response svcAccDtlsresponse = reqProcessor.process("/ad/serviceaccount/details",ROLE_NAME_FORMAT_STRING+svcAccName+"\"}",token);
		if (HttpStatus.OK.equals(svcAccDtlsresponse.getHttpstatus())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "getOnboardedServiceAccountDetails").
				      put(LogMessage.MESSAGE, "Successfully retrieved the Service Account details").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			try {
				String response = svcAccDtlsresponse.getResponse();
				Map<String, Object> requestParams = new ObjectMapper().readValue(response, new TypeReference<Map<String, Object>>(){});
				
				String accName =  (String) requestParams.get("service_account_name");
				Integer accTTL = (Integer)requestParams.get("ttl");
				String accLastPwdRotation = (String) requestParams.get("last_vault_rotation");
				String accLastPwd = (String) requestParams.get("password_last_set");
				onbSvcAccDtls = new OnboardedServiceAccountDetails();
				onbSvcAccDtls.setName(accName);
				
				onbSvcAccDtls.setTtl(accTTL.longValue());
				
				onbSvcAccDtls.setLastVaultRotation(accLastPwdRotation);
				onbSvcAccDtls.setPasswordLastSet(accLastPwd);
			}
			catch(Exception ex) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "getADServiceAccounts").
						put(LogMessage.MESSAGE, "There are no service accounts currently onboarded or error in retrieving onboarded service accounts").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				
			}
			return onbSvcAccDtls;
		}
		else {
			return onbSvcAccDtls;
		}
	}
	/**
	 * 
	 * @param userDetails
	 * @param serviceAccountUser
	 * @param action
	 * @return
	 */
	public boolean canAddOrRemoveUser(UserDetails userDetails) {
		boolean isAdmin = true;
		if (userDetails != null && userDetails.isAdmin()) {
			// Admin is always authorized to add/remove user
			isAdmin = true;
		}
		else {
			//Implementation to be completed...
			// Get the policies for the current users
			// Get the serviceAccountName from serviceAccountUser
			// If there is owner policy for the serviceAccountName, then this owner can add/remove user
			isAdmin = false;
		}
		return isAdmin;
	}
	/**
	 * To get list of service accounts
	 * @param token
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> getOnboardedServiceAccounts(String token,  UserDetails userDetails) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "listOnboardedServiceAccounts").
			      put(LogMessage.MESSAGE, "Trying to get list of onboaded service accounts").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		Response response = null;
		if (userDetails.isAdmin()) {
			response = reqProcessor.process("/ad/serviceaccount/onboardedlist","{}",token);
		}
		else {
			String[] latestPolicies = policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername());
			List<String> onboardedlist = new ArrayList<>();
			for (String policy: latestPolicies) {
				if (policy.startsWith("o_")) {
					onboardedlist.add(policy.substring(10));
				}
			}
			response = new Response();
			response.setHttpstatus(HttpStatus.OK);
			response.setSuccess(true);
			response.setResponse("{\"keys\":"+JSONUtil.getJSON(onboardedlist)+"}");
		}

		if (HttpStatus.OK.equals(response.getHttpstatus())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "listOnboardedServiceAccounts").
				      put(LogMessage.MESSAGE, "Successfully retrieved the list of Service Accounts").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}
		else if (HttpStatus.NOT_FOUND.equals(response.getHttpstatus())) {
			return ResponseEntity.status(HttpStatus.OK).body("{\"keys\":[]}");
		}
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
	}

    /**
     * Check if user has the permission to add user/group/awsrole/approles to the Service Account
     * @param userDetails
     * @param action
     * @param token
     * @return
     */
    public boolean hasAddOrRemovePermission(UserDetails userDetails, String serviceAccount, String token) {
		// Owner of the service account can add/remove users, groups, aws roles and approles to service account
        String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(serviceAccount).toString();
        String [] policies = policyUtils.getCurrentPolicies(token, userDetails.getUsername());
        return (ArrayUtils.contains(policies, sudoPolicy));
    }

	/**
	 * Check if user has the permission to add user to the Service Account
	 * @param userDetails
	 * @param serviceAccount
	 * @param access
	 * @param token
	 * @return
	 */
	public boolean hasAddUserPermission(UserDetails userDetails, String serviceAccount, String token, boolean isPartOfSvcAccOnboard) {
		// Admin user can add sudo policy for owner while onboarding the service account
		if (userDetails.isAdmin() && isPartOfSvcAccOnboard) {
			return true;
		}
		// Owner of the service account can add/remove users, groups, aws roles and approles to service account
		String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(serviceAccount).toString();
		String [] policies = policyUtils.getCurrentPolicies(token, userDetails.getUsername());
		return (ArrayUtils.contains(policies, sudoPolicy));
	}
	/**
	 * Validates Service Account permission inputs
	 * @param access
	 * @return
	 */
	public static boolean isSvcaccPermissionInputValid(String access) {
		boolean isValid = true;
		if (!org.apache.commons.lang3.ArrayUtils.contains(permissions, access)) {
			isValid = false;
		}
		return isValid;
	}

    /**
     * Add Group to Service Account
     * @param token
     * @param serviceAccountGroup
     * @param userDetails
     * @return
     */
	public ResponseEntity<String> addGroupToServiceAccount(String token, ServiceAccountGroup serviceAccountGroup, UserDetails userDetails) {

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, ADD_GROUP_TO_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, "Trying to add Group to Service Account").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
        if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
        if(!isSvcaccPermissionInputValid(serviceAccountGroup.getAccess())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERROR_INVALID_VALUE_MSG);
        }
		if (serviceAccountGroup.getAccess().equalsIgnoreCase(RESET_STRING)) {
			serviceAccountGroup.setAccess(TVaultConstants.WRITE_POLICY);
		}
		String groupName = serviceAccountGroup.getGroupname();
		String svcAccName = serviceAccountGroup.getSvcAccName();
		String access = serviceAccountGroup.getAccess();

		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"This operation is not supported for Userpass authentication. \"]}");
		}

		groupName = (groupName !=null) ? groupName.toLowerCase() : groupName;
		access = (access != null) ? access.toLowerCase(): access;

		boolean canAddGroup = hasAddOrRemovePermission(userDetails, svcAccName, token);
		if(canAddGroup){
			return processAndAddGroupToServiceAccount(token, serviceAccountGroup, userDetails, groupName, svcAccName,
					access);
		}else{
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to add groups to this service account\"]}");
		}
	}

	private ResponseEntity<String> processAndAddGroupToServiceAccount(String token,
			ServiceAccountGroup serviceAccountGroup, UserDetails userDetails, String groupName, String svcAccName,
			String access) {
		if (!ifInitialPwdReset(token, userDetails, serviceAccountGroup.getSvcAccName())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ADD_GROUP_TO_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Failed to add group permission to Service account. Initial password reset is pending for this Service Account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to add group permission to Service account. Initial password reset is pending for this Service Account. Please reset the password and try again.\"]}");
		}
		String policy = "";
		policy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(access)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, ADD_GROUP_TO_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format (POLICY_MSG_STRING, policy)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, ADD_GROUP_TO_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format (POLICIES_MSG_STRING, readPolicy, writePolicy, denyPolicy, sudoPolicy)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

		Response groupResp = reqProcessor.process(AUTH_LDAP_GROUPS,GROUP_NAME_STRING+groupName+"\"}",token);

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, ADD_GROUP_TO_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format (USER_RESPONSE_MSG_STRING, groupResp.getHttpstatus())).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

		String responseJson="";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();

		if(HttpStatus.OK.equals(groupResp.getHttpstatus())){
			responseJson = groupResp.getResponse();
			try {
				ObjectMapper objMapper = new ObjectMapper();
				currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "Add Group to ServiceAccount").
						put(LogMessage.MESSAGE, "Exception while creating currentpolicies").
						put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
			}

			policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
			policies.add(policy);
		}else{
			// New group to be configured
			policies.add(policy);
		}
		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "Add Group to ServiceAccount").
				put(LogMessage.MESSAGE, String.format ("policies [%s] before calling configureLDAPGroup", policies)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

		Response ldapConfigresponse = ControllerUtil.configureLDAPGroup(groupName,policiesString,token);

		return updateMetaDataAndConfigureLDAPGroup(token, groupName, svcAccName, access, currentpoliciesString,
				ldapConfigresponse);
	}

	private ResponseEntity<String> updateMetaDataAndConfigureLDAPGroup(String token, String groupName,
			String svcAccName, String access, String currentpoliciesString, Response ldapConfigresponse) {
		if(ldapConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || ldapConfigresponse.getHttpstatus().equals(HttpStatus.OK)){
			String path = new StringBuffer(TVaultConstants.SVC_ACC_ROLES_PATH).append(svcAccName).toString();
			Map<String,String> params = new HashMap<>();
			params.put("type", "groups");
			params.put("name",groupName);
			params.put("path",path);
			params.put(ACCESS_STRING,access);

			Response metadataResponse = ControllerUtil.updateMetadata(params,token);
			if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, ADD_GROUP_TO_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, "Group configuration Success.").
						put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Group is successfully associated with Service Account\"]}");
			}
			return configureLDAPGroupForServiceAccount(token, groupName, currentpoliciesString, metadataResponse);
		}
		else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to add group to the Service Account\"]}");
		}
	}

	private ResponseEntity<String> configureLDAPGroupForServiceAccount(String token, String groupName,
			String currentpoliciesString, Response metadataResponse) {
		Response ldapConfigresponse;
		ldapConfigresponse = ControllerUtil.configureLDAPGroup(groupName,currentpoliciesString,token);
		if(ldapConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ADD_GROUP_TO_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Reverting, group policy update success").
					put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
					put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Group configuration failed. Please try again\"]}");
		}else{
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ADD_GROUP_TO_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Reverting group policy update failed").
					put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
					put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Group configuration failed. Contact Admin \"]}");
		}
	}

    /**
     * Remove Group Service Account
     * @param token
     * @param serviceAccountGroup
     * @param userDetails
     * @return
     */
    public ResponseEntity<String> removeGroupFromServiceAccount(String token, ServiceAccountGroup serviceAccountGroup, UserDetails userDetails) {
        log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                put(LogMessage.ACTION, "Remove Group from Service Account").
                put(LogMessage.MESSAGE, "Trying to remove Group from Service Account").
                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                build()));
        if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
        if(!isSvcaccPermissionInputValid(serviceAccountGroup.getAccess())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERROR_INVALID_VALUE_MSG);
        }
		if (serviceAccountGroup.getAccess().equalsIgnoreCase(RESET_STRING)) {
			serviceAccountGroup.setAccess(TVaultConstants.WRITE_POLICY);
		}
        String groupName = serviceAccountGroup.getGroupname().toLowerCase();
        String svcAccName = serviceAccountGroup.getSvcAccName();
        
        boolean isAuthorized = true;
        
        isAuthorized = hasAddOrRemovePermission(userDetails, svcAccName, token);        

        if(isAuthorized){
			if (!ifInitialPwdReset(token, userDetails, serviceAccountGroup.getSvcAccName())) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "Remove Group from ServiceAccount").
						put(LogMessage.MESSAGE, "Failed to remove group permission from Service account. Initial password reset is pending for this Service Account.").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to remove group permission from Service account. Initial password reset is pending for this Service Account. Please reset the password and try again.\"]}");
			}
            String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
            String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
            String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
            String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

            log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                    put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                    put(LogMessage.ACTION, "Remove group from Service Account").
                    put(LogMessage.MESSAGE, String.format (POLICIES_MSG_STRING, readPolicy, writePolicy, denyPolicy, sudoPolicy)).
                    put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                    build()));
            Response groupResp = reqProcessor.process(AUTH_LDAP_GROUPS,GROUP_NAME_STRING+groupName+"\"}",token);

            log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                    put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                    put(LogMessage.ACTION, "Remove group from ServiceAccount").
                    put(LogMessage.MESSAGE, String.format (USER_RESPONSE_MSG_STRING, groupResp.getHttpstatus())).
                    put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                    build()));

            String responseJson="";
            List<String> policies = new ArrayList<>();
            List<String> currentpolicies = new ArrayList<>();
            
            if(HttpStatus.OK.equals(groupResp.getHttpstatus())){
                responseJson = groupResp.getResponse();
                try {
                    ObjectMapper objMapper = new ObjectMapper();
                    currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
                } catch (IOException e) {
                    log.error(e);
                    log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                            put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                            put(LogMessage.ACTION, "Remove group from ServiceAccount").
                            put(LogMessage.MESSAGE, ERROR_POLICY_GROUP_MSG).
                            put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace())).
                            put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                            build()));
                }

                policies.addAll(currentpolicies);                
				policies.remove(readPolicy);
				policies.remove(writePolicy);
				policies.remove(denyPolicy);
            }
            String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
			String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");
            Response ldapConfigresponse = ControllerUtil.configureLDAPGroup(groupName,policiesString,token);

            return updateMetaDataAfterRemoveGroup(token, groupName, svcAccName, currentpoliciesString,
					ldapConfigresponse);
        }
        else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to remove groups from this service account\"]}");
        }

    }

	private ResponseEntity<String> updateMetaDataAfterRemoveGroup(String token, String groupName, String svcAccName,
			String currentpoliciesString, Response ldapConfigresponse) {
		if(ldapConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || ldapConfigresponse.getHttpstatus().equals(HttpStatus.OK)){
			String path = new StringBuffer(TVaultConstants.SVC_ACC_ROLES_PATH).append(svcAccName).toString();
			Map<String,String> params = new HashMap<>();
			params.put("type", "groups");
			params.put("name",groupName);
			params.put("path",path);
			params.put(ACCESS_STRING,DELETE_STRING);
			Response metadataResponse = ControllerUtil.updateMetadata(params,token);
			if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "Remove Group to Service Account").
						put(LogMessage.MESSAGE, "Group configuration Success.").
						put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Group is successfully removed from Service Account\"]}");
			}
			return configureLDAPGroupForServiceAccount(token, groupName, currentpoliciesString, metadataResponse);
		}
		else {
		    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to remove the group from the Service Account\"]}");
		}
	}

    /**
     * Associate Approle to Service Account
     * @param userDetails
     * @param token
     * @param serviceAccountApprole
     * @return
     */
    public ResponseEntity<String> associateApproletoSvcAcc(UserDetails userDetails, String token, ServiceAccountApprole serviceAccountApprole) {
        log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                put(LogMessage.ACTION, ADD_APPROLE_TO_SERVICE_ACCOUNT).
                put(LogMessage.MESSAGE, "Trying to add Approle to Service Account").
                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                build()));
        if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
        if(!isSvcaccPermissionInputValid(serviceAccountApprole.getAccess())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERROR_INVALID_VALUE_MSG);
        }
		if (serviceAccountApprole.getAccess().equalsIgnoreCase(RESET_STRING)) {
			serviceAccountApprole.setAccess(TVaultConstants.WRITE_POLICY);
		}
        String approleName = serviceAccountApprole.getApprolename();
        String svcAccName = serviceAccountApprole.getSvcAccName();
        String access = serviceAccountApprole.getAccess();

        if (serviceAccountApprole.getApprolename().equals(TVaultConstants.SELF_SERVICE_APPROLE_NAME)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: no permission to associate this AppRole to any Service Account\"]}");
        }
        approleName = (approleName !=null) ? approleName.toLowerCase() : approleName;
        access = (access != null) ? access.toLowerCase(): access;

        boolean isAuthorized = hasAddOrRemovePermission(userDetails, svcAccName, token);
        if(isAuthorized){
			return processAndAssociateApproletoSvcAcc(userDetails, token, serviceAccountApprole, approleName,
					svcAccName, access);
        }else{
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to add Approle to this service account\"]}");
        }
    }

	private ResponseEntity<String> processAndAssociateApproletoSvcAcc(UserDetails userDetails, String token,
			ServiceAccountApprole serviceAccountApprole, String approleName, String svcAccName, String access) {
		if (!ifInitialPwdReset(token, userDetails, serviceAccountApprole.getSvcAccName())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "Add approle to ServiceAccount").
					put(LogMessage.MESSAGE, "Failed to add approle permission to Service account. Initial password reset is pending for this Service Account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to add approle permission to Service account. Initial password reset is pending for this Service Account. Please reset the password and try again.\"]}");
		}
		String policy = "";
		policy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(access)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		        put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		        put(LogMessage.ACTION, ADD_APPROLE_TO_SERVICE_ACCOUNT).
		        put(LogMessage.MESSAGE, String.format (POLICY_MSG_STRING, policy)).
		        put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		        build()));
		String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		        put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		        put(LogMessage.ACTION, ADD_APPROLE_TO_SERVICE_ACCOUNT).
		        put(LogMessage.MESSAGE, String.format (POLICIES_MSG_STRING, readPolicy, writePolicy, denyPolicy, sudoPolicy)).
		        put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		        build()));

		Response roleResponse = reqProcessor.process(READ_APPROLE_ROLE,ROLE_NAME_FORMAT_STRING+approleName+"\"}",token);

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		        put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		        put(LogMessage.ACTION, ADD_APPROLE_TO_SERVICE_ACCOUNT).
		        put(LogMessage.MESSAGE, String.format ("roleResponse status is [%s]", roleResponse.getHttpstatus())).
		        put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		        build()));

		String responseJson="";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();

		if(HttpStatus.OK.equals(roleResponse.getHttpstatus())) {
			responseJson = roleResponse.getResponse();
			ObjectMapper objMapper = new ObjectMapper();
			try {
				JsonNode policiesArry = objMapper.readTree(responseJson).get("data").get(POLICIES_STRING);
				if (null != policiesArry) {
					for (JsonNode policyNode : policiesArry) {
						currentpolicies.add(policyNode.asText());
					}
				}
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, ADD_APPROLE_TO_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, "Exception while creating currentpolicies").
						put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
			}
			policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
			policies.add(policy);
		} else {
		    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("{\"errors\":[\"Non existing role name. Please configure approle as first step\"]}");
		}
		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, ADD_APPROLE_TO_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format ("policies [%s] before calling configureApprole", policies)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

		Response approleControllerResp = appRoleService.configureApprole(approleName,policiesString,token);

		return updateMetaDataAndConfigureApproleToSvcAcc(token, approleName, svcAccName, access,
				currentpoliciesString, approleControllerResp);
	}

	private ResponseEntity<String> updateMetaDataAndConfigureApproleToSvcAcc(String token, String approleName,
			String svcAccName, String access, String currentpoliciesString, Response approleControllerResp) {
		if(approleControllerResp.getHttpstatus().equals(HttpStatus.NO_CONTENT) || approleControllerResp.getHttpstatus().equals(HttpStatus.OK)){
			String path = new StringBuffer(TVaultConstants.SVC_ACC_ROLES_PATH).append(svcAccName).toString();
			Map<String,String> params = new HashMap<>();
			params.put("type", "app-roles");
			params.put("name",approleName);
			params.put("path",path);
			params.put(ACCESS_STRING,access);
			Response metadataResponse = ControllerUtil.updateMetadata(params,token);
			if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, ADD_APPROLE_TO_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, "Approle successfully associated with Service Account").
						put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle successfully associated with Service Account\"]}");
			}
			return configureApproleForSvcAcc(token, approleName, currentpoliciesString, metadataResponse);
		}
		else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to add Approle to the Service Account\"]}");
		}
	}

	private ResponseEntity<String> configureApproleForSvcAcc(String token, String approleName,
			String currentpoliciesString, Response metadataResponse) {
		Response approleControllerResp;
		approleControllerResp = appRoleService.configureApprole(approleName,currentpoliciesString,token);
		if(approleControllerResp.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ADD_APPROLE_TO_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Reverting, Approle policy update success").
					put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
					put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Approle configuration failed. Please try again\"]}");
		}else{
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ADD_APPROLE_TO_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Reverting Approle policy update failed").
					put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
					put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Approle configuration failed. Contact Admin \"]}");
		}
	}

	public ResponseEntity<String> getServiceAccountMeta(String token, UserDetails userDetails, String path) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "Get metadata for Service Account").
				put(LogMessage.MESSAGE, "Trying to get metadata for Service Account").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		Response response = getMetadata(token, userDetails, path);
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
	}

	/**
	 * Get metadata for service account
	 * @param token
	 * @param userDetails
	 * @param path
	 * @return
	 */
	private Response getMetadata(String token, UserDetails userDetails, String path) {
		if (!userDetails.isAdmin()) {
			token = tokenUtils.getSelfServiceToken();
		}
		if (path != null && path.startsWith("/")) {
			path = path.substring(1, path.length());
		}
		if (path != null && path.endsWith("/")) {
			path = path.substring(0, path.length()-1);
		}
		String metaDataPath = "metadata/"+path;
		return reqProcessor.process("/sdb","{\"path\":\""+metaDataPath+"\"}",token);
	}

	/**
	 * Update User policy on Service account offboarding
	 * @param svcAccName
	 * @param acessInfo
	 * @param token
	 */
	private void updateUserPolicyAssociationOnSvcaccDelete(String svcAccName,Map<String,String> acessInfo,String token){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, UPDATE_USER_POLICY_SVCACC).
				put(LogMessage.MESSAGE, "trying updateUserPolicyAssociationOnSvcaccDelete").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		log.debug ("updateUserPolicyAssociationOnSvcaccDelete...for auth method " + vaultAuthMethod);
		if(acessInfo!=null){
			processAndUpdateUserPolicyOnSvcaccDelete(svcAccName, acessInfo, token);
		}
	}

	private void processAndUpdateUserPolicyOnSvcaccDelete(String svcAccName, Map<String, String> acessInfo,
			String token) {
		String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		Set<String> users = acessInfo.keySet();
		ObjectMapper objMapper = new ObjectMapper();
		for(String userName : users){

			Response userResponse;
			if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
				userResponse = reqProcessor.process(AUTH_USERPASS_READ,USERNAME_FORMAT_STRING+userName+"\"}",token);
			}
			else {
				userResponse = reqProcessor.process(AUTH_LDAP_USERS,USERNAME_FORMAT_STRING+userName+"\"}",token);
			}
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
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, UPDATE_USER_POLICY_SVCACC).
							put(LogMessage.MESSAGE, String.format ("updateUserPolicyAssociationOnSvcaccDelete failed [%s]", e.getMessage())).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}
				policies.addAll(currentpolicies);
				policies.remove(readPolicy);
				policies.remove(writePolicy);
				policies.remove(denyPolicy);
				policies.remove(sudoPolicy);

				configureUserpassOrLDAPUser(token, userName, groups, policies);
			}
		}
	}

	private void configureUserpassOrLDAPUser(String token, String userName, String groups, List<String> policies) {
		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, UPDATE_USER_POLICY_SVCACC).
				put(LogMessage.MESSAGE, String.format (CURRENT_POLICIES_MSG, policies )).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, UPDATE_USER_POLICY_SVCACC).
					put(LogMessage.MESSAGE, String.format ("Current policies userpass [%s]", policies )).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			ControllerUtil.configureUserpassUser(userName,policiesString,token);
		}
		else {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, UPDATE_USER_POLICY_SVCACC).
					put(LogMessage.MESSAGE, String.format ("Current policies ldap [%s]", policies )).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			ControllerUtil.configureLDAPUser(userName,policiesString,groups,token);
		}
	}

	/**
	 * Update Group policy on Service account offboarding
	 * @param svcAccName
	 * @param acessInfo
	 * @param token
	 */
	private void updateGroupPolicyAssociationOnSvcaccDelete(String svcAccName,Map<String,String> acessInfo,String token){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, UPDATE_GROUP_POLICY_SVCACC).
				put(LogMessage.MESSAGE, "trying updateGroupPolicyAssociationOnSvcaccDelete").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			log.debug ("Inside userpass of updateGroupPolicyAssociationOnSvcaccDelete...Just Returning...");
			return;
		}
		if(acessInfo!=null){
			String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
			String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
			String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

			Set<String> groups = acessInfo.keySet();
			ObjectMapper objMapper = new ObjectMapper();
			for(String groupName : groups){
				Response response = reqProcessor.process(AUTH_LDAP_GROUPS,GROUP_NAME_STRING+groupName+"\"}",token);
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
								put(LogMessage.ACTION, UPDATE_GROUP_POLICY_SVCACC).
								put(LogMessage.MESSAGE, String.format ("updateGroupPolicyAssociationOnSvcaccDelete failed [%s]", e.getMessage())).
								put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								build()));
					}
					policies.addAll(currentpolicies);
					policies.remove(readPolicy);
					policies.remove(writePolicy);
					policies.remove(denyPolicy);
					String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, UPDATE_GROUP_POLICY_SVCACC).
							put(LogMessage.MESSAGE, String.format (CURRENT_POLICIES_MSG, policies )).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					ControllerUtil.configureLDAPGroup(groupName,policiesString,token);
				}
			}
		}
	}

    /**
     * Aws role deletion as part of Offboarding
     * @param acessInfo
     * @param token
     */
    private void deleteAwsRoleonOnSvcaccDelete(Map<String,String> acessInfo, String token) {
        log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                put(LogMessage.ACTION, DELETE_AWS_ROLE_SVCACC).
                put(LogMessage.MESSAGE, "Trying to delete AwsRole On Service Account offboarding").
                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                build()));
        if(acessInfo!=null){
            Set<String> roles = acessInfo.keySet();
            for(String role : roles){
                Response response = reqProcessor.process("/auth/aws/roles/delete",ROLE_STRING+role+"\"}",token);
                if(response.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
                    log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                            put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                            put(LogMessage.ACTION, DELETE_AWS_ROLE_SVCACC).
                            put(LogMessage.MESSAGE, String.format ("%s, AWS Role is deleted as part of offboarding Service account.", role)).
                            put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                            build()));
                }else{
                    log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                            put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                            put(LogMessage.ACTION, DELETE_AWS_ROLE_SVCACC).
                            put(LogMessage.MESSAGE, String.format ("%s, AWS Role deletion as part of offboarding Service account failed.", role)).
                            put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                            build()));
                }
            }
        }
    }

    /**
     * Approle policy update as part of offboarding
     * @param svcAccName
     * @param acessInfo
     * @param token
     */
    private void updateApprolePolicyAssociationOnSvcaccDelete(String svcAccName, Map<String,String> acessInfo, String token) {
        log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                put(LogMessage.ACTION, UPDATE_APPROLE_POLICY_SVCACC).
                put(LogMessage.MESSAGE, "trying updateApprolePolicyAssociationOnSvcaccDelete").
                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                build()));
        if(acessInfo!=null) {
            processAndUpdateApprolePolicyOnSvcaccDelete(svcAccName, acessInfo, token);
        }
    }

	private void processAndUpdateApprolePolicyOnSvcaccDelete(String svcAccName, Map<String, String> acessInfo,
			String token) {
		String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		Set<String> approles = acessInfo.keySet();
		ObjectMapper objMapper = new ObjectMapper();
		for(String approleName : approles) {
		    Response roleResponse = reqProcessor.process(READ_APPROLE_ROLE, ROLE_NAME_FORMAT_STRING + approleName + "\"}", token);
		    String responseJson = "";
		    List<String> policies = new ArrayList<>();
		    List<String> currentpolicies = new ArrayList<>();
		    if (HttpStatus.OK.equals(roleResponse.getHttpstatus())) {
		        responseJson = roleResponse.getResponse();
		        try {
		            JsonNode policiesArry = objMapper.readTree(responseJson).get("data").get(POLICIES_STRING);
					if (null != policiesArry) {
						for (JsonNode policyNode : policiesArry) {
							currentpolicies.add(policyNode.asText());
						}
					}
		        } catch (IOException e) {
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, UPDATE_APPROLE_POLICY_SVCACC).
							put(LogMessage.MESSAGE, String.format ("%s, Approle removal as part of offboarding Service account failed.", approleName)).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
		        }
		        policies.addAll(currentpolicies);
		        policies.remove(readPolicy);
		        policies.remove(writePolicy);
		        policies.remove(denyPolicy);

		        String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		        log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		                put(LogMessage.ACTION, UPDATE_APPROLE_POLICY_SVCACC).
		                put(LogMessage.MESSAGE, "Current policies :" + policiesString + POLICIES_CONFIGURED_MSG).
		                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		                build()));
		        appRoleService.configureApprole(approleName, policiesString, token);
		    }
		}
	}

    /**
     * Get Manager details for service account
     * @param filter
     * @return
     */
    private List<ADUserAccount> getServiceAccountManagerDetails(String filter) {
        log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                put(LogMessage.ACTION, "getServiceAccountManagerDetails").
                put(LogMessage.MESSAGE, "Trying to get manager details").
                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                build()));
        return adUserLdapTemplate.search("", filter, new AttributesMapper<ADUserAccount>() {
            @Override
            public ADUserAccount mapFromAttributes(Attributes attr) throws NamingException {
				ADUserAccount person = new ADUserAccount();
				if (attr != null) {
					String userId = ((String) attr.get("name").get());
					person.setUserId(userId);
					if (attr.get(DISPLAY_NAME_STRING) != null) {
						person.setDisplayName(((String) attr.get(DISPLAY_NAME_STRING).get()));
					}
					if (attr.get(GIVEN_NAME_STRING) != null) {
						person.setGivenName(((String) attr.get(GIVEN_NAME_STRING).get()));
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
	 * Remove approle from service account
	 * @param userDetails
	 * @param token
	 * @param serviceAccountApprole
	 * @return
	 */
	public ResponseEntity<String> removeApproleFromSvcAcc(UserDetails userDetails, String token, ServiceAccountApprole serviceAccountApprole) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, REMOVE_APPROLE_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format ("Trying to remove approle from Service Account [%s]", serviceAccountApprole.getApprolename())).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
		if (serviceAccountApprole.getAccess().equalsIgnoreCase(RESET_STRING)) {
			serviceAccountApprole.setAccess(TVaultConstants.WRITE_POLICY);
		}
		String approleName = serviceAccountApprole.getApprolename();
		String svcAccName = serviceAccountApprole.getSvcAccName();
		String access = serviceAccountApprole.getAccess();

		if (serviceAccountApprole.getApprolename().equals(TVaultConstants.SELF_SERVICE_APPROLE_NAME)) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: no permission to remove this AppRole to any Service Account\"]}");
		}
		approleName = (approleName !=null) ? approleName.toLowerCase() : approleName;
		access = (access != null) ? access.toLowerCase(): access;
		if(StringUtils.isEmpty(access)){
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("{\"errors\":[\"Incorrect access. Valid values are read, reset, deny \"]}");
		}
		boolean isAuthorized = hasAddOrRemovePermission(userDetails, svcAccName, token);

		if (isAuthorized) {
			return processAndRemoveApproleFromSvcAcc(userDetails, token, serviceAccountApprole, approleName,
					svcAccName);
		} else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to remove approle from Service Account\"]}");
		}
	}

	private ResponseEntity<String> processAndRemoveApproleFromSvcAcc(UserDetails userDetails, String token,
			ServiceAccountApprole serviceAccountApprole, String approleName, String svcAccName) {
		if (!ifInitialPwdReset(token, userDetails, serviceAccountApprole.getSvcAccName())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "Remove Approle from ServiceAccount").
					put(LogMessage.MESSAGE, "Failed to remove approle permission from Service account. Initial password reset is pending for this Service Account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to remove approle permission from Service account. Initial password reset is pending for this Service Account. Please reset the password and try again.\"]}");
		}
		String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, REMOVE_APPROLE_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format (POLICIES_MSG_STRING, readPolicy, writePolicy, denyPolicy, sudoPolicy)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		
		Response roleResponse = reqProcessor.process(READ_APPROLE_ROLE,ROLE_NAME_FORMAT_STRING+approleName+"\"}",token);
		String responseJson="";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();
		if(HttpStatus.OK.equals(roleResponse.getHttpstatus())){
			responseJson = roleResponse.getResponse();
			ObjectMapper objMapper = new ObjectMapper();
			try {
				JsonNode policiesArry = objMapper.readTree(responseJson).get("data").get(POLICIES_STRING);
				if (null != policiesArry) {
					for (JsonNode policyNode : policiesArry) {
						currentpolicies.add(policyNode.asText());
					}
				}
			} catch (IOException e) {
				log.error(e);
			}
			policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);

		}

		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");
		log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, REMOVE_APPROLE_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, "Remove approle from Service account -  policy :" + policiesString + POLICIES_CONFIGURED_MSG ).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		//Update the policy for approle
		return updateMetaDataAndConfigureApproleForSvccAcc(token, approleName, svcAccName, policiesString,
				currentpoliciesString);
	}

	private ResponseEntity<String> updateMetaDataAndConfigureApproleForSvccAcc(String token, String approleName,
			String svcAccName, String policiesString, String currentpoliciesString) {
		Response approleControllerResp = appRoleService.configureApprole(approleName,policiesString,token);
		if(approleControllerResp.getHttpstatus().equals(HttpStatus.NO_CONTENT) || approleControllerResp.getHttpstatus().equals(HttpStatus.OK)){
			String path = new StringBuffer(TVaultConstants.SVC_ACC_ROLES_PATH).append(svcAccName).toString();
			Map<String,String> params = new HashMap<>();
			params.put("type", "app-roles");
			params.put("name",approleName);
			params.put("path",path);
			params.put(ACCESS_STRING,DELETE_STRING);
			Response metadataResponse = ControllerUtil.updateMetadata(params,token);
			if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, REMOVE_APPROLE_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, "Approle is successfully removed from Service Account").
						put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle is successfully removed from Service Account\"]}");
			}
			return configureApproleAfterRemoveFromSvcAcc(token, approleName, currentpoliciesString, metadataResponse);
		}
		else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to remove approle from the Service Account\"]}");
		}
	}

	private ResponseEntity<String> configureApproleAfterRemoveFromSvcAcc(String token, String approleName,
			String currentpoliciesString, Response metadataResponse) {
		Response approleControllerResp;
		approleControllerResp = appRoleService.configureApprole(approleName,currentpoliciesString,token);
		if(approleControllerResp.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, REMOVE_APPROLE_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Reverting, approle policy update success").
					put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
					put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Approle configuration failed. Please try again\"]}");
		}else{
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, REMOVE_APPROLE_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Reverting approle policy update failed").
					put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
					put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Approle configuration failed. Contact Admin \"]}");
		}
	}

	/**
	 * Add AWS role to Service Account
	 * @param userDetails
	 * @param token
	 * @param serviceAccountAWSRole
	 * @return
	 */
	public ResponseEntity<String> addAwsRoleToSvcacc(UserDetails userDetails, String token, ServiceAccountAWSRole serviceAccountAWSRole) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, ADD_AWS_ROLE_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, "Trying to add AWS Role to Service Account").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
        if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
		if(!isSvcaccPermissionInputValid(serviceAccountAWSRole.getAccess())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERROR_INVALID_VALUE_MSG);
		}
		if (serviceAccountAWSRole.getAccess().equalsIgnoreCase(RESET_STRING)) {
			serviceAccountAWSRole.setAccess(TVaultConstants.WRITE_POLICY);
		}
		String roleName = serviceAccountAWSRole.getRolename();
		String svcAccName = serviceAccountAWSRole.getSvcAccName();
		String access = serviceAccountAWSRole.getAccess();

		roleName = (roleName !=null) ? roleName.toLowerCase() : roleName;
		access = (access != null) ? access.toLowerCase(): access;

		boolean isAuthorized = hasAddOrRemovePermission(userDetails, svcAccName, token);
		if(isAuthorized){
			return processAndAddAwsRoleToSvcacc(userDetails, token, serviceAccountAWSRole, roleName, svcAccName,
					access);
		} else{
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to add AWS Role to this service account\"]}");
		}

	}

	private ResponseEntity<String> processAndAddAwsRoleToSvcacc(UserDetails userDetails, String token,
			ServiceAccountAWSRole serviceAccountAWSRole, String roleName, String svcAccName, String access) {
		if (!ifInitialPwdReset(token, userDetails, serviceAccountAWSRole.getSvcAccName())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ADD_AWS_ROLE_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Failed to add awsrole permission to Service account. Initial password reset is pending for this Service Account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to add awsrole permission to Service account. Initial password reset is pending for this Service Account. Please reset the password and try again.\"]}");
		}
		String policy = "";
		policy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(access)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, ADD_AWS_ROLE_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format (POLICY_MSG_STRING, policy)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, ADD_AWS_ROLE_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format (POLICIES_MSG_STRING, readPolicy, writePolicy, denyPolicy, sudoPolicy)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

		Response roleResponse = reqProcessor.process("/auth/aws/roles",ROLE_STRING+roleName+"\"}",token);
		String responseJson="";
		String authType = TVaultConstants.EC2;
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();
		String policiesString = "";
		String currentpoliciesString = "";

		if(HttpStatus.OK.equals(roleResponse.getHttpstatus())){
			responseJson = roleResponse.getResponse();
			ObjectMapper objMapper = new ObjectMapper();
			try {
				JsonNode policiesArry =objMapper.readTree(responseJson).get(POLICIES_STRING);
				for(JsonNode policyNode : policiesArry){
					currentpolicies.add(policyNode.asText());
				}
				authType = objMapper.readTree(responseJson).get("auth_type").asText();
			} catch (IOException e) {
		        log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		                put(LogMessage.ACTION, ADD_AWS_ROLE_SERVICE_ACCOUNT).
		                put(LogMessage.MESSAGE, e.getMessage()).
		                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		                build()));
			}
			policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
			policies.add(policy);
			policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
			currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");
		} else{
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("{\"errors\":[\"AWS role '"+roleName+"' does not exist. Please create the role and try again!\"]}");
		}
		return updateMetaDataAndConfigureAWSIAMorAWSRole(token, roleName, svcAccName, access, authType,
				policiesString, currentpoliciesString);
	}

	private ResponseEntity<String> updateMetaDataAndConfigureAWSIAMorAWSRole(String token, String roleName,
			String svcAccName, String access, String authType, String policiesString, String currentpoliciesString) {
		Response awsRoleConfigresponse = null;
		if (TVaultConstants.IAM.equals(authType)) {
			awsRoleConfigresponse = awsiamAuthService.configureAWSIAMRole(roleName,policiesString,token);
		}
		else {
			awsRoleConfigresponse = awsAuthService.configureAWSRole(roleName,policiesString,token);
		}
		if(awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.OK)){
			String path = new StringBuffer(TVaultConstants.SVC_ACC_ROLES_PATH).append(svcAccName).toString();
			Map<String,String> params = new HashMap<>();
			params.put("type", "aws-roles");
			params.put("name",roleName);
			params.put("path",path);
			params.put(ACCESS_STRING,access);
			Response metadataResponse = ControllerUtil.updateMetadata(params,token);
			if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, ADD_AWS_ROLE_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, "AWS Role configuration Success.").
						put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role successfully associated with Service Account\"]}");
			}
			return configureAWSIAMorAWSRoleByAuthType(token, roleName, authType, currentpoliciesString,
					metadataResponse);
		} else{
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Role configuration failed. Try Again\"]}");
		}
	}

	private ResponseEntity<String> configureAWSIAMorAWSRoleByAuthType(String token, String roleName, String authType,
			String currentpoliciesString, Response metadataResponse) {
		Response awsRoleConfigresponse;
		if (TVaultConstants.IAM.equals(authType)) {
			awsRoleConfigresponse = awsiamAuthService.configureAWSIAMRole(roleName,currentpoliciesString,token);
		}
		else {
			awsRoleConfigresponse = awsAuthService.configureAWSRole(roleName,currentpoliciesString,token);
		}
		if(awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ADD_AWS_ROLE_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Reverting, AWS Role policy update success").
					put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
					put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AWS Role configuration failed. Please try again\"]}");
		} else{
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ADD_AWS_ROLE_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Reverting AWS Role policy update failed").
					put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
					put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AWS Role configuration failed. Contact Admin \"]}");
		}
	}

	/**
	 * Remove AWS Role from service account
	 * @param userDetails
	 * @param token
	 * @param serviceAccountAWSRole
	 * @return
	 */
	public ResponseEntity<String> removeAWSRoleFromSvcacc(UserDetails userDetails, String token, ServiceAccountAWSRole serviceAccountAWSRole) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, REMOVE_AWS_ROLE_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format ("Trying to remove AWS Role from Service Account [%s]", serviceAccountAWSRole.getRolename())).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
        if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
		if(!isSvcaccPermissionInputValid(serviceAccountAWSRole.getAccess())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERROR_INVALID_VALUE_MSG);
		}
		if (serviceAccountAWSRole.getAccess().equalsIgnoreCase(RESET_STRING)) {
			serviceAccountAWSRole.setAccess(TVaultConstants.WRITE_POLICY);
		}
		String roleName = serviceAccountAWSRole.getRolename();
		String svcAccName = serviceAccountAWSRole.getSvcAccName();		

		roleName = (roleName !=null) ? roleName.toLowerCase() : roleName;		
		boolean isAuthorized = hasAddOrRemovePermission(userDetails, svcAccName, token);

		if (isAuthorized) {
			return processAndRemoveAWSRoleFromSvcacc(userDetails, token, serviceAccountAWSRole, roleName, svcAccName);
		} else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to remove AWS Role from Service Account\"]}");
		}
	}

	private ResponseEntity<String> processAndRemoveAWSRoleFromSvcacc(UserDetails userDetails, String token,
			ServiceAccountAWSRole serviceAccountAWSRole, String roleName, String svcAccName) {
		if (!ifInitialPwdReset(token, userDetails, serviceAccountAWSRole.getSvcAccName())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "Remove AWSRole from ServiceAccount").
					put(LogMessage.MESSAGE, "Failed to remove awsrole permission from Service account. Initial password reset is pending for this Service Account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to remove awsrole permission from Service account. Initial password reset is pending for this Service Account. Please reset the password and try again.\"]}");
		}
		String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
		String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, REMOVE_AWS_ROLE_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format (POLICIES_MSG_STRING, readPolicy, writePolicy, denyPolicy, sudoPolicy)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

		Response roleResponse = reqProcessor.process("/auth/aws/roles",ROLE_STRING+roleName+"\"}",token);
		String responseJson="";
		String authType = TVaultConstants.EC2;
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();

		if(HttpStatus.OK.equals(roleResponse.getHttpstatus())){
			responseJson = roleResponse.getResponse();
			ObjectMapper objMapper = new ObjectMapper();
			try {
				JsonNode policiesArry =objMapper.readTree(responseJson).get(POLICIES_STRING);
				for(JsonNode policyNode : policiesArry){
					currentpolicies.add(policyNode.asText());
				}
				authType = objMapper.readTree(responseJson).get("auth_type").asText();
			} catch (IOException e) {
		        log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		                put(LogMessage.ACTION, REMOVE_AWS_ROLE_SERVICE_ACCOUNT).
		                put(LogMessage.MESSAGE, e.getMessage()).
		                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		                build()));
			}
			policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
		} else{
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("{\"errors\":[\"AppRole doesn't exist\"]}");
		}

		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");
		log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, REMOVE_AWS_ROLE_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, "Remove AWS Role from Service account -  policy :" + policiesString + POLICIES_CONFIGURED_MSG ).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		return updateMetaDataAndConfigureAWSRoleForSvcAcc(token, roleName, svcAccName, authType, policiesString,
				currentpoliciesString);
	}

	private ResponseEntity<String> updateMetaDataAndConfigureAWSRoleForSvcAcc(String token, String roleName,
			String svcAccName, String authType, String policiesString, String currentpoliciesString) {
		Response awsRoleConfigresponse = null;
		if (TVaultConstants.IAM.equals(authType)) {
			awsRoleConfigresponse = awsiamAuthService.configureAWSIAMRole(roleName,policiesString,token);
		}
		else {
			awsRoleConfigresponse = awsAuthService.configureAWSRole(roleName,policiesString,token);
		}
		if(awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.OK)){
			String path = new StringBuffer(TVaultConstants.SVC_ACC_ROLES_PATH).append(svcAccName).toString();
			Map<String,String> params = new HashMap<>();
			params.put("type", "aws-roles");
			params.put("name",roleName);
			params.put("path",path);
			params.put(ACCESS_STRING,DELETE_STRING);
			Response metadataResponse = ControllerUtil.updateMetadata(params,token);
			if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, REMOVE_AWS_ROLE_SERVICE_ACCOUNT).
						put(LogMessage.MESSAGE, "AWS Role configuration Success.").
						put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role is successfully removed from Service Account\"]}");
			}
			return configureAWSIAMorAWSRoleForSvcAcc(token, roleName, authType, currentpoliciesString,
					metadataResponse);
		}
		else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to remove AWS Role from the Service Account\"]}");
		}
	}

	private ResponseEntity<String> configureAWSIAMorAWSRoleForSvcAcc(String token, String roleName, String authType,
			String currentpoliciesString, Response metadataResponse) {
		Response awsRoleConfigresponse;
		if (TVaultConstants.IAM.equals(authType)) {
			awsRoleConfigresponse = awsiamAuthService.configureAWSIAMRole(roleName,currentpoliciesString,token);
		}
		else {
			awsRoleConfigresponse = awsAuthService.configureAWSRole(roleName,currentpoliciesString,token);
		}
		if(awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, REMOVE_AWS_ROLE_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Reverting, AWS Role policy update success").
					put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
					put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AWS Role configuration failed. Please try again\"]}");
		}else{
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, REMOVE_APPROLE_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Reverting approle policy update failed").
					put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
					put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AWS Role configuration failed. Contact Admin \"]}");
		}
	}

	/**
	 * To create aws ec2 role
	 * @param userDetails
	 * @param token
	 * @param awsLoginRole
	 * @return
	 * @throws TVaultValidationException
	 */
	public ResponseEntity<String> createAWSRole(UserDetails userDetails, String token, AWSLoginRole awsLoginRole) throws TVaultValidationException {
        if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
		return awsAuthService.createRole(token, awsLoginRole, userDetails);
	}

	/**
	 * Create aws iam role
	 * @param userDetails
	 * @param token
	 * @param awsiamRole
	 * @return
	 * @throws TVaultValidationException
	 */
	public ResponseEntity<String> createIAMRole(UserDetails userDetails, String token, AWSIAMRole awsiamRole) throws TVaultValidationException {
        if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
		return awsiamAuthService.createIAMRole(awsiamRole, token, userDetails);
	}

	/**
	 * Update TTL for onboarded service account
	 * @param token
	 * @param serviceAccount
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> updateOnboardedServiceAccount(String token, ServiceAccount serviceAccount, UserDetails userDetails) {

		List<String> onboardedList = getOnboardedServiceAccountList(token, userDetails);

		if (!onboardedList.contains(serviceAccount.getName())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, UPDATE_ONBOARDED_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Failed to update onboarded Service Account. Service account not onboarded").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to update onboarded Service Account. Please onboard this Service Account first and try again.\"]}");
		}

		log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, UPDATE_ONBOARDED_SERVICE_ACCOUNT).
				put(LogMessage.MESSAGE, String.format("Update onboarded Service Account [%s]", serviceAccount.getName())).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		// get the maxPwdAge for this service account
		List<ADServiceAccount> allServiceAccounts = getADServiceAccount(serviceAccount.getName());
		if (allServiceAccounts == null || allServiceAccounts.isEmpty()) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to update onboarded Service Account. Unable to read Service account details\"]}");
		}
		int maxPwdAge = allServiceAccounts.get(0).getMaxPwdAge();
        if (serviceAccount.isAutoRotate()) {
            if (null == serviceAccount.getMax_ttl()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid or no value has been provided for MAX_TTL\"]}");
            }
			if (null == serviceAccount.getTtl()) {
				serviceAccount.setTtl(maxPwdAge-0L);
			}
            if (serviceAccount.getTtl() > maxPwdAge) {
                log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                        put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                        put(LogMessage.ACTION, UPDATE_ONBOARDED_SERVICE_ACCOUNT).
                        put(LogMessage.MESSAGE, String.format (ERROR_PASSWRD_EXPIRY_MSG, serviceAccount.getTtl(), maxPwdAge)).
                        put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                        build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid value provided for Password Expiration Time. This can't be more than "+maxPwdAge+" for this Service Account\"]}");
            }
            if (serviceAccount.getTtl() > serviceAccount.getMax_ttl()) {
                log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                        put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                        put(LogMessage.ACTION, UPDATE_ONBOARDED_SERVICE_ACCOUNT).
                        put(LogMessage.MESSAGE, String.format (ERROR_PASSWRD_EXPIRY_MSG, serviceAccount.getTtl(), serviceAccount.getMax_ttl())).
                        put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                        build()));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Password Expiration Time must be less than Maximum expiration time (MAX_TTL) for this Service Account\"]}");
            }
        }
		if (!serviceAccount.isAutoRotate()) {
			serviceAccount.setTtl(TVaultConstants.MAX_TTL);
		}
		return createRoleAndUpdateMetadataOnSvcUpdate(token, serviceAccount);
	}

	private ResponseEntity<String> createRoleAndUpdateMetadataOnSvcUpdate(String token, ServiceAccount serviceAccount) {
		ResponseEntity<String> accountRoleDeletionResponse = createAccountRole(token, serviceAccount);
		if (accountRoleDeletionResponse!=null && HttpStatus.OK.equals(accountRoleDeletionResponse.getStatusCode())) {

			String path = new StringBuffer(TVaultConstants.SVC_ACC_ROLES_PATH).append(serviceAccount.getName()).toString();
			Response metadataResponse = ControllerUtil.updateMetadataOnSvcUpdate(path, serviceAccount,token);
			if(metadataResponse != null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "pdate onboarded Service Account").
						put(LogMessage.MESSAGE, "Successfully updated onboarded Service Account.").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully updated onboarded Service Account.\"]}");
			}
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully updated onboarded Service Account. However metadata update failed\"]}");

		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, UPDATE_ONBOARDED_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, "Failed to update onboarded Service Account.").
					put(LogMessage.STATUS, accountRoleDeletionResponse!=null?accountRoleDeletionResponse.getStatusCode().toString():HttpStatus.MULTI_STATUS.toString()).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"errors\":[\"Failed to update onboarded Service Account.\"]}");
		}
	}

	/**
	 * Get onboarded service account list
	 * @param token
	 * @param userDetails
	 * @return
	 */
	private List<String> getOnboardedServiceAccountList(String token, UserDetails userDetails) {
		ResponseEntity<String> onboardedResponse = getOnboardedServiceAccounts(token, userDetails);

		ObjectMapper objMapper = new ObjectMapper();
		List<String> onboardedList = new ArrayList<>();
		Map<String,String[]> requestMap = null;
		try {
			requestMap = objMapper.readValue(onboardedResponse.getBody(), new TypeReference<Map<String,String[]>>() {});
			if (requestMap != null && null != requestMap.get("keys")) {
				onboardedList = new ArrayList<>(Arrays.asList((String[]) requestMap.get("keys")));
			}
		} catch (IOException e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, UPDATE_ONBOARDED_SERVICE_ACCOUNT).
					put(LogMessage.MESSAGE, String.format ("Error creating onboarded list [%s]", e.getMessage())).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return onboardedList;
	}

	/**
	 * Change service account owner
	 * @param userDetails
	 * @param token
	 * @param svcAccName
	 * @return
	 */
	public ResponseEntity<String> transferSvcAccountOwner(UserDetails userDetails, String token, String svcAccName) {
		if (!userDetails.isAdmin()) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body("{\"errors\":[\"Access denied. No permission to transfer service account.\"]}");
		}
		boolean isSvcAccOwnerChanged = false;
		ServiceAccountMetadataDetails serviceAccountMetadataDetails = getServiceAccountMetadataDetails(token, userDetails, svcAccName);
		OnboardedServiceAccountDetails onbSvcAccDtls = getOnboarderdServiceAccountDetails(token, svcAccName);
		String oldOwner = serviceAccountMetadataDetails.getManagedBy();
		ADServiceAccount adServiceAccount = null;
		if (onbSvcAccDtls != null) {
			List<ADServiceAccount> allServiceAccounts = getADServiceAccount(svcAccName);
			if (!CollectionUtils.isEmpty(allServiceAccounts)) {
				adServiceAccount = allServiceAccounts.get(0);
				if (!oldOwner.equals(adServiceAccount.getOwner())) {
					isSvcAccOwnerChanged=true;
				}
			}
			else {
					return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"errors\":[\"Failed to transfer service account ownership. Unable to read Service account details\"]}");
			}
			if (isSvcAccOwnerChanged) {
				String svcOwner = adServiceAccount.getOwner();

				ServiceAccount serviceAccount = new ServiceAccount();
				serviceAccount.setName(svcAccName);
				serviceAccount.setTtl(onbSvcAccDtls.getTtl());
				serviceAccount.setMax_ttl(adServiceAccount.getMaxPwdAge()+0L);
				boolean autoRotate = false;
				if (onbSvcAccDtls.getTtl() <= adServiceAccount.getMaxPwdAge()) {
					autoRotate =  true;
				}
				serviceAccount.setAutoRotate(autoRotate);


				serviceAccount.setAdGroup(serviceAccountMetadataDetails.getAdGroup());
				serviceAccount.setAppName(serviceAccountMetadataDetails.getAppName());
				serviceAccount.setAppID(serviceAccountMetadataDetails.getAppID());
				serviceAccount.setAppTag(serviceAccountMetadataDetails.getAppTag());

				serviceAccount.setOwner(svcOwner);

				return updateOnboardedServiceAccountToTransferSvcAcc(userDetails, token, svcAccName,
						serviceAccountMetadataDetails, oldOwner, svcOwner, serviceAccount);
			}
			else {
				return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"messages\":[\"Ownership transfer not required for this service account.\"]}");
			}
		}
		else {
			return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"messages\":[\"Failed to get service account details. Service account is not onboarded.\"]}");
		}
	}

	private ResponseEntity<String> updateOnboardedServiceAccountToTransferSvcAcc(UserDetails userDetails, String token,
			String svcAccName, ServiceAccountMetadataDetails serviceAccountMetadataDetails, String oldOwner,
			String svcOwner, ServiceAccount serviceAccount) {
		ResponseEntity<String> svcAccOwnerUpdateResponse = updateOnboardedServiceAccount(token, serviceAccount, userDetails);
		if (HttpStatus.OK.equals(svcAccOwnerUpdateResponse.getStatusCode())) {
			// Add sudo permission to new owner
			ServiceAccountUser serviceAccountNewOwner = new ServiceAccountUser(svcAccName, svcOwner, TVaultConstants.SUDO_POLICY);
			ResponseEntity<String> addOwnerSudoToServiceAccountResponse = addUserToServiceAccount(token, serviceAccountNewOwner, userDetails, true);

			// Add default reset permission to new owner. If initial password reset is not done, then reset permission will be added during initial reset.
			if (serviceAccountMetadataDetails.getInitialPasswordReset()) {
				serviceAccountNewOwner = new ServiceAccountUser(svcAccName, svcOwner, TVaultConstants.RESET_POLICY);
				addUserToServiceAccount(token, serviceAccountNewOwner, userDetails, true);
			}

			removeOldUserPermissions(oldOwner, token, svcAccName);

			if (HttpStatus.OK.equals(addOwnerSudoToServiceAccountResponse.getStatusCode())) {
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Service account ownership transferred successfully from " + oldOwner + " to " + svcOwner + ".\"]}");
			}
			else {
				return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"messages\":[\"Failed to transfer service account ownership. Adding new user to service account failed\"]}");
			}
		}
		else {
			return ResponseEntity.status(HttpStatus.MULTI_STATUS).body("{\"messages\":[\"Failed to transfer service account ownership. Update service account failed\"]}");
		}
	}


	/**
	 * To remove old owner permissions and metadata
	 * @param userName
	 * @param token
	 * @param svcAccName
	 */
	private void removeOldUserPermissions(String userName, String token, String svcAccName) {

		// Remove metadata directly as removeUserFromServiceAccount() will need refreshed token
		String path = new StringBuffer(TVaultConstants.SVC_ACC_ROLES_PATH).append(svcAccName).toString();
		Map<String,String> params = new HashMap<>();
		params.put("type", "users");
		params.put("name", userName);
		params.put("path",path);
		params.put(ACCESS_STRING, DELETE_STRING);
		Response metadataResponse = ControllerUtil.updateMetadata(params,token);
		if(metadataResponse != null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "Remove old owner from ServiceAccount").
					put(LogMessage.MESSAGE, String.format("Owner %s is successfully removed from Service Account %s", userName, svcAccName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		else {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "Remove old owner from ServiceAccount").
					put(LogMessage.MESSAGE,String.format("Failed to remove Owner %s from Service Account %s", userName, svcAccName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}

		// Remove old owner sudo and reset permissions
		ObjectMapper objMapper = new ObjectMapper();

		Response userResponse;
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			userResponse = reqProcessor.process(AUTH_USERPASS_READ, USERNAME_FORMAT_STRING + userName + "\"}", token);
		} else {
			userResponse = reqProcessor.process(AUTH_LDAP_USERS, USERNAME_FORMAT_STRING + userName + "\"}", token);
		}
		String responseJson = "";
		String groups = "";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();

		if (HttpStatus.OK.equals(userResponse.getHttpstatus())) {
			responseJson = userResponse.getResponse();
			try {
				currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
				if (!(TVaultConstants.USERPASS.equals(vaultAuthMethod))) {
					groups = objMapper.readTree(responseJson).get("data").get("groups").asText();
				}
			} catch (IOException e) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, UPDATE_USER_POLICY_SVCACC).
						put(LogMessage.MESSAGE, String.format("updateUserPolicyAssociationOnSvcaccDelete failed [%s]", e.getMessage())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
			}
			policies.addAll(currentpolicies);
			String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
			String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
			String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();
			String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(TVaultConstants.SVC_ACC_PATH_PREFIX).append("_").append(svcAccName).toString();

			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
			policies.remove(sudoPolicy);

			String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");

			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, REMOVE_OLD_USER_PERMISSIONS).
					put(LogMessage.MESSAGE, String.format(CURRENT_POLICIES_MSG, policies)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, REMOVE_OLD_USER_PERMISSIONS).
						put(LogMessage.MESSAGE, String.format("Current policies userpass [%s]", policies)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				ControllerUtil.configureUserpassUser(userName, policiesString, token);
			} else {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, REMOVE_OLD_USER_PERMISSIONS).
						put(LogMessage.MESSAGE, String.format("Current policies ldap [%s]", policies)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				ControllerUtil.configureLDAPUser(userName, policiesString, groups, token);
			}
		}
	}

	/**
	 * To get ServiceAccountMetadataDetails
	 *
	 * @param token
	 * @param userDetails
	 * @param svcAccName
	 * @return
	 */
	private ServiceAccountMetadataDetails getServiceAccountMetadataDetails(String token, UserDetails userDetails, String svcAccName) {
		String metaDataPath = TVaultConstants.SVC_ACC_ROLES_PATH + svcAccName;
		Response metaResponse = getMetadata(token, userDetails, metaDataPath);
		ServiceAccountMetadataDetails serviceAccountMetadataDetails = new ServiceAccountMetadataDetails();
		if (metaResponse !=null && metaResponse.getHttpstatus().equals(HttpStatus.OK)) {
			try {
				prepareServiceAccountMetadataDetails(metaResponse, serviceAccountMetadataDetails);
			} catch (IOException e) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "getServiceAccountMetadataDetails").
						put(LogMessage.MESSAGE, String.format ("Failed to parse service account metadata [%s]", svcAccName)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
			}
		}
		return serviceAccountMetadataDetails;
	}

	private void prepareServiceAccountMetadataDetails(Response metaResponse,
			ServiceAccountMetadataDetails serviceAccountMetadataDetails) throws IOException {
		JsonNode jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("adGroup");
		if (jsonNode != null) {
			serviceAccountMetadataDetails.setAdGroup(jsonNode.asText());
		}
		jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("appID");
		if (jsonNode != null) {
			serviceAccountMetadataDetails.setAppID(jsonNode.asText());
		}
		jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("appName");
		if (jsonNode != null) {
			serviceAccountMetadataDetails.setAppName(jsonNode.asText());
		}
		jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("appTag");
		if (jsonNode != null) {
			serviceAccountMetadataDetails.setAppTag(jsonNode.asText());
		}
		jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get(MANAGED_BY_STRING);
		if (jsonNode != null) {
			serviceAccountMetadataDetails.setManagedBy(jsonNode.asText());
		}
		jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get(INITIAL_PASSWRD_RESET);
		if (jsonNode != null) {
			serviceAccountMetadataDetails.setInitialPasswordReset(Boolean.parseBoolean(jsonNode.asText()));
		}
		jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("name");
		if (jsonNode != null) {
			serviceAccountMetadataDetails.setName(jsonNode.asText());
		}
	}
}
