package com.tmobile.cso.vault.api.model;

import java.io.Serializable;

import org.hibernate.validator.constraints.NotBlank;

import io.swagger.annotations.ApiModelProperty;

public class AzureServiceAccountUser implements Serializable {
	/**
	 * serialVersionUID
	 */
	private static final long serialVersionUID = -2100272556105686915L;

	@NotBlank
	private String azureSvcAccName;
	@NotBlank
	private String username;
	@NotBlank
	private String access;

	/**
	 * 
	 */
	public AzureServiceAccountUser() {
		super();
	}

	/**
	 * 
	 * @param azureSvcAccName
	 * @param username
	 * @param access
	 */
	public AzureServiceAccountUser(String azureSvcAccName, String username, String access) {
		super();
		this.azureSvcAccName = azureSvcAccName;
		this.username = username;
		this.access = access;
	}

	@ApiModelProperty(example = "svc_vault_test2", position = 1)
	public String getAzureSvcAccName() {
		return azureSvcAccName;
	}

	public void setAzureSvcAccName(String azureSvcAccName) {
		this.azureSvcAccName = azureSvcAccName;
	}

	@ApiModelProperty(example = "testuser1", position = 2)
	public String getUsername() {
		return username.toLowerCase();
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@ApiModelProperty(example = "read", position = 3, allowableValues = "read,reset,deny,owner")
	public String getAccess() {
		return access.toLowerCase();
	}

	public void setAccess(String access) {
		this.access = access;
	}

	@Override
	public String toString() {
		return "AzureServiceAccountUser [azureSvcAccName=" + azureSvcAccName + ", username=" + username + ", access="
				+ access + "]";
	}
}
