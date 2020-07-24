package com.tata.policyservice.entity;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity(name="T_APPLICATIONCLIENTS")
public class ApplicationClient {
	
	@Id
	@Column(name = "CLIENTID")
	private String clientId;
	
	@Column(name = "CLIENTNAME")
	private String clientName;
	
	@Column(name = "CLIENTSECRET")
	private String clientSecret;
	
	@Temporal(TemporalType.DATE)
	@Column(name = "CREATEDDATE")
	private Date createdDate;
	
	@Column(name = "STATUS")
	private String status;

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientName() {
		return clientName;
	}

	public void setClientName(String clientName) {
		this.clientName = clientName;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public Date getCreatedDate() {
		return createdDate;
	}

	public void setCreatedDate(Date createdDate) {
		this.createdDate = createdDate;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public ApplicationClient(String clientId, String clientName, String clientSecret, Date createdDate, String status) {
		this.clientId = clientId;
		this.clientName = clientName;
		this.clientSecret = clientSecret;
		this.createdDate = createdDate;
		this.status = status;
	}
	
	public ApplicationClient() {

	}

	@Override
	public String toString() {
		return "ApplicationClient [clientId=" + clientId + ", clientName=" + clientName + ", clientSecret="
				+ clientSecret + ", createdDate=" + createdDate + ", status=" + status + "]";
	}
}
