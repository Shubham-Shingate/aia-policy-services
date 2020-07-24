package com.tata.policyservice.entity;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity(name="WHATSAPP_OPT_IN")
public class WhatsappOptIn {
	
	@Id
	@Column(name="OPT_IN_ID")
	private String optInId;
	
	@Column(name="MOBILE_NUMBER")
	private String mobileNumber;
	
	@Column(name="POLICY_NUMBER")
	private String policyNumber;
	
	@Temporal(TemporalType.DATE)
	@Column(name="OPT_IN_DATE")
	private Date optInDate;

	public String getOptInId() {
		return optInId;
	}

	public void setOptInId(String optInId) {
		this.optInId = optInId;
	}

	public String getMobileNumber() {
		return mobileNumber;
	}

	public void setMobileNumber(String mobileNumber) {
		this.mobileNumber = mobileNumber;
	}

	public String getPolicyNumber() {
		return policyNumber;
	}

	public void setPolicyNumber(String policyNumber) {
		this.policyNumber = policyNumber;
	}

	public Date getOptInDate() {
		return optInDate;
	}

	public void setOptInDate(Date optInDate) {
		this.optInDate = optInDate;
	}

	public WhatsappOptIn(String optInId, String mobileNumber, String policyNumber, Date optInDate) {
		this.optInId = optInId;
		this.mobileNumber = mobileNumber;
		this.policyNumber = policyNumber;
		this.optInDate = optInDate;
	}
	
	public WhatsappOptIn() {
		
	}

	@Override
	public String toString() {
		return "WhatsappOptIn [optInId=" + optInId + ", mobileNumber=" + mobileNumber + ", policyNumber=" + policyNumber
				+ ", optInDate=" + optInDate + "]";
	}	
}