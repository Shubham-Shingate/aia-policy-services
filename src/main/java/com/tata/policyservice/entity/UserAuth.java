package com.tata.policyservice.entity;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity(name = "T_USERAUTH")
public class UserAuth {

	@Id
	@Column(name = "CUSTOMERID")
	private String customerID;

	@Column(name = "MOBILENUMBER")
	private String mobileNumber;

	@Column(name = "EMAILADDRESS")
	private String emailAddress;

	@Column(name = "POLICYNUMBER")
	private String policyNumber;

	@Temporal(TemporalType.DATE)
	@Column(name = "DATEOFBIRTH")
	private Date dob;

	public String getCustomerID() {
		return customerID;
	}

	public void setCustomerID(String customerID) {
		this.customerID = customerID;
	}

	public String getMobileNumber() {
		return mobileNumber;
	}

	public void setMobileNumber(String mobileNumber) {
		this.mobileNumber = mobileNumber;
	}

	public String getEmailAddress() {
		return emailAddress;
	}

	public void setEmailAddress(String emailAddress) {
		this.emailAddress = emailAddress;
	}

	public String getPolicyNumber() {
		return policyNumber;
	}

	public void setPolicyNumber(String policyNumber) {
		this.policyNumber = policyNumber;
	}

	public Date getDob() {
		return dob;
	}

	public void setDob(Date dob) {
		this.dob = dob;
	}

	public UserAuth(String customerID, String mobileNumber, String emailAddress, String policyNumber, Date dob) {
		this.customerID = customerID;
		this.mobileNumber = mobileNumber;
		this.emailAddress = emailAddress;
		this.policyNumber = policyNumber;
		this.dob = dob;
	}

	public UserAuth() {

	}

	@Override
	public String toString() {
		return "UserAuth [customerID=" + customerID + ", mobileNumber=" + mobileNumber + ", emailAddress="
				+ emailAddress + ", policyNumber=" + policyNumber + ", dob=" + dob + "]";
	}
}