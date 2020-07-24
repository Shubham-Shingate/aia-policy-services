package com.tata.policyservice.entity;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity(name = "POLICY_MASTER")
public class Policy {

	@Id
	@Column(name = "POLICY_NUMBER")
	private String policyNumber;

	@Column(name = "CUSTOMER_ID")
	private String customerID;

	@Column(name = "CUSTOMER_NAME")
	private String customerName;

	@Column(name = "INSURED_NAME")
	private String insuredName;
	
	@Temporal(TemporalType.DATE)
	@Column(name = "DOB")
	private Date dob;

	@Column(name = "EMAIL_ADDRESS")
	private String emailAddress;

	@Column(name = "MOBILE_NUMBER")
	private String mobileNumber;

	@Column(name = "PREMIUM_MODE")
	private String premiumMode;

	@Column(name = "POLICY_STATUS")
	private String policyStatus;

	@Column(name = "CUSTOMER_PAN_NO")
	private String customerPanNo;
	
	@Temporal(TemporalType.DATE)
	@Column(name = "POLICY_ISSUANCE_DATE")
	private Date policyIssuanceDate;

	@Temporal(TemporalType.TIMESTAMP)
	@Column(name = "CONTACT_NUMBER_LAST_UPDATED")
	private Date contactNumberLastUpdated;
	
	@Temporal(TemporalType.TIMESTAMP)
	@Column(name = "EMAIL_ADDRESS_LAST_UPDATED")
	private Date emailAddressLastUpdated;

	@Column(name = "BANK_ACCOUNT_NUMBER")
	private String bankAccountNumber;

	@Column(name = "WHATSAPP_OPT_IN_STATUS")
	private String whatsappOptInStatus;

	@Column(name = "PRODUCT_NAME")
	private String productName;

	@Column(name = "PRODUCT_ID")
	private String productId;

	@Column(name = "REINVEST_APPLICABLE")
	private String reinvestApplicable;

	@Column(name = "OUTSTANDING_PAYOUT")
	private String outstandingPayout;

	@Column(name = "UNCLAIMED_AMOUNT")
	private String unclaimedAmount;

	@Column(name = "NEFT_REGISTERED")
	private String neftRegistered;

	@Column(name = "LAST_PREMIUM_PAID")
	private String lastPremiumPaid;

	public String getPolicyNumber() {
		return policyNumber;
	}

	public void setPolicyNumber(String policyNumber) {
		this.policyNumber = policyNumber;
	}

	public String getCustomerID() {
		return customerID;
	}

	public void setCustomerID(String customerID) {
		this.customerID = customerID;
	}

	public String getCustomerName() {
		return customerName;
	}

	public void setCustomerName(String customerName) {
		this.customerName = customerName;
	}

	public String getInsuredName() {
		return insuredName;
	}

	public void setInsuredName(String insuredName) {
		this.insuredName = insuredName;
	}

	public Date getDob() {
		return dob;
	}

	public void setDob(Date dob) {
		this.dob = dob;
	}

	public String getEmailAddress() {
		return emailAddress;
	}

	public void setEmailAddress(String emailAddress) {
		this.emailAddress = emailAddress;
	}

	public String getMobileNumber() {
		return mobileNumber;
	}

	public void setMobileNumber(String mobileNumber) {
		this.mobileNumber = mobileNumber;
	}

	public String getPremiumMode() {
		return premiumMode;
	}

	public void setPremiumMode(String premiumMode) {
		this.premiumMode = premiumMode;
	}

	public String getPolicyStatus() {
		return policyStatus;
	}

	public void setPolicyStatus(String policyStatus) {
		this.policyStatus = policyStatus;
	}

	public String getCustomerPanNo() {
		return customerPanNo;
	}

	public void setCustomerPanNo(String customerPanNo) {
		this.customerPanNo = customerPanNo;
	}

	public Date getPolicyIssuanceDate() {
		return policyIssuanceDate;
	}

	public void setPolicyIssuanceDate(Date policyIssuanceDate) {
		this.policyIssuanceDate = policyIssuanceDate;
	}

	public Date getContactNumberLastUpdated() {
		return contactNumberLastUpdated;
	}

	public void setContactNumberLastUpdated(Date contactNumberLastUpdated) {
		this.contactNumberLastUpdated = contactNumberLastUpdated;
	}

	public Date getEmailAddressLastUpdated() {
		return emailAddressLastUpdated;
	}

	public void setEmailAddressLastUpdated(Date emailAddressLastUpdated) {
		this.emailAddressLastUpdated = emailAddressLastUpdated;
	}

	public String getBankAccountNumber() {
		return bankAccountNumber;
	}

	public void setBankAccountNumber(String bankAccountNumber) {
		this.bankAccountNumber = bankAccountNumber;
	}

	public String getWhatsappOptInStatus() {
		return whatsappOptInStatus;
	}

	public void setWhatsappOptInStatus(String whatsappOptInStatus) {
		this.whatsappOptInStatus = whatsappOptInStatus;
	}

	public String getProductName() {
		return productName;
	}

	public void setProductName(String productName) {
		this.productName = productName;
	}

	public String getProductId() {
		return productId;
	}

	public void setProductId(String productId) {
		this.productId = productId;
	}

	public String getReinvestApplicable() {
		return reinvestApplicable;
	}

	public void setReinvestApplicable(String reinvestApplicable) {
		this.reinvestApplicable = reinvestApplicable;
	}

	public String getOutstandingPayout() {
		return outstandingPayout;
	}

	public void setOutstandingPayout(String outstandingPayout) {
		this.outstandingPayout = outstandingPayout;
	}

	public String getUnclaimedAmount() {
		return unclaimedAmount;
	}

	public void setUnclaimedAmount(String unclaimedAmount) {
		this.unclaimedAmount = unclaimedAmount;
	}

	public String getNeftRegistered() {
		return neftRegistered;
	}

	public void setNeftRegistered(String neftRegistered) {
		this.neftRegistered = neftRegistered;
	}

	public String getLastPremiumPaid() {
		return lastPremiumPaid;
	}

	public void setLastPremiumPaid(String lastPremiumPaid) {
		this.lastPremiumPaid = lastPremiumPaid;
	}

	public Policy(String policyNumber, String customerID, String customerName, String insuredName, Date dob,
			String emailAddress, String mobileNumber, String premiumMode, String policyStatus, String customerPanNo,
			Date policyIssuanceDate, Date contactNumberLastUpdated, Date emailAddressLastUpdated,
			String bankAccountNumber, String whatsappOptInStatus, String productName, String productId,
			String reinvestApplicable, String outstandingPayout, String unclaimedAmount, String neftRegistered,
			String lastPremiumPaid) {

		this.policyNumber = policyNumber;
		this.customerID = customerID;
		this.customerName = customerName;
		this.insuredName = insuredName;
		this.dob = dob;
		this.emailAddress = emailAddress;
		this.mobileNumber = mobileNumber;
		this.premiumMode = premiumMode;
		this.policyStatus = policyStatus;
		this.customerPanNo = customerPanNo;
		this.policyIssuanceDate = policyIssuanceDate;
		this.contactNumberLastUpdated = contactNumberLastUpdated;
		this.emailAddressLastUpdated = emailAddressLastUpdated;
		this.bankAccountNumber = bankAccountNumber;
		this.whatsappOptInStatus = whatsappOptInStatus;
		this.productName = productName;
		this.productId = productId;
		this.reinvestApplicable = reinvestApplicable;
		this.outstandingPayout = outstandingPayout;
		this.unclaimedAmount = unclaimedAmount;
		this.neftRegistered = neftRegistered;
		this.lastPremiumPaid = lastPremiumPaid;
	}
	

	public Policy() {
		
	}

	@Override
	public String toString() {
		return "Policy [policyNumber=" + policyNumber + ", customerID=" + customerID + ", customerName=" + customerName
				+ ", insuredName=" + insuredName + ", dob=" + dob + ", emailAddress=" + emailAddress + ", mobileNumber="
				+ mobileNumber + ", premiumMode=" + premiumMode + ", policyStatus=" + policyStatus + ", customerPanNo="
				+ customerPanNo + ", policyIssuanceDate=" + policyIssuanceDate + ", contactNumberLastUpdated="
				+ contactNumberLastUpdated + ", emailAddressLastUpdated=" + emailAddressLastUpdated
				+ ", bankAccountNumber=" + bankAccountNumber + ", whatsappOptInStatus=" + whatsappOptInStatus
				+ ", productName=" + productName + ", productId=" + productId + ", reinvestApplicable="
				+ reinvestApplicable + ", outstandingPayout=" + outstandingPayout + ", unclaimedAmount="
				+ unclaimedAmount + ", neftRegistered=" + neftRegistered + ", lastPremiumPaid=" + lastPremiumPaid + "]";
	}
}
