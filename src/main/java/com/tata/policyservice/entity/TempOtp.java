package com.tata.policyservice.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;

@Entity(name = "TEMP_OTP")
public class TempOtp {

	@Id
	@Column(name = "MOBILE_NUMBER")
	private String mobileNumber;

	@Column(name = "OTP")
	private String otp;

	@Column(name = "STATUS")
	private String status;

	public String getMobileNumber() {
		return mobileNumber;
	}

	public void setMobileNumber(String mobileNumber) {
		this.mobileNumber = mobileNumber;
	}

	public String getOtp() {
		return otp;
	}

	public void setOtp(String otp) {
		this.otp = otp;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public TempOtp(String mobileNumber, String otp, String status) {
		this.mobileNumber = mobileNumber;
		this.otp = otp;
		this.status = status;
	}
	
	public TempOtp() {
		
	}

	@Override
	public String toString() {
		return "TempOtp [mobileNumber=" + mobileNumber + ", otp=" + otp + ", status=" + status + "]";
	}
}