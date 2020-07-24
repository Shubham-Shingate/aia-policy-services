package com.tata.policyservice.service;

import java.io.IOException;
import java.net.MalformedURLException;

import com.tata.policyservice.entity.Policy;
import com.tata.policyservice.entity.UserAuth;

import io.jsonwebtoken.Claims;

public interface PolicyService {
	
	public boolean validateMobileAndPolicy(String mobileNumber, String policyNumber);
	
	public boolean saveOrUpdateJwtOTP(String mobileNumber, int jwtOTP);
	
	public boolean validateMobileAndOTP(String mobileNumber, String otp);
	
	public String getCustomerName(String mobileNumber);
	
	public Policy getPolicyInfo(String policyNumber, Claims authenticatedUserDetails);
	
	public String validateEmailAndDOB(String emailId, String dateOfBirth);

	public String validateMobileNumberAndDOB(String mobileNo, String dateOfBirth);

	public boolean updateMobileNumber(String newMobileNo, String policyNumber, Claims authenticatedUserDetails);

	public boolean updateEmailAddress(String newEmailId, String policyNumber, Claims authenticatedUserDetails);

	public boolean updatePANnumber(String newPANno, String policyNumber, Claims authenticatedUserDetails);

	public boolean mobileNoOptinStatus(String mobileNo);

	public boolean checkMobileNo(String mobileNo);

	public String sendOTPsms(int OTP, String mobileNo, String messageToSend) throws MalformedURLException, IOException;

	public String getClientSecretKey(String clientID);

	public String getSHA1EncryptedString(String string, byte[] salt);

	public UserAuth validateMobileNumberAndDOB_2(String mobileNumber, String dateOfBirth);

}