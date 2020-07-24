package com.tata.policyservice.dao;


import com.tata.policyservice.entity.Policy;
import com.tata.policyservice.entity.UserAuth;

import io.jsonwebtoken.Claims;

public interface PolicyDAO {

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

	public String getClientSecretKey(String clientID);

	public UserAuth validateMobileNumberAndDOB_2(String mobileNumber, String dateOfBirth);
	
}