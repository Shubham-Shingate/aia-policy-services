package com.tata.policyservice.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.tata.policyservice.dao.PolicyDAO;
import com.tata.policyservice.entity.Policy;
import com.tata.policyservice.entity.UserAuth;

import io.jsonwebtoken.Claims;

@Service
public class PolicyServiceImpl implements PolicyService {

	@Value("${smsAPIkey}")
	private String smsAPIkey;
	
	@Autowired
	private PolicyDAO policyDAO;
	
	@Override
	@Transactional
	public boolean validateMobileAndPolicy(String mobileNumber, String policyNumber) {
		boolean  registeredUser = policyDAO.validateMobileAndPolicy(mobileNumber, policyNumber);
		return registeredUser;
	}
	
	@Override
	@Transactional
	public boolean saveOrUpdateJwtOTP(String mobileNumber, int jwtOTP) {
		boolean result = policyDAO.saveOrUpdateJwtOTP(mobileNumber, jwtOTP);
		return result;
	}
	
	@Override
	@Transactional
	public boolean validateMobileAndOTP(String mobileNumber, String otp) {
		boolean result = policyDAO.validateMobileAndOTP(mobileNumber, otp);
		return result;
	}
	
	@Override
	@Transactional
	public String getCustomerName(String mobileNumber) {
		String customerName	= policyDAO.getCustomerName(mobileNumber);	
		return customerName;
	}

	@Override
	@Transactional
	public Policy getPolicyInfo(String policyNumber, Claims authenticatedUserDetails) {
		Policy policyInfo = policyDAO.getPolicyInfo(policyNumber, authenticatedUserDetails);
		return policyInfo;
	}

	@Override
	@Transactional
	public String validateEmailAndDOB(String emailId, String dateOfBirth) {
		String emailAddress = policyDAO.validateEmailAndDOB(emailId, dateOfBirth);
		return emailAddress;
	}

	@Override
	@Transactional
	public String validateMobileNumberAndDOB(String mobileNo, String dateOfBirth) {
		String mobileNumber = policyDAO.validateMobileNumberAndDOB(mobileNo, dateOfBirth);
		return mobileNumber;
	}

	@Override
	@Transactional
	public boolean updateMobileNumber(String newMobileNo, String policyNumber, Claims authenticatedUserDetails) {
		boolean mobileNumberUpdated = policyDAO.updateMobileNumber(newMobileNo, policyNumber, authenticatedUserDetails);
		return mobileNumberUpdated;
	}

	@Override
	@Transactional
	public boolean updateEmailAddress(String newEmailId, String policyNumber, Claims authenticatedUserDetails) {
		boolean emailAddressUpdated = policyDAO.updateEmailAddress(newEmailId, policyNumber, authenticatedUserDetails);
		return emailAddressUpdated;
	}

	@Override
	@Transactional
	public boolean updatePANnumber(String newPANno, String policyNumber, Claims authenticatedUserDetails) {
		boolean panNumberUpdated = policyDAO.updatePANnumber(newPANno, policyNumber, authenticatedUserDetails);
		return panNumberUpdated;
	}

	@Override
	@Transactional
	public boolean mobileNoOptinStatus(String mobileNo) {
		boolean optinStatus = policyDAO.mobileNoOptinStatus(mobileNo);
		return optinStatus;
	}

	@Override
	@Transactional
	public boolean checkMobileNo(String mobileNo) {
		boolean mobileNumberRegistered = policyDAO.checkMobileNo(mobileNo);
		return mobileNumberRegistered;
	}

	@Override // This is just a utility method to send OTP by access TextLocal's API. No need of @Transactional.
	public String sendOTPsms(int OTP, String mobileNo, String messageToSend) throws MalformedURLException, IOException {

		// appending country code to the number
		String mobileNumber = "91" + mobileNo;

		// Construct data
		String apiKey = "apikey=" + smsAPIkey;
		String message = "&message=" + messageToSend + OTP;
		String sender = "&sender=" + "TXTLCL";
		String numbers = "&numbers=" + mobileNumber;
		String test = "&test=" + "true";

		// Send data
		HttpURLConnection conn = (HttpURLConnection) new URL("https://api.textlocal.in/send/?").openConnection();
		String data = apiKey + numbers + message + sender + test;
		conn.setDoOutput(true);
		conn.setRequestMethod("POST");
		conn.setRequestProperty("Content-Length", Integer.toString(data.length()));
		conn.getOutputStream().write(data.getBytes("UTF-8"));
		final BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		final StringBuffer stringBuffer = new StringBuffer();
		String line;
		while ((line = rd.readLine()) != null) {
			stringBuffer.append(line);
		}
		rd.close();
		return stringBuffer.toString();
	}

	/** Methods Needed for the new Flow of Obtaining JWT */
	
	@Override
	@Transactional
	public String getClientSecretKey(String clientID) {
		String clientSecretKey = policyDAO.getClientSecretKey(clientID);
		return clientSecretKey;
	}
	
	public String getSHA1EncryptedString(String string, byte[] salt) {
		String encryptedString = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(salt);
			byte[] bytes = md.digest(string.getBytes());
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			encryptedString = sb.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return encryptedString;
	}

	@Override
	@Transactional
	public UserAuth validateMobileNumberAndDOB_2(String mobileNumber, String dateOfBirth) {
		UserAuth userDetails = policyDAO.validateMobileNumberAndDOB_2(mobileNumber, dateOfBirth);
		return userDetails;
	}
}