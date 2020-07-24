package com.tata.policyservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.tata.policyservice.constants.PolicyAppConstants;
import com.tata.policyservice.entity.Policy;
import com.tata.policyservice.entity.UserAuth;
import com.tata.policyservice.service.PolicyService;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.Key;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClaims;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@RestController
@RequestMapping("/policy-service")
public class PolicyController {

	@Value("${SECRET_KEY}")
	private String SECRET_KEY;
	
	@Value("${REFRESH_SECRET_KEY}")
	private String REFRESH_SECRET_KEY;
	
	@Value("${JWT_TOKEN_VALIDITY_MINS}")
	private String jwtTokenValidity;
	
	@Value("${REFRESH_TOKEN_VALIDITY_DAYS}")
	private String refreshTokenValidity;
	
	@Autowired
	private PolicyService policyService;
	
	/** ------------------------------------------OLD FLOW OF OBTAINING TOKEN STARTS------------------------------------------ */
	
	/* -----------------------------REQUEST OTP FOR JWT TOKEN----------------------------- */
	@PostMapping("/requestOTP")
	public Map<String, Object> requestOTP(@RequestParam String mobileNumber, @RequestParam String policyNumber){

		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();
		
		//Check whether mobile number and policy number are registered in POLICY_MASTER (i.e whether its a valid customer?)
		boolean  registeredUser = policyService.validateMobileAndPolicy(mobileNumber, policyNumber);
		
		if (registeredUser == true) { //means user it is a valid customer (policy holder), hence generate & send the OTP for JWT token API.
			/* Create the OTP for JWT */
			int jwtOTP = (new Random()).nextInt(9999);
			
			/* Store the OTP in TEMP_OTP */
			policyService.saveOrUpdateJwtOTP(mobileNumber, jwtOTP);
			
			/* Send the OTP for JWT to the user */
			try {
				policyService.sendOTPsms(jwtOTP, mobileNumber, "Your One time Password for obtaining the JWT token is- ");
			} catch (IOException e) {
				e.printStackTrace();
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
				jsonResponseMap.put(PolicyAppConstants.ERROR, "An Error occured while sending OTP");
				return jsonResponseMap;
			}
			
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.OTP_SENT);
			jsonResponseMap.put(PolicyAppConstants.MESSAGE, "JWT OTP sent on the mobile number");
			return jsonResponseMap;
		} else {
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.ERROR, "Invalid mobile or policy number");
			return jsonResponseMap;
		}
	}	
	
	/* -----------------------------OBTAIN JWT TOKEN----------------------------- */
	
	@PostMapping("/securityJwtToken")
	public Map<String, Object> createJWT(@RequestParam String id, @RequestParam String mobileNumber,
										@RequestParam String otp) { //email, dob
		
		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();
		
		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);
		
		//JWT Token Time Bound Definitions 
		Date expJWTToken =  new Date (nowMillis+(60000*Integer.parseInt(jwtTokenValidity))); 
		
		//Refresh Token Time Bound Definitions
		Date expRefreshToken = new Date(nowMillis+(86400000*Integer.parseInt(refreshTokenValidity))); //Date,time of expiry of refresh token.
						
		//Check mobile number, OTP and status = active in TEMP_OTP table and return true if all matched. Also update status of TEMP_OTP to inactive.
		boolean result = policyService.validateMobileAndOTP(mobileNumber, otp); //Major focus on validating OTP

		if (result == true) {
			//Obtain the user(customer) name from the DB by passing mobile number.
			String customerName= policyService.getCustomerName(mobileNumber);
			
			// The JWT signature algorithm we will be using to sign the token
			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
			
			
			/* =========JWT TOKEN GENERATION========= */
			// We will sign our JWT with our ApiKey secret
			byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
			Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

			// Lets set the JWT Token Claims, Signature and Expiry
			JwtBuilder builderForJWT = Jwts.builder().setId(id).setIssuedAt(now).setSubject(customerName).setIssuer(customerName)
					.signWith(signatureAlgorithm, signingKey).setExpiration(expJWTToken);
			
			
			/* =========REFRESH TOKEN GENERATION========= */
			// We will sign our refresh Token with our refreshKey secret
			byte[] refreshKeySecretBytes = DatatypeConverter.parseBase64Binary(REFRESH_SECRET_KEY);
			Key refreshSigningKey = new SecretKeySpec(refreshKeySecretBytes, signatureAlgorithm.getJcaName());
			
			//Lets set the Refresh Token Claims, Signature and Expiry
			JwtBuilder builderForRefreshToken = Jwts.builder().setId(id).setIssuedAt(now).setSubject(customerName).setIssuer(customerName)
					.signWith(signatureAlgorithm, refreshSigningKey).setExpiration(expRefreshToken);
			
			
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.SERVICE_REQ_SUCCESS);
			jsonResponseMap.put(PolicyAppConstants.TOKEN, builderForJWT.compact());
			jsonResponseMap.put(PolicyAppConstants.REFRESH, builderForRefreshToken.compact());
			return jsonResponseMap;
		} else {
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.ERROR, "Invalid Mobile Number or OTP");
			return jsonResponseMap;
		}
	}
	
	/** ------------------------------------------OLD FLOW OF OBTAINING TOKEN STARTS------------------------------------------ */
	
	
	
	/** ------------------------------------------NEW FLOW OF OBTAINING TOKEN STARTS------------------------------------------ */
	
	/* -----------------------------VALIDATE THE CLIENT HEADER CREDENTIALS----------------------------- */
	@PostMapping("/validateClient")
	public Map<String, Object> validateClient(@RequestHeader("ClientID") String clientID,
			@RequestHeader("UID") String uid, @RequestHeader("RequestTime") String requestTime) {

		System.out.println("I came in");

		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();

		// Get Client Secret from T_APPLICATIONCLIENTS
		String clientSecretKey = policyService.getClientSecretKey(clientID);

		if (clientSecretKey != null) {
			// Generate SHA1(clientID + requestTime) with clientSecrteKey as Salt
			String sha1EncryptedStr = policyService.getSHA1EncryptedString(clientID + requestTime,
					clientSecretKey.getBytes());

			if (sha1EncryptedStr.equals(uid)) {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.SERVICE_REQ_SUCCESS);
				jsonResponseMap.put(PolicyAppConstants.MESSAGE, "Success");
				return jsonResponseMap;
			} else {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
				jsonResponseMap.put(PolicyAppConstants.MESSAGE, "Invalid Client Credentials-uid did not match");
				return jsonResponseMap;
			}
		} else {
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.MESSAGE, "Secret Key for Client ID Not foud in DB");
			return jsonResponseMap;
		}

	}
	
	/* -----------------------------CREATE JWT AND REFRESH TOKENS----------------------------- */
	@PostMapping("/createTokens")
	public Map<String, Object> createTokens(@RequestParam String mobileNumber, @RequestParam String emailAddress, 
									@RequestParam String policyNumber, @RequestParam String dateOfBirth) {
		
		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();
		
		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);
		
		//JWT Token Time Bound Definitions 
		Date expJWTToken =  new Date (nowMillis+(60000*Integer.parseInt(jwtTokenValidity))); 
		
		//Refresh Token Time Bound Definitions
		Date expRefreshToken = new Date(nowMillis+(86400000*Integer.parseInt(refreshTokenValidity)));
		
		
		/*----If Mobile Number , DOB combination was passed---- */
		if (mobileNumber != null) {
			// Validate mobileNumber and Date of Birth in T_UserAuth
			UserAuth userDetails = policyService.validateMobileNumberAndDOB_2(mobileNumber, dateOfBirth);

			if (userDetails != null) { // means Mobile No. and DOB is Verified, Hence Create tokens and return them
				// The JWT signature algorithm we will be using to sign the token
				SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
				
				
				/* =========JWT TOKEN GENERATION========= */
				// We will sign our JWT with our ApiKey secret
				byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
				Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

				// Lets set the JWT Token Claims, Signature and Expiry
				JwtBuilder builderForJWT = Jwts.builder().setId("213232").setIssuedAt(now).setSubject(userDetails.getCustomerID()).setIssuer(userDetails.getCustomerID())
						.signWith(signatureAlgorithm, signingKey).setExpiration(expJWTToken);
				
				
				/* =========REFRESH TOKEN GENERATION========= */
				// We will sign our refresh Token with our refreshKey secret
				byte[] refreshKeySecretBytes = DatatypeConverter.parseBase64Binary(REFRESH_SECRET_KEY);
				Key refreshSigningKey = new SecretKeySpec(refreshKeySecretBytes, signatureAlgorithm.getJcaName());
				
				//Lets set the Refresh Token Claims, Signature and Expiry
				JwtBuilder builderForRefreshToken = Jwts.builder().setId("213232").setIssuedAt(now).setSubject(userDetails.getCustomerID()).setIssuer(userDetails.getCustomerID())
						.signWith(signatureAlgorithm, refreshSigningKey).setExpiration(expRefreshToken);
				
				
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.SERVICE_REQ_SUCCESS);
				jsonResponseMap.put(PolicyAppConstants.TOKEN, builderForJWT.compact());
				jsonResponseMap.put(PolicyAppConstants.REFRESH, builderForRefreshToken.compact());
				return jsonResponseMap;
				
			} else {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
				jsonResponseMap.put(PolicyAppConstants.ERROR, "Invalid Mobile No. OR Date of Birth");
				return jsonResponseMap;
			}
		}
		
		
		/*----If Email Address, DOB combination was passed---- */
		if (emailAddress != null) {
			// Validate emailAddress and Date of Birth in T_UserAuth

		}
		

		/*----If Policy Number, DOB combination was passed---- */
		if(policyNumber != null) {
		//Validate policyNumber and Date of Birth in T_UserAuth
		
		}
		return null;
	}
	
	/** ------------------------------------------NEW FLOW OF OBTAINING TOKEN STARTS------------------------------------------ */
	
	
	
	
	
	/* -----------------------------FETCH CUSTOMER POLICY INFO----------------------------- */
	
	@PostMapping("/customerPolicyInfo")
	public Map<String, Object> getCustomerPolicyInfo(HttpServletRequest req) {

		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();
		//Claims authenticatedUserDetails = (Claims) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		String policyNumber = req.getParameter("policyNumber");
		String claimsId = req.getParameter("claimsId");
		Date claimsIssuedAt = new Date(Long.valueOf(req.getParameter("claimsIssuedAt")));
		Date claimsExpiry = new Date(Long.valueOf(req.getParameter("claimsExpiry")));		
		String claimsSubject = req.getParameter("claimsSubject");
		String claimsIssuer = req.getParameter("claimsIssuer");

		Claims authenticatedUserDetails = new DefaultClaims().setId(claimsId).setIssuedAt(claimsIssuedAt)
												.setSubject(claimsSubject).setIssuer(claimsIssuer).setExpiration(claimsExpiry);

		if (authenticatedUserDetails != null) {
			// Here return Policy object if policy number is valid or return null from DAO
			Policy policyInfo = policyService.getPolicyInfo(policyNumber, authenticatedUserDetails);
			if (policyInfo != null) {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.GET_DATA_REQ_SUCCESS);
				jsonResponseMap.put(PolicyAppConstants.DATA, policyInfo);
				return jsonResponseMap;
			} else {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
				jsonResponseMap.put(PolicyAppConstants.ERROR,
						"Token is valid but Policy no. does not exist OR unauthorized to access info of this Policy no.");
				return jsonResponseMap;
			}
		} else {
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.ERROR, "Token valid but user not authenticated (Authentication Object for this request not found in Spring's SecurityContext)");
			return jsonResponseMap;
		}
	}

	/* -----------------------------CUSTOMER EMAIL VALIDATION----------------------------- */
	
	@PostMapping("/emailValidation")
	public Map<String, Object> validateEmail(@RequestParam String emailId, @RequestParam String dateOfBirth) {

		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();
			
		// This line returns EmailId if given emailId and DOB are valid in POLICY_MASTER table.
		String emailAddress = policyService.validateEmailAndDOB(emailId, dateOfBirth);
		if (emailAddress != null) {
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.VALIDATION_REQ_SUCCESS);
			jsonResponseMap.put(PolicyAppConstants.DATA, emailAddress);
			return jsonResponseMap;
		} else {
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.ERROR, "Token is valid but Email Id or Date of Birth Invalid");
			return jsonResponseMap;
		}
	}
	
	/* -----------------------------CUSTOMER MOBILE NUMBER VALIDATION----------------------------- */
	
	@PostMapping("/mobileNumberValidation")
	public Map<String, Object> validateMobileNumber(@RequestParam String mobileNo, @RequestParam String dateOfBirth) {

		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();

		// This line returns Mobile Number if given Mobile Number and DOB are valid in POLICY_MASTER table.
		String mobileNumber = policyService.validateMobileNumberAndDOB(mobileNo, dateOfBirth);
		if (mobileNumber != null) {
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.VALIDATION_REQ_SUCCESS);
			jsonResponseMap.put(PolicyAppConstants.DATA, mobileNumber);
			return jsonResponseMap;
		} else {
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.ERROR,
					"Token is valid but Mobile Number or Date of Birth Invalid");
			return jsonResponseMap;
		}
	}

	/* -----------------------------CUSTOMER MOBILE NUMBER UPDATION----------------------------- */
	
	@PostMapping("/mobileNumberUpdation")
	public Map<String, Object> updateMobileNumber(@RequestParam String newMobileNo, @RequestParam String policyNumber, 
									@RequestParam Claims authenticatedUserDetails) {

		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();
		//	Claims authenticatedUserDetails = (Claims) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		if (authenticatedUserDetails != null) {
			// This line updates the mobile number against a policy if policy number exists and
			// "token owner (authenticated user)" = "policy owner".
			boolean mobileNumberUpdated = policyService.updateMobileNumber(newMobileNo, policyNumber, authenticatedUserDetails);
			if (mobileNumberUpdated == true) {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.SERVICE_REQ_SUCCESS);
				jsonResponseMap.put(PolicyAppConstants.DATA, "SR10001");
				jsonResponseMap.put(PolicyAppConstants.MESSAGE, "Service Request for Mobile Number Updation Generated");
				return jsonResponseMap;
			} else {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
				jsonResponseMap.put(PolicyAppConstants.ERROR,
						"Token is valid but Policy no. does not exist OR unauthorized to update info of this Policy no.");
				return jsonResponseMap;
			}
		} else {
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.ERROR, "Token valid but user not authenticated (Authentication Object for this request not found in Spring's SecurityContext)");
			return jsonResponseMap;
		}
	}
	
	/* -----------------------------CUSTOMER EMAIL ADDRESS UPDATION----------------------------- */
	
	@PostMapping("/emailAddressUpdation")
	public Map<String, Object> updateEmailAddress(@RequestParam String newEmailId, @RequestParam String policyNumber, 
										@RequestParam Claims authenticatedUserDetails) {

		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();
		//	Claims authenticatedUserDetails = (Claims) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

		if (authenticatedUserDetails != null) {
			// Here update the email address against a policy if policy number exists and
			// "token owner (authenticated user)" = "policy owner".
			boolean emailAddressUpdated = policyService.updateEmailAddress(newEmailId, policyNumber, authenticatedUserDetails);
			if (emailAddressUpdated == true) {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.SERVICE_REQ_SUCCESS);
				jsonResponseMap.put(PolicyAppConstants.DATA, "SR10002");
				jsonResponseMap.put(PolicyAppConstants.MESSAGE, "Service Request for Email Address Updation Generated");
				return jsonResponseMap;
			} else {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
				jsonResponseMap.put(PolicyAppConstants.ERROR,
						"Token is valid but Policy no. does not exist OR unauthorized to update info of this Policy no.");
				return jsonResponseMap;
			}
		} else {
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.ERROR, "Token valid but user not authenticated (Authentication Object for this request not found in Spring's SecurityContext)");
			return jsonResponseMap;
		}
	}
	
	/* -----------------------------CUSTOMER PAN NO. UPDATION----------------------------- */
	
	@PostMapping("/PANcardUpdation")
	public Map<String, Object> updatePANnumber(@RequestParam String newPANno, @RequestParam String policyNumber, 
										@RequestParam Claims authenticatedUserDetails) {

		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();
		//	Claims authenticatedUserDetails = (Claims) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

		if (authenticatedUserDetails != null) {
			// This line updates the PAN number against a policy if policy number exists and
			// "token owner (authenticated user)" = "policy owner".
			boolean panNumberUpdated = policyService.updatePANnumber(newPANno, policyNumber, authenticatedUserDetails);
			if (panNumberUpdated == true) {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.SERVICE_REQ_SUCCESS);
				jsonResponseMap.put(PolicyAppConstants.DATA, "SR10003");
				jsonResponseMap.put(PolicyAppConstants.MESSAGE, "Service Request for PAN Number Updation Generated");
				return jsonResponseMap;
			} else {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
				jsonResponseMap.put(PolicyAppConstants.ERROR,
						"Token is valid but Policy no. does not exist OR unauthorized to update info of this Policy no.");
				return jsonResponseMap;
			}
		} else {
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.ERROR, "Token valid but user not authenticated (Authentication Object for this request not found in Spring's SecurityContext)");
			return jsonResponseMap;
		}
	}
	
	/* -----------------------------WHATSAPP OPT-IN TWO STEP PROCESS (step-1)----------------------------- */
	
	@PostMapping("/whatsappOptin1")
	public Map<String, Object> whatsappOptin1(@RequestParam String mobileNo) {

		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();

		// Check if mobile number is present already in WHATSAPP_OPT_IN table, return
		// true if yes and false if No.
		boolean optinStatus = policyService.mobileNoOptinStatus(mobileNo);

		if (optinStatus == true) { //means this Mobile No. is already opted in. (Old User!)
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.OLD_USER);
			jsonResponseMap.put(PolicyAppConstants.MESSAGE, "Thank you, this mobile number is already Opted In");
			return jsonResponseMap;
		} else { // means Mobile No. not opted in. (New User!) hence check the number in POLICY_MASTER whether he/she is valid policy holder. 
			boolean mobileNumberRegistered = policyService.checkMobileNo(mobileNo);
			
			if (mobileNumberRegistered == true) { //means mobile no. is present in POLICY_MASTER, hence valid user ! SEND THE OTP.
				/* Create the OTP */
				int OTP = (new Random()).nextInt(9999);
				
				/* Send OTP SMS */
				try {
					policyService.sendOTPsms(OTP, mobileNo,"Your One Time Password for whatsapp opt-in is- ");
				} catch (IOException e) {
					e.printStackTrace();
					jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
					jsonResponseMap.put(PolicyAppConstants.ERROR, "An Error occured while sending OTP");
					return jsonResponseMap;
				}
				
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.OTP_SENT);
				jsonResponseMap.put(PolicyAppConstants.MESSAGE, "Whatsapp Opt-In OTP sent on the mobile number");
				return jsonResponseMap;
			} else {
				jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
				jsonResponseMap.put(PolicyAppConstants.ERROR, "Invalid Mobile Number");
				return jsonResponseMap;
			}		
		}
	}
	
	/* -----------------------------REGENERATE JWT TOKEN----------------------------- */
	
	@PostMapping("/regenerateJWT")
	public Map<String, Object> regenerateJWT(@RequestParam String expiredJWT, HttpServletRequest req){
		
		Map<String, Object> jsonResponseMap = new HashMap<String, Object>();
		Claims refreshTokenClaims = (Claims) req.getAttribute("claims");
		Claims expiredJwtClaims = null;
		
		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);
		
		// JWT Token Time Bound Definitions
		Date expJWTToken = new Date(nowMillis + (60000 * Integer.parseInt(jwtTokenValidity)));
		
		try {
			expiredJwtClaims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
					.parseClaimsJws(expiredJWT).getBody();
		} catch (ExpiredJwtException e) {	// Here Generate a new JWT only (No refresh token) and send to the user.
			// The JWT signature algorithm we will be using to sign the token
			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
			
			/* =========JWT TOKEN GENERATION========= */
			// We will sign our JWT with our ApiKey secret
			byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
			Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
			
			// Lets set the JWT Token Claims, Signature and Expiry
			JwtBuilder builderForJWT = Jwts.builder().setId(refreshTokenClaims.getId()).setIssuedAt(now).setSubject(refreshTokenClaims.getSubject()).setIssuer(refreshTokenClaims.getIssuer())
					.signWith(signatureAlgorithm, signingKey).setExpiration(expJWTToken);
			
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.SERVICE_REQ_SUCCESS);
			jsonResponseMap.put(PolicyAppConstants.TOKEN, builderForJWT.compact());
			return jsonResponseMap;
		} catch (MalformedJwtException e) {
			e.printStackTrace();
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.ERROR, "Expired JWT was invalid- Malformed Token Structure");
			return jsonResponseMap;
		} catch (SignatureException e) {
			e.printStackTrace();
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.ERROR, "The expired JWT was invalid- Wrong Signature");
			return jsonResponseMap;
		}
		if(expiredJwtClaims != null) {
			//The expired JWT sent was not actually expired
			jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
			jsonResponseMap.put(PolicyAppConstants.ERROR, "The provided JWT Token was not expired");
			return jsonResponseMap;
		}
		
		//The expired JWT sent was not actually expired
		jsonResponseMap.put(PolicyAppConstants.STATUS, PolicyAppConstants.REQ_UNSUCCESS);
		jsonResponseMap.put(PolicyAppConstants.ERROR, "The provided JWT Token was not expired");
		return jsonResponseMap;
	}
}