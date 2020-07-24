package com.tata.policyservice.constants;

public final class PolicyAppConstants {

	/* Application Wide Status Codes */
	public static final int REQ_UNSUCCESS = 0;
	public static final int OLD_USER = 1001;
	public static final int NEW_USER = 1002;
	public static final int OTP_SENT = 1003;
	public static final int SERVICE_REQ_SUCCESS = 1004;
	public static final int VALIDATION_REQ_SUCCESS = 1005;
	public static final int GET_DATA_REQ_SUCCESS = 1006;

	/* Application Wide Other Constants */
	public static final String STATUS = "Status";
	public static final String ERROR = "Error";
	public static final String DATA = "Data";
	public static final String TOKEN = "Token";
	public static final String REFRESH = "Refresh";
	public static final String MESSAGE = "Message";
	public static final String HEADER_KEY = "Authorization";
	public static final String TOKEN_PREFIX = "Bearer ";
	
	/* The SECRET KEY for JWT creation and validation */
	public static final String SECRET_KEY = "oeRaYY7Wo24sDqKSX3IM9ASGmdGPmkTd9jo1QTy4b7P9Ze5_9hKolVX8xNrQDcNRfVEdTZNOuOyqEGhXEbdJI-ZQ19k_o9MI0y3eZN2lp9jow55FfXMiINEdt1XR85VipRLSOkT6kSpzs2x-jbLDiz9iFVzkd81YKxMgPA7VfZeQUm4n-mOmnWMaVX30zGFU4L3oPBctYKkl4dYfqYWqRNfrgPJVi5DGFjywgxx0ASEiJHtV72paI3fDR2XwlSkyhhmY-ICjCRmsJN4fX1pdoL8a18-aQrvyu4j0Os6dVPYIoPvvY0SAZtWYKHfM15g7A3HD4cVREf9cUsprCRK93w";
	
	private PolicyAppConstants() {

	}
}
