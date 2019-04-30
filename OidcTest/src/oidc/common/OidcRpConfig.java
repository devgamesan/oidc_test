package oidc.common;

/**
 * RPの各種情報
 */
public class OidcRpConfig {
	private String callbackUrl = "http://localhost:22015/OidcTest/callback";
	private String loginUrl = "http://localhost:22015/OidcTest/login";
	private String clientId = "test";
	private String clientSecret = "db1a8486-b320-489b-befc-40d72254cc62";

	public String getLoginUrl() {
		return loginUrl;
	}
	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}
	public String getCallbackurl() {
		return callbackUrl;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}
}
