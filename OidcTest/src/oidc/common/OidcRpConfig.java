package oidc.common;

public class OidcRpConfig {
	private String callbackUrl = "http://localhost:22015/OidcTest/callback";
	private String loginUrl = "http://localhost:22015/OidcTest/login";
	public String getLoginUrl() {
		return loginUrl;
	}
	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}
	public String getCallbackurl() {
		return callbackUrl;
	}
}
