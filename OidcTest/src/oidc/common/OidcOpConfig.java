package oidc.common;

public class OidcOpConfig {

	private String issuer = "http://localhost:8080/auth/realms/test";
	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	private String authUrl = "http://localhost:8080/auth/realms/test/protocol/openid-connect/auth";
	private String tokenEndPoint = "http://localhost:8080/auth/realms/test/protocol/openid-connect/token";
	private String userinfEndPoint ="http://localhost:8080/auth/realms/test/protocol/openid-connect/userinfo";
	private String jwksUri = "http://localhost:8080/auth/realms/test/protocol/openid-connect/certs";
	private String tokenIntrospectEndPoint = "http://localhost:8080/auth/realms/test/protocol/openid-connect/token/introspect";

	public String getTokenIntrospectEndPoint() {
		return tokenIntrospectEndPoint;
	}

	public void setTokenIntrospectEndPoint(String tokenIntrospectEndPoint) {
		this.tokenIntrospectEndPoint = tokenIntrospectEndPoint;
	}

	public String getTokenEndPoint() {
		return tokenEndPoint;
	}

	public void setTokenEndPoint(String tokenEndPoint) {
		this.tokenEndPoint = tokenEndPoint;
	}

	public String getUserinfEndPoint() {
		return userinfEndPoint;
	}

	public void setUserinfEndPoint(String userinfEndPoint) {
		this.userinfEndPoint = userinfEndPoint;
	}

	public String getJwksUri() {
		return jwksUri;
	}

	public void setJwksUri(String jwksUri) {
		this.jwksUri = jwksUri;
	}

	private String clientId = "test";

	private String clientSecret = "db1a8486-b320-489b-befc-40d72254cc62";


	public String getAuthUrl() {
		return authUrl;
	}

	public void setAuthUrl(String authUrl) {
		this.authUrl = authUrl;
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
