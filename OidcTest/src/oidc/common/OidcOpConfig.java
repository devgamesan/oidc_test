package oidc.common;

/**
 * OpenIDProviderの各種情報
 */
public class OidcOpConfig {
	// FIXME
	private String issuer = "http://localhost:8080/auth/realms/test";
	private String authUrl = "http://localhost:8080/auth/realms/test/protocol/openid-connect/auth";
	private String tokenEndPoint = "http://localhost:8080/auth/realms/test/protocol/openid-connect/token";
	private String userinfEndPoint ="http://localhost:8080/auth/realms/test/protocol/openid-connect/userinfo";
	private String jwksUri = "http://localhost:8080/auth/realms/test/protocol/openid-connect/certs";
	private String tokenIntrospectEndPoint = "http://localhost:8080/auth/realms/test/protocol/openid-connect/token/introspect";

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

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

	public String getAuthUrl() {
		return authUrl;
	}

	public void setAuthUrl(String authUrl) {
		this.authUrl = authUrl;
	}

}
