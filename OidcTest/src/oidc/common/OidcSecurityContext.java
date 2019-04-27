package oidc.common;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

public class OidcSecurityContext {
	AccessToken accessToken = null;
	RefreshToken refreshToken = null;

	public AccessToken getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(AccessToken accessToken) {
		this.accessToken = accessToken;
	}

	public RefreshToken getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(RefreshToken refreshToken) {
		this.refreshToken = refreshToken;
	}

	public OidcSecurityContext(AccessToken accessToken, RefreshToken refreshToken) {
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}
}
