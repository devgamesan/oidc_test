package oidc.common;

import java.text.ParseException;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;

import net.minidev.json.JSONObject;

public class OidcUtils {
	public static JSONObject getAccessTokenPayload(AccessToken accessToken) throws ParseException {
		SignedJWT signedJWT = SignedJWT.parse(accessToken.getValue());
		return signedJWT.getPayload().toJSONObject();
	}
	}


