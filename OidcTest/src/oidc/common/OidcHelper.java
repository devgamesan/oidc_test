package oidc.common;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

public class OidcHelper {

	private OidcOpConfig opConfig = null;
	private OidcRpConfig rpConfig = null;

	/**
	 * コンストラクタ
	 * @param opConfig OpenID Provider Config
	 * @param rpConfig Relaying Party Config
	 */
	public OidcHelper(OidcOpConfig opConfig, OidcRpConfig rpConfig) {
		this.opConfig = opConfig;
		this.rpConfig = rpConfig;
	}

	/**
	 * 認可リクエスト用のURIを構築する
	 * @param nonce nonce
	 * @param state state
	 * @return  認可リクエスト用のURI
	 * @throws URISyntaxException URI構築失敗
	 */
	public URI createAutorizationEndPointURL(Nonce nonce, State state) throws URISyntaxException {
		StringBuilder urlBuff = new StringBuilder();
		urlBuff.append(opConfig.getAuthUrl())
		.append("?").append(OidcConst.AUTH_REQ_PARAM_RESPONSE_TYPE).append("=").append(OidcConst.AUTH_REQ_RESPONSE_TYPE_CODE)
		.append("&").append(OidcConst.AUTH_REQ_PARAM_SCOPE).append("=").append(OidcConst.AUTH_REQ_PARAM_SCOPE_OPENID)
		.append("&").append(OidcConst.AUTH_REQ_PARAM_CLIENT_ID).append("=").append(rpConfig.getClientId())
		.append("&").append(OidcConst.AUTH_REQ_PARAM_STATE).append("=").append(state.getValue())
		.append("&").append(OidcConst.AUTH_REQ_PARAM_NONCE).append("=").append(nonce.getValue())
		.append("&").append(OidcConst.AUTH_REQ_PARAM_REDIRECT_URI).append("=").append(rpConfig.getCallbackurl());
		return new URI(urlBuff.toString());
	}

	/**
	 * アクセストークンリクエスト
	 * @param authCode 認可コード
	 * @return
	 * @throws URISyntaxException  URL不正
	 * @throws ParseException トークンリクエストのレスポンスのパース失敗
	 * @throws IOException
	 */
	public TokenResponse sendTokenRequest(String authCode) throws URISyntaxException, ParseException, IOException {
		// トークンリクエスト
		ClientID clientId = new ClientID(rpConfig.getClientId());
		AuthorizationGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode(authCode), new URI(rpConfig.getCallbackurl()));
		ClientAuthentication clientAuth = new ClientSecretBasic(clientId, new Secret(rpConfig.getClientSecret()));

		URI tokenEndpoint = new URI(opConfig.getTokenEndPoint());

		TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

		return  OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

	}


	/**
	 * IDトークンを検証する
	 * @param idToken IDトークン
	 * @param nonceInSession nonce
	 * @return IDTokenClaimsSet
	 * @throws MalformedURLException URL不正
	 * @throws BadJOSEException IDトークンが不正/期限切れ
	 * @throws JOSEException IDトークンのパース失敗
	 */
	public IDTokenClaimsSet validateIDToken(JWT idToken, String nonceInSession) throws MalformedURLException, BadJOSEException, JOSEException {
		ClientID clientId = new ClientID(rpConfig.getClientId());
		IDTokenValidator idTokenValidator = new IDTokenValidator(new Issuer(opConfig.getIssuer()), clientId,
				JWSAlgorithm.RS256, new URL(opConfig.getJwksUri()));
		return idTokenValidator.validate(idToken, new Nonce(nonceInSession));
	}


	/**
	 * アクセストークンをイントロスペクトする
	 * @param accessToken アクセストークン
	 * @return TokenIntrospectionResponse
	 * @throws ParseException イントロスぺトのレスポンスのパース失敗
	 * @throws IOException
	 * @throws URISyntaxException URI構築失敗
	 */
	public TokenIntrospectionResponse introspectAccessToke(BearerAccessToken accessToken) throws ParseException, IOException, URISyntaxException {
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID(rpConfig.getClientId()),
				new Secret(rpConfig.getClientSecret()));
		// アクセストークンのイントロスペクト
		TokenIntrospectionRequest tokenIntroRequest = new TokenIntrospectionRequest(	new URI(opConfig.getTokenIntrospectEndPoint()),
				clientAuth, accessToken);
		return TokenIntrospectionResponse.parse(tokenIntroRequest.toHTTPRequest().send());
	}

	/**
	 * アクセストークンをリフレシュする
	 * @param refreshToken リフレッシュトークン
	 * @return TokenResponse
	 * @throws ParseException レスポンスのパース失敗
	 * @throws IOException
	 * @throws URISyntaxException URI構築失敗
	 */
	public TokenResponse refreshAccessToken(RefreshToken refreshToken) throws ParseException, IOException, URISyntaxException {
		TokenRequest tokenRefreshRequest = new TokenRequest(new URI(opConfig.getTokenEndPoint()),
				new ClientSecretBasic(new ClientID(rpConfig.getClientId()), new Secret(rpConfig.getClientSecret())),
				new RefreshTokenGrant(refreshToken));

		return OIDCTokenResponseParser.parse(tokenRefreshRequest.toHTTPRequest().send());

	}

}
