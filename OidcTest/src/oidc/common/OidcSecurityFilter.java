package oidc.common;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Date;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
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
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import net.minidev.json.JSONObject;

public class OidcSecurityFilter implements Filter
{

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// TODO 自動生成されたメソッド・スタブ

	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		try {
			// 仮。OPとRPの設定をどこかからか読んでくる
			OidcOpConfig opConfig = new OidcOpConfig();
			OidcRpConfig rpConfig = new OidcRpConfig();

		    HttpServletRequest httpReq = (HttpServletRequest) request;
		    HttpServletResponse httpRes = (HttpServletResponse) response;

		    HttpSession session = httpReq.getSession(false);
		    String authHeader = httpReq.getHeader("Authorization");

		    if (authHeader != null && !authHeader.equalsIgnoreCase(OidcConst.BEARER)) {
		    	// Basic認証等他の認証が指定されている場合は次のフィルタへ
			    chain.doFilter(request, response);
		    } else if (authHeader != null && authHeader.equalsIgnoreCase(OidcConst.BEARER)) {
		    	// Bearer認証
		    	BearerAccessToken accessToken = new BearerAccessToken(authHeader.split(" ")[1]);
				ClientAuthentication clientAuth = new ClientSecretBasic( new ClientID(opConfig.getClientId()), new Secret(opConfig.getClientSecret()));
				// アクセストークンのイントロスペクト
				TokenIntrospectionRequest tokenIntroRequest
					= new TokenIntrospectionRequest	(new URI(opConfig.getTokenIntrospectEndPoint()),
							clientAuth, accessToken);
				TokenIntrospectionResponse tokenIntroResponse = TokenIntrospectionResponse.parse(tokenIntroRequest.toHTTPRequest().send());
				if (tokenIntroResponse.indicatesSuccess()) {
					// 認証OK
					chain.doFilter(request, response);
				} else {
					// 認証エラー
					((HttpServletResponse)response).sendError(401);
				}
		    } if (session != null){
		    	synchronized (session) {
		    		// Authorization Code Flowで認証済み
			    	OidcSecurityContext securityContext = (OidcSecurityContext) session.getAttribute(OidcConst.SESSOION_OIDC_SECURITY_CONTEXT);
			    	if (securityContext == null) {
					    // 認証エラー(認可とトークンリクエストをしていない)
				    	httpRes.sendError(401);
			    	}
			    	JSONObject jsonObject = OidcUtils.getAccessTokenPayload(securityContext.getAccessToken());

			    	long now = new Date().getTime();
			    	long exp = Long.parseLong(String.valueOf(jsonObject.get("exp"))) * 1000;

			    	if (exp - now <= 120 * 1000L) {
			    		// 残り120秒で執行する
			    		// トークンリフレッシュ
						TokenRequest tokenRefreshRequest = new TokenRequest(new URI(opConfig.getTokenEndPoint()),
								new ClientSecretBasic(new ClientID(opConfig.getClientId()), new Secret(opConfig.getClientSecret())),
								new RefreshTokenGrant(securityContext.getRefreshToken()));

						TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRefreshRequest.toHTTPRequest().send());

						if (! tokenResponse.indicatesSuccess()) {
							((HttpServletResponse)response).sendError(401);
						}
						OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();

						// IDトークンバリデーション
						JWT idToken = successResponse.getOIDCTokens().getIDToken();
						if (idToken != null) {
							// nonce
							String nonceInSession = (String) session.getAttribute(OidcConst.SESSION_OIDC_NONCE);
							if (nonceInSession == null) {
								((HttpServletResponse)response).sendError(401);
							}
							IDTokenValidator idTokenValidator = new IDTokenValidator(new Issuer(opConfig.getIssuer()),
									new ClientID(opConfig.getClientId()),
									JWSAlgorithm.RS256, new URL(opConfig.getJwksUri()));
							idTokenValidator.validate(idToken, new Nonce(nonceInSession));
						}
						securityContext.setAccessToken(successResponse.getOIDCTokens().getAccessToken());
						securityContext.setRefreshToken(successResponse.getOIDCTokens().getRefreshToken());
			    	}
		    	}
		    	chain.doFilter(request, response);
		    } else {
			    // 認証エラー
		    	httpRes.sendError(401);
		    }
		} catch (URISyntaxException | ParseException | java.text.ParseException | BadJOSEException | JOSEException e) {
			((HttpServletResponse)response).sendError(500);
		}
	}


	@Override
	public void destroy() {

	}

}
