package oidc.common;

import java.io.IOException;
import java.net.URISyntaxException;
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
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

import net.minidev.json.JSONObject;

/**
 * Bearer認証および、セッションによる認証をハンドルするフィルタ
 */
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

			if (authHeader != null) {
				String[] authElems = authHeader.split(" ");
				if (authElems.length != 2) {
					// Bad Request
					((HttpServletResponse) response).sendError(400);
				}

				if (!authElems[0].equalsIgnoreCase(OidcConst.BEARER)) {
					// Basic認証等他の認証が指定されている場合は次のフィルタへ
					chain.doFilter(request, response);
				} else if (authElems[0].equalsIgnoreCase(OidcConst.BEARER)) {
					// Bearer認証
					BearerAccessToken accessToken = new BearerAccessToken(authElems[1]);

					OidcHelper helper = new OidcHelper(opConfig, rpConfig);
					// アクセストークンのイントロスペクト
					TokenIntrospectionResponse tokenIntroResponse = helper.introspectAccessToke(accessToken);
					if (tokenIntroResponse.indicatesSuccess()) {
						// 認証OK
						chain.doFilter(request, response);
					} else {
						// 認証エラー
						((HttpServletResponse) response).sendError(401);
					}
				}
		    } else if (session != null){
		    	synchronized (session) {
		    		// Authorization Code Flowで認証済み
			    	OidcSecurityContext securityContext = (OidcSecurityContext) session.getAttribute(OidcConst.SESSOION_OIDC_SECURITY_CONTEXT);
			    	if (securityContext == null) {
					    // 認証エラー(認可とトークンリクエストをしていない)
				    	httpRes.sendError(401);
			    	}

			    	if (checkNeedUpdateAccessToken(securityContext.getAccessToken())) {
			    		// アクセストークンの更新要

						OidcHelper helper = new OidcHelper(opConfig, rpConfig);

						// 残り120秒で執行する
			    		// トークンリフレッシュ
						TokenResponse tokenResponse = helper.refreshAccessToken(securityContext.getRefreshToken());
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
							// IDトークンバリデーション
							try {
								helper.validateIDToken(idToken, nonceInSession);
							} catch (BadJOSEException e) {
								// IDトークンがinvalid or 期限切れ
								httpRes.sendError(401);
							}
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
		} catch (URISyntaxException | ParseException | java.text.ParseException | JOSEException e) {
			((HttpServletResponse)response).sendError(500);
		}
	}

	/**
	 * アクセストークンの更新が必要かチェックする
	 * @param accessToken アクセストークン
	 * @return true:更新要, false:更新不要
	 * @throws java.text.ParseException
	 */
	private boolean checkNeedUpdateAccessToken(AccessToken accessToken) throws java.text.ParseException {
		SignedJWT signedJWT = SignedJWT.parse(accessToken.getValue());

		JSONObject jsonObject = 	signedJWT.getPayload().toJSONObject();
    	long now = new Date().getTime();
    	long exp = Long.parseLong(String.valueOf(jsonObject.get("exp"))) * 1000;

    	if (exp - now <= 120 * 1000L) {
    		// 有効期限が残り120秒の場合、更新要
    		return true;
    	}
    	return false;
	}

	@Override
	public void destroy() {

	}

}
