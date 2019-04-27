package oidc.common;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

public class OidcCallbackServlet extends HttpServlet {


	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try {
			// OPからリダイレクトバックされてきた。

			// 仮。OPとRPの設定をどこかからか読んでくる
			OidcOpConfig opConfig = new OidcOpConfig();
			OidcRpConfig rpConfig = new OidcRpConfig();

			// セッション取得
			HttpSession session = request.getSession(false);

			if (session == null) {
				// 直接このURLをたたかれた
				response.sendRedirect(rpConfig.getLoginUrl());
			}

			// 同一セッションでは認可リクエスト/トークンリクエスト/イントロスペクトは排他する
			synchronized (session) {
				// Stateの突合せ
				String stateInSess = (String) session.getAttribute(OidcConst.SESSION_OIDC_STATE);

				if (stateInSess == null) {
					// stateがない
					response.sendRedirect(rpConfig.getLoginUrl());
				}

				// stateの突合せ
				String state = request.getParameter(OidcConst.AUTH_REQ_PARAM_STATE);

				if (!stateInSess.equals(state)) {
					// stateが一致しない
					response.sendRedirect(rpConfig.getLoginUrl());
				}

				// nonce
				String nonceInSession = (String) session.getAttribute(OidcConst.SESSION_OIDC_NONCE);
				if (nonceInSession == null) {
					// nonceがない場合もログインからやり直し
					response.sendRedirect(rpConfig.getLoginUrl());
				}

				// 認可コード取得
				String auth_code = request.getParameter(OidcConst.AUTH_REQ_PARAM_CODE);
				if (auth_code == null) {
					response.sendRedirect(rpConfig.getLoginUrl());
				}

				// トークンリクエスト
				ClientID clientId = new ClientID(opConfig.getClientId());
				AuthorizationGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode(auth_code), new URI(rpConfig.getCallbackurl()));
				ClientAuthentication clientAuth = new ClientSecretBasic(clientId, new Secret(opConfig.getClientSecret()));

				URI tokenEndpoint = new URI(opConfig.getTokenEndPoint());

				TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

				TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

				if (! tokenResponse.indicatesSuccess()) {
				    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
				    // TODO Errorハンドリング
				    response.sendError(500);
				}
				OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();


				// IDトークンバリデーション
				JWT idToken = successResponse.getOIDCTokens().getIDToken();
				IDTokenValidator idTokenValidator = new IDTokenValidator(new Issuer(opConfig.getIssuer()), clientId,
						JWSAlgorithm.RS256, new URL(opConfig.getJwksUri()));
				idTokenValidator.validate(idToken, new Nonce(nonceInSession));

				AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
				RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();

				// アクセストークンとリフレッシュトークンをセッションに保存
				OidcSecurityContext securityContext = new OidcSecurityContext(accessToken, refreshToken);
				session.setAttribute(OidcConst.SESSOION_OIDC_SECURITY_CONTEXT, securityContext);

				// 目的のページにリダイレクトする
				response.sendRedirect("target.jsp");
			}
		} catch (BadJOSEException | JOSEException |IOException | URISyntaxException | ParseException e) {
			response.sendError(500);
		}
	}
}
