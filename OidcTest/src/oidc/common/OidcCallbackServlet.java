package oidc.common;
import java.io.IOException;
import java.net.URISyntaxException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

/**
 * 認証サーバからリダイレクトバックをうけるサーブレット
 */
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
				String authCode = request.getParameter(OidcConst.AUTH_REQ_PARAM_CODE);
				if (authCode == null) {
					response.sendRedirect(rpConfig.getLoginUrl());
				}

				OidcHelper helper = new OidcHelper(opConfig, rpConfig);

				// トークンリクエスト
				TokenResponse tokenResponse = helper.sendTokenRequest(authCode);

				if (! tokenResponse.indicatesSuccess()) {
				    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
				    response.sendError(500);
				}
				OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();

				// IDトークンバリデーション
				try {
					helper.validateIDToken(successResponse.getOIDCTokens().getIDToken(), nonceInSession);
				} catch (BadJOSEException e) {
					// IDトークンがinvalid or 期限切れ
					response.sendRedirect(rpConfig.getLoginUrl());
				}

				AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
				RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();

				// アクセストークンとリフレッシュトークンをセッションに保存
				OidcSecurityContext securityContext = new OidcSecurityContext(accessToken, refreshToken);
				session.setAttribute(OidcConst.SESSOION_OIDC_SECURITY_CONTEXT, securityContext);

				// 目的のページにリダイレクトする
				response.sendRedirect("target.jsp");
			}
		} catch (JOSEException |IOException | URISyntaxException | ParseException e) {
			response.sendError(500);
		}
	}
}
