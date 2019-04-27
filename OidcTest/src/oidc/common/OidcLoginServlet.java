package oidc.common;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;

public class OidcLoginServlet extends HttpServlet {


	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try {
			// 同一セッションでは認可リクエスト/トークンリクエスト/イントロスペクトは排他する
			synchronized (request.getSession()) {
				// StateとNonceをセッションに保存
				Nonce nonce = new Nonce();
				State state = new State();

				request.getSession().setAttribute(OidcConst.SESSION_OIDC_NONCE, nonce.getValue());
				request.getSession().setAttribute(OidcConst.SESSION_OIDC_STATE, state.getValue());

				// 仮。OPとRPの設定をどこかからか読んでくる
				OidcOpConfig opConfig = new OidcOpConfig();
				OidcRpConfig rpConfig = new OidcRpConfig();

				// Authorization End Pointにリダイレクト
				StringBuilder urlBuff = new StringBuilder();
				urlBuff.append(opConfig.getAuthUrl())
				.append("?").append(OidcConst.AUTH_REQ_PARAM_RESPONSE_TYPE).append("=").append(OidcConst.AUTH_REQ_RESPONSE_TYPE_CODE)
				.append("&").append(OidcConst.AUTH_REQ_PARAM_SCOPE).append("=").append("openid")
				.append("&").append(OidcConst.AUTH_REQ_PARAM_CLIENT_ID).append("=").append(opConfig.getClientId())
				.append("&").append(OidcConst.AUTH_REQ_PARAM_STATE).append("=").append(state.getValue())
				.append("&").append(OidcConst.AUTH_REQ_PARAM_NONCE).append("=").append(nonce.getValue())
				.append("&").append(OidcConst.AUTH_REQ_PARAM_REDIRECT_URI).append("=").append(rpConfig.getCallbackurl());

				URI redirectUri = new URI(urlBuff.toString());
				response.sendRedirect(redirectUri.toString());
			}
		} catch (URISyntaxException e) {
			response.sendError(500);
		}
	}
}
