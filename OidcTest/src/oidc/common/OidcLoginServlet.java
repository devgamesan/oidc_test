package oidc.common;
import java.io.IOException;
import java.net.URISyntaxException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;

/**
 * RPのログイン用URL
 */
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
				OidcHelper helper = new OidcHelper(opConfig, rpConfig);
				response.sendRedirect(helper.createAutorizationEndPointURL(nonce, state).toString());
			}
		} catch (URISyntaxException e) {
			response.sendError(500);
		}
	}
}
