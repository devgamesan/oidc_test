package oidc.common;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

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
					chain.doFilter(request, response);
				} else {
					((HttpServletResponse)response).sendError(500);
				}
		    } if (session != null){
		    	synchronized (session) {
		    		// Authorization Code Flowで認証済み
			    	OidcSecurityContext securityContext = (OidcSecurityContext) session.getAttribute(OidcConst.SESSOION_OIDC_SECURITY_CONTEXT);
			    	if (securityContext == null) {
					    // 認証エラー(認可とトークンリクエストをしていない)
				    	httpRes.sendError(401);
			    	}

			    	// 残り時間が120秒以下であったら更新する


			    	// 更新エラー
				}
		    } else {
			    // 認証エラー
		    	httpRes.sendError(401);
		    }
		} catch (URISyntaxException | ParseException e) {
			((HttpServletResponse)response).sendError(500);
		}
	}



	// テスト
	/*

	*/

	// トークンリフレッシュ
	//TokenRevocationRequest tokenRefreshRequest = new TokenRevocationRequest(uri, clientAuth, token):
	@Override
	public void destroy() {

	}

}
