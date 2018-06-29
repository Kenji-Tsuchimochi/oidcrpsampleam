package oidc;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.http.GenericUrl;

@WebServlet(urlPatterns="/start")
public class OIDCStart extends HttpServlet {
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		HttpSession sess = req.getSession();
		if(sess == null || sess.getAttribute("state") == null || sess.getAttribute("nonce") == null) {
			res.sendRedirect("/");
		}
		else {
			String state = sess.getAttribute("state").toString();
			String nonce = sess.getAttribute("nonce").toString();

			if(state.isEmpty()) {
				res.sendRedirect("/");
			}
			else if(nonce.isEmpty()) {
				res.sendRedirect("/");
			}
			else {
				AuthorizationCodeRequestUrl url = new AuthorizationCodeRequestUrl(
					OIDCConsts.AUTH_URL, OIDCConsts.CLIENT_ID
				);
				//response_typeパラメータを設定
				url.setResponseTypes(Arrays.asList("code"));

				//scopeパラメータを設定
				url.setScopes(Arrays.asList("openid","profile"));

				//stateパラメータを設定
				url.setState(state);

				//nonceパラメータを設定
				url.set("nonce", nonce);

				//redirect_uriパラメータを設定
				GenericUrl redirectUri = new GenericUrl("http://localhost:8080" + req.getContextPath());
				redirectUri.appendRawPath(OIDCConsts.REDIRECT_URI);
				url.setRedirectUri(redirectUri.build());

				res.sendRedirect(url.build());
			}
		}
	}
}