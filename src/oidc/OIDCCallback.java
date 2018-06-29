package oidc;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;

/**
 * Servlet implementation class OIDCCallback
 */
@WebServlet("/callback")
public class OIDCCallback extends HttpServlet {
	private static final long serialVersionUID = 1L;

	public OIDCCallback() {
		super();
	}

	protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		HttpSession sess = req.getSession();

		//セッションにstateとnonceが入っていることを検証
		if(sess == null) {
			res.sendError(HttpServletResponse.SC_FORBIDDEN,"No Session");
			return;
		}

		String state = String.valueOf(sess.getAttribute("state"));
		String nonce = String.valueOf(sess.getAttribute("nonce"));

		//セッションに入っているstateとリクエストパラメータで渡ってくるstateが一致していることを確認
		if( ! state.equals(req.getParameter("state"))) {
			res.sendError(HttpServletResponse.SC_FORBIDDEN,"Invalid state");
			return;
		}

		//認可コードがリクエストパラメータに存在していることを確認
		String code = req.getParameter("code");
		if(code == null || code.isEmpty()) {
			res.sendError(HttpServletResponse.SC_FORBIDDEN,"Invalid code");
			return;
		}

		//トークンエンドポイントへのリクエストを生成する
		AuthorizationCodeTokenRequest authreq = new AuthorizationCodeTokenRequest(
				new NetHttpTransport()
				, new JacksonFactory()
				, new GenericUrl(OIDCConsts.TOKEN_URL)
				, code
		);
		authreq.setRedirectUri(OIDCConsts.REDIRECT_SERVER + req.getContextPath() + OIDCConsts.REDIRECT_URI)
		.setClientAuthentication(
			new BasicAuthentication( OIDCConsts.CLIENT_ID, OIDCConsts.CLIENT_SECRET )
		);

		//トークンエンドポイントへリクエストを送出する
		HttpResponse httpres =  authreq.executeUnparsed();

		//レスポンスを取得し、パースする
		IdTokenResponse idtokenres = httpres.parseAs(IdTokenResponse.class);

		//レスポンスに含まれるアクセストークンを取得する
		String accessToken = idtokenres.getAccessToken();

		//IDトークンを取得する
		IdToken idToken = IdToken.parse(idtokenres.getFactory(), idtokenres.getIdToken());
		try {
			//IDトークンの署名を検証する
			if( ! idToken.verifySignature(OIDCUtil.getYConnectPublicKey(idToken.getHeader().getKeyId()))) {
				res.sendError(HttpServletResponse.SC_FORBIDDEN,"Invalid signature");
				return;
			}
			//iss値の検証
			if( ! idToken.verifyIssuer(Arrays.asList(OIDCConsts.ISSUER_URL))) {
				res.sendError(HttpServletResponse.SC_FORBIDDEN,"Invalid issuer");
				return;
			}
			//aud値の検証
			if( ! idToken.verifyAudience(Arrays.asList(OIDCConsts.CLIENT_ID))) {
				res.sendError(HttpServletResponse.SC_FORBIDDEN,"Invalid audience");
				return;
			}
			//セッションに入っているnonceとIDトークンに入っているnonceが一致していることを検証
			if( ! nonce.equals(idToken.getPayload().getNonce())) {
				res.sendError(HttpServletResponse.SC_FORBIDDEN,"Invalid nonce");
				return;
			}
			//at_hathの検証
			if( ! OIDCUtil.getAtHash(accessToken).equals(idToken.getPayload().getAccessTokenHash())) {
				res.sendError(HttpServletResponse.SC_FORBIDDEN,"Invalid at_hash");
				return;
			}
			//exp値の検証
			if( ! idToken.verifyExpirationTime(System.currentTimeMillis(),0)) {
				res.sendError(HttpServletResponse.SC_FORBIDDEN,"Invalid Expiration Time");
				return;
			}
			//iat値の検証
			if( ! idToken.verifyIssuedAtTime(System.currentTimeMillis(), 600)) {
				res.sendError(HttpServletResponse.SC_FORBIDDEN,"Invalid Issued At");
				return;
			}

			//UserInfoAPIにアクセスし、結果を出力
			String userInfoJsonStr = OIDCUtil.getUserInfo(accessToken);
			res.setContentType("text/plain");
			res.setCharacterEncoding("UTF-8");
			PrintWriter pw = new PrintWriter(res.getOutputStream());
			pw.println(userInfoJsonStr);
			pw.flush();
			pw.close();
		} catch (GeneralSecurityException e) {
			throw new ServletException(e);
		}
	}

	protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		doGet(req, res);
	}
}
