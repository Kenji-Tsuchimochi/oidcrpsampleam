package oidc;

public class OIDCConsts {
	public static final String TOKEN_URL = "https://auth.login.yahoo.co.jp/yconnect/v2/token";
	public static final String AUTH_URL = "https://auth.login.yahoo.co.jp/yconnect/v2/authorization";
	public static final String PUBKEY_URL = "https://auth.login.yahoo.co.jp/yconnect/v2/public-keys";
	public static final String CLIENT_ID = "YOUR_APP_CLIENT_ID";
	public static final String CLIENT_SECRET = "YOUR_APP_CLIENT_SECRET";
	public static final String REDIRECT_URI = "/callback";
	public static final String REDIRECT_SERVER = "http://localhost:8080";
	public static final String ISSUER_URL = "https://auth.login.yahoo.co.jp/yconnect/v2";
	public static final String USER_INFO_API_URL = "https://userinfo.yahooapis.jp/yconnect/v2/attribute";
}
