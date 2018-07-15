package oidc;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class OIDCUtil {
	public static String getAtHash(String accessToken) {
		byte[] hashedbytes = DigestUtils.sha256(accessToken);
		byte[] hashedbyteshalf = new byte[hashedbytes.length/2];
		System.arraycopy(hashedbytes, 0, hashedbyteshalf, 0, hashedbyteshalf.length);
		return Base64.encodeBase64URLSafeString(hashedbyteshalf);
	}

	public static PublicKey getJwkPublicKey(String kid) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		//Public Key エンドポイントにアクセス
		URL url = new URL(OIDCConsts.PUBKEY_URL);
		HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();

		if(conn.getResponseCode() == HttpsURLConnection.HTTP_OK) {
			//JSON形式で返却されるのパースする
			JsonParser parser = new JsonParser();
			JsonObject obj = parser.parse(new InputStreamReader(conn.getInputStream())).getAsJsonObject();

			OIDCJwk jwk = new OIDCJwk(obj);
			PublicKey pubKey = jwk.getKey(jwk.getKidArray()[0]);

	        return pubKey;
		}
		else {
			return null;
		}
	}

	public static String getUserInfo(String accessToken) throws IOException {
		URL url = new URL(OIDCConsts.USER_INFO_API_URL);
		HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();

		//Authorizationヘッダに、Bearerトークン形式でアクセストークンを設定する
		conn.setRequestProperty("Authorization", "Bearer " + accessToken);

		if(conn.getResponseCode() == HttpsURLConnection.HTTP_OK) {
			BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			StringBuilder sb = new StringBuilder();
			String line = null;
			while((line = br.readLine()) != null) {
				sb.append(line);
			}

			return sb.toString();
		}
		else {
			return null;
		}
	}

	public static void main(String[] args) {
		try {
			OIDCUtil.getJwkPublicKey("0cc175b9c0f1b6a831c399e269772661");
		}
		catch(Exception e) {
			e.printStackTrace();
		}

	}
}
