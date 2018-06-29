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

	public static PublicKey getYConnectPublicKey(String kid) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		//Public Key エンドポイントにアクセス
		URL url = new URL(OIDCConsts.PUBKEY_URL);
		HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();

		if(conn.getResponseCode() == HttpsURLConnection.HTTP_OK) {
			//JSON形式で返却されるのパースする
			JsonParser parser = new JsonParser();
			JsonObject obj = parser.parse(new InputStreamReader(conn.getInputStream())).getAsJsonObject();

			//公開鍵文字列を取得する
			String pubkeystr = obj.get(kid).getAsString();

			KeyFactory kf = KeyFactory.getInstance("RSA");

			//公開鍵文字列に含まれる余分な文字列を削除する
			pubkeystr = pubkeystr.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");

			//PublicKeyインスタンスを生成する
	        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.decodeBase64(pubkeystr));
	        PublicKey pubKey = (PublicKey) kf.generatePublic(keySpecX509);

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
			OIDCUtil.getYConnectPublicKey("0cc175b9c0f1b6a831c399e269772661");
		}
		catch(Exception e) {
			e.printStackTrace();
		}

	}
}
