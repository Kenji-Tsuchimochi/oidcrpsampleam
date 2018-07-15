package oidc;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class OIDCJwk {
	private Map<String, Key> keyMap = new HashMap<>();

	public OIDCJwk(final JsonObject obj) throws NoSuchAlgorithmException, InvalidKeySpecException {
		JsonArray ja = obj.getAsJsonArray("keys");
	    for (int i = 0;i < ja.size();i++) {
	        JsonObject keyJson = (JsonObject) ja.get(i);
	        String kid = keyJson.get("kid").getAsString();
	        if (keyJson.get("use") != null
	          && "sig".equals(keyJson.get("use").getAsString())) {
	            PublicKey key = buildPublicKey(keyJson);
	            if (key != null) {
	                keyMap.put(kid, key);
	            }
	        }
	    }
	}

	public String[] getKidArray() {
		int size = keyMap.size();
		return keyMap.keySet().toArray(new String[size]);
	}

	private PublicKey buildPublicKey(final JsonObject keyJson) throws NoSuchAlgorithmException, InvalidKeySpecException {
	    String kty = keyJson.get("kty").getAsString();
	    if ("RSA".equals(kty)) {
	        return buildRSAPublicKey(keyJson);
	    }
	    return null;
	}

	private PublicKey buildRSAPublicKey(final JsonObject keyJson) throws NoSuchAlgorithmException, InvalidKeySpecException {
		Base64 base64 = new Base64();
	    BigInteger modulus = new BigInteger(1, base64.decode(keyJson.get("n").getAsString()));
	    BigInteger publicExponent = new BigInteger(1, base64.decode(keyJson.get("e").getAsString()));
	    return KeyFactory.getInstance("RSA").generatePublic(
	                new RSAPublicKeySpec(modulus, publicExponent));
	}

	public PublicKey getKey(final String kid) {
	    return (PublicKey) keyMap.get(kid);
	}

	public static void main(String[] args) {
		try {
			String str = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"zhBofbZw+jkZZjXs28fGfzxZgM8=\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"AKNbl89eP6B8kZATNSPe3-OZ3esLx31hjX-dakHtPwXCAaCKqJFwjwKdxyRuPdsVG-8Dbk3PGhk26aJrSE93EpxeqmQqxNPMeD-N0_8pjkuVYWwPIQ_ts2iTiWOVn7wzlE4ASfvupqOR5pjuYMWNo_pd4L7QNjUCKoAt9H11HMyiP-6roo_EYgX4AH7OAhfUMncYsopWhkW_ze9z8wTXc8BAEgDmt8zFCez1CtqJB_MlSBUGDgk8oHYDsHKmx05baBaOBQ8LRGP5SULSbRtu34eLFootBIn0FvUZSnwTiSpbaHHRgWrMOVm07oSLWBuO3h_bj38zBuuqqVsAK8YuyoE\",\"e\":\"AQAB\"}]}";
			JsonParser parser = new JsonParser();
			JsonObject obj = parser.parse(new StringReader(str)).getAsJsonObject();

			OIDCJwk jwk = new OIDCJwk(obj);
			PublicKey key = jwk.getKey(jwk.getKidArray()[0]);
			System.out.println(key);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
}
