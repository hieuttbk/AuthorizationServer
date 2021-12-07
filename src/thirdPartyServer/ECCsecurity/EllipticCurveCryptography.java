package thirdPartyServer.ECCsecurity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.math.ec.ECPoint;

import thirdPartyServer.util.ServerConstants;

public class EllipticCurveCryptography {

	private static ECPrivateKeyParameters privateKey;
	private static ECPublicKeyParameters publicKey;
	private static Map<String, ECPrivateKeyParameters> ZPrivateKeys = new HashMap<>();
	private static Map<String, ECPublicKeyParameters> clientsPublicKeys = new HashMap<>();
	private static Map<String, String> clientsIDandq = new HashMap<>();
	private static byte[] resRegRandomR;

	/*
	 * public EllipticCurveCryptography() { privateKey = null; publicKey = null; }
	 */

	/* Transform a byte array in an hexadecimal string */
	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	/* Transform an hexadecimal string in byte array */
	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	/* Convert a string representation in its hexadecimal string */
	private static String toHex(String arg) {
		return String.format("%02x", new BigInteger(1, arg.getBytes()));
	}

	/* Convert hexadecimal notation in the ascii characters */
	private static String convertHexToString(String hex) {

		StringBuilder sb = new StringBuilder();
		StringBuilder temp = new StringBuilder();

		// 49204c6f7665204a617661 split into two characters 49, 20, 4c...
		for (int i = 0; i < hex.length() - 1; i += 2) {

			// grab the hex in pairs
			String output = hex.substring(i, (i + 2));
			// convert hex to decimal
			int decimal = Integer.parseInt(output, 16);
			// convert the decimal to character
			sb.append((char) decimal);

			temp.append(decimal);
		}

		return sb.toString();
	}

	/* Concatenation of two byte arrays */
	private static byte[] concatByteArrays(byte[] a, byte[] b) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try {
			outputStream.write(a);
			outputStream.write(b);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] concatResult = outputStream.toByteArray();
		return concatResult;
	}

	/* Perform SHA256 and return the result */
	private static byte[] sha256(byte[] data) {
		SHA256Digest digest = new SHA256Digest();
		byte[] hash = new byte[digest.getDigestSize()];
		digest.update(data, 0, data.length);
		digest.doFinal(hash, 0);
		return hash;
	}

	public static void createECKeyPair() {
		// Get domain parameters for example curve secp256r1
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		// Generate a private key and a public key
		AsymmetricCipherKeyPair keyPair;
		ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
		ECKeyPairGenerator generator = new ECKeyPairGenerator();
		generator.init(keyGenParams);
		keyPair = generator.generateKeyPair();

		privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
		publicKey = (ECPublicKeyParameters) keyPair.getPublic();
		byte[] privateKeyBytes = privateKey.getD().toByteArray();

		// First print our generated private key and public key
		System.out.println("Private key: " + toHex(privateKeyBytes));
		System.out.println("Public key: " + toHex(publicKey.getQ().getEncoded(true)));

		// Then calculate the public key only using domainParams.getG() and private key
		/*
		 * ECPoint Q = domainParams.getG().multiply(new BigInteger(privateKeyBytes));
		 * System.out.println("Calculated public key: " + toHex(Q.getEncoded(true)));
		 * 
		 * // The calculated public key and generated public key should always match if
		 * (!toHex(publicKey.getQ().getEncoded(true)).equals(toHex(Q.getEncoded(true))))
		 * { System.out.println("ERROR: Public keys do not match!"); } else {
		 * System.out.println("Congratulations, public keys match!"); }
		 */

	}

	private static BigInteger computeUserq(byte[] clientIDbytes, byte[] cert_u, BigInteger a) {

		/* Concatenation of 2 bytes array */
		byte[] certIDconcat = concatByteArrays(cert_u, clientIDbytes);

		/* Do the sha256 of the certIDconcat byte array */
		byte[] hash = sha256(certIDconcat);

		BigInteger bigIntHash = new BigInteger(hash);
		System.out.println("Hash value: " + bigIntHash);
		BigInteger hashRandMult = bigIntHash.multiply(a);
		System.out.println("Hash multiplied value: " + hashRandMult);

		BigInteger qUser = hashRandMult.add(privateKey.getD()); // k
		System.out.println("q: " + qUser);

		// Create an hashMap to retrieve the combination clientID and q value
		clientsIDandq.put(toHex(clientIDbytes), toHex(qUser.toByteArray()));

		return qUser;
	}

	public static String ECQVRegistration(String clientID, String stringHexEncodedU) {
		byte[] clientIDbytes = hexStringToByteArray(clientID);
		// Get domain parameters for example curve secp256r1
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		SecureRandom random = new SecureRandom();
		byte[] a = new byte[ServerConstants.randomNumberSize]; // Create a byte array with a size of 32 bytes
		random.nextBytes(a); // Fill the array with random bytes
		// add
		System.out.println("a = " + toHex(a));
		ECPoint pointA = domainParams.getG().multiply(new BigInteger(a));
		// add
		// System.out.println("A = " + toHex(pointA));

		/* Decode the received encoded U to obtain the point U */
		byte[] encodedU = hexStringToByteArray(stringHexEncodedU);
		ECPoint pointU = ecp.getCurve().decodePoint(encodedU);

		/*
		 * Compute the client certificate with the elliptic curve point addition
		 * operation
		 */
		ECPoint cert_u = pointU.add(pointA);
		byte[] encodedCert_u = cert_u.getEncoded(true);
		System.out.println("user certificate =" + toHex(encodedCert_u));

		/* Encode the public key that needs to be sent over the http channel */
		byte[] pubKeyBytes = publicKey.getQ().getEncoded(true);

		// Calculates the public key of the client and put it in the hashmap
		// Concatenate client's certificate with its identity
		byte[] certIDconcat = concatByteArrays(encodedCert_u, clientIDbytes);
		// Do sha256 of the concatenation
		byte[] hash = sha256(certIDconcat);
		// Elliptic curve multiplication with the point certificate
		ECPoint intermPoint = cert_u.multiply(new BigInteger(hash));
		// Point representation of the public key of the client
		ECPoint pubKeyClientPoint = intermPoint.add(publicKey.getQ());
		// Public key of the client
		ECPublicKeyParameters pubKeyClient = new ECPublicKeyParameters(pubKeyClientPoint, domainParams);
		clientsPublicKeys.put(clientID, pubKeyClient);

		// Compute the q parameter
		BigInteger qUser = computeUserq(clientIDbytes, encodedCert_u, new BigInteger(a));

		System.out.println("qUser = " + toHex(qUser.toByteArray()));

		return toHex(encodedCert_u) + "|" + toHex(qUser.toByteArray()) + "|" + toHex(pubKeyBytes);
	}

//	public static String resourceRegistrationReq(String clientID, String timestamp, String ciphertext, String nonce) {
//		byte[] cleartext = null;
//		byte[] ciphertextBytes = hexStringToByteArray(ciphertext);
//		/* Compute the key Kr = H(k*Pu||Tr) used to decrypt the ciphertext */
//		/* Elliptic curve multiplication */
//		ECPublicKeyParameters pubKeyClient = clientsPublicKeys.get(clientID);
//		ECPoint secretPoint = pubKeyClient.getQ().multiply(privateKey.getD());
//		byte[] encodedSecretPoint = secretPoint.getEncoded(true);
//		// Concatenate encoded secret point with the received timestamp
//		byte[] secretTimestampEncoded = concatByteArrays(encodedSecretPoint, hexStringToByteArray(timestamp));
//		// Do sha256 to obtain the symmetric key
//		byte[] Kr = sha256(secretTimestampEncoded);
//		System.out.println("Symmetric key: " + toHex(Kr));
//		
//		// Decrypt the cipher text to obtain the application specific request of the client
//		CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
//		ccm.init(false, new ParametersWithIV(new KeyParameter(Kr), hexStringToByteArray(nonce)));
//		byte[] tmp = new byte[ciphertextBytes.length];
//		int len = ccm.processBytes(ciphertextBytes, 0, ciphertextBytes.length, tmp, 0);
//		try {
//			len += ccm.doFinal(tmp, len);
//			cleartext = new byte[len];
//			System.arraycopy(tmp, 0, cleartext, 0, len);
//			System.out.println("Cleartext: " + toHex(cleartext));
//		} catch (IllegalStateException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (InvalidCipherTextException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//
//		// Retrieve the application data (resource name and type of subscription)
//		int appDataByteLength = cleartext.length - ServerConstants.randomNumberSize;
//		String appData = toHex(cleartext).substring(0, 2*appDataByteLength);
//		appData = convertHexToString(appData);
//		String[] data = appData.split("\\|\\|");
//		
//		String resName = data[0];
//		String subType = data[1];
//		
//		System.out.println("Resource requested by the client: " + resName);
//		System.out.println("Type of subscription requested by the client: " + subType);
//		
//		// Retrieve the random number c
//		String c = toHex(cleartext).substring(2*appDataByteLength, 2*cleartext.length);
//		System.out.println("Random number c generated by the client: " + c);
//		
//		return resName + "|" + subType + "|" + c;
//	}

	// DAS created Kr
	public static String CreatedKr(String clientID, String timestamp) {
		/* Compute the key Kr = H(k*Pu||Tr) used to decrypt the ciphertext */
		/* Elliptic curve multiplication */
		ECPublicKeyParameters pubKeyClient = clientsPublicKeys.get(clientID);
		ECPoint secretPoint = pubKeyClient.getQ().multiply(privateKey.getD());
		byte[] encodedSecretPoint = secretPoint.getEncoded(true);
		// Concatenate encoded secret point with the received timestamp
		byte[] secretTimestampEncoded = concatByteArrays(encodedSecretPoint, hexStringToByteArray(timestamp));
		// Do sha256 to obtain the symmetric key
		byte[] Kr = sha256(secretTimestampEncoded);
		System.out.println("Symmetric key Kr by the DAS: " + toHex(Kr));
		return toHex(Kr);
	}

	public static String resourceRegistrationReq(String timestamp, String ciphertext, String nonce, String encodeZ) {
		byte[] cleartext = null;
		byte[] ciphertextBytes = hexStringToByteArray(ciphertext);

		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");

		/* Compute the key Kz = H(k*Z||Tr) used to decrypt the ciphertext */
		/* Elliptic curve multiplication */

		/* Decode the received encoded Z to obtain the point Z */
		byte[] Z = hexStringToByteArray(encodeZ);
		ECPoint pointZ = ecp.getCurve().decodePoint(Z);

		ECPoint secretPoint = pointZ.multiply(privateKey.getD());
		byte[] encodedSecretPoint = secretPoint.getEncoded(true);
		// Concatenate encoded secret point with the received timestamp
		byte[] secretTimestampEncoded = concatByteArrays(encodedSecretPoint, hexStringToByteArray(timestamp));
		// Do sha256 to obtain the symmetric key
		byte[] Kz = sha256(secretTimestampEncoded);
		System.out.println("Symmetric key Kz: " + toHex(Kz));

		System.out.println("Nonce: " + nonce);
		// Decrypt the cipher text to obtain the application specific request of the
		// client
		CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
		ccm.init(false, new ParametersWithIV(new KeyParameter(Kz), hexStringToByteArray(nonce)));
		byte[] tmp = new byte[ciphertextBytes.length];
		int len = ccm.processBytes(ciphertextBytes, 0, ciphertextBytes.length, tmp, 0);
		try {
			len += ccm.doFinal(tmp, len);
			cleartext = new byte[len];
			System.arraycopy(tmp, 0, cleartext, 0, len);
			System.out.println("Cleartext: " + toHex(cleartext));
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

//		int appDataByteLength = cleartext.length;
//		String appData = toHex(cleartext).substring(0, 2 * appDataByteLength);
//		System.out.println("appData :"+ appData);
		// Retrieve the application data (resource name and type of subscription)

		// int appDataByteLength = cleartext.length - ServerConstants.randomNumberSize;
		//int appDataByteLength = cleartext.length;
//		String appData = toHex(cleartext).substring(0, 2 * appDataByteLength); // dang hex co 2 gia tri
//		appData = convertHexToString(appData);
		String appData = convertHexToString(toHex(cleartext));
		String[] data = appData.split("\\|\\|");

		String resName = data[0];
		String subType = data[1];
		String clientID = data[3];
		String Kr = data[4];
		String c = data[2];

		hexStringToByteArray(c);
		System.out.println("Kr by the client: " + Kr);
		// resName || Subtype|| c || ClientID || Kr

		System.out.println("Resource requested by the client: " + resName);
		System.out.println("Type of subscription requested by the client: " + subType);
		System.out.println("ClientID by the client: " + convertHexToString(toHex(clientID)));
		// Retrieve the random number c
		// String c = toHex(cleartext).substring(2 * appDataByteLength, 2 *
		// cleartext.length);
		System.out.println("Random number c generated by the client: " + c);
		return resName + "|" + subType + "|" + c + "|" + clientID + "|" + Kr;

		// return appData;
	}

	public static String resourceRegistrationResp(String clientID, String tokenID, String resName, String c,
			String Kr,String Texp) {
		// Convert the tokenID and resource name in its hexadecimal notation using the
		// ascii standard
		byte[] tokenIDbytes = hexStringToByteArray(toHex(tokenID));
		byte[] resNamebytes = hexStringToByteArray(toHex(resName));

		// Concatenate the tokenID with the resource name (e.g. temperature)
		// TokenID||Rn||Texp
		String sepSymb = "||";
		// Add separation symbol to tokenID
		byte[] tokenIDResConcat = concatByteArrays(tokenIDbytes, hexStringToByteArray(toHex(sepSymb)));
		// Add type of resource name
		tokenIDResConcat = concatByteArrays(tokenIDResConcat, resNamebytes);
		tokenIDResConcat = concatByteArrays(tokenIDbytes, hexStringToByteArray(toHex(sepSymb)));
		tokenIDResConcat = concatByteArrays(tokenIDResConcat, hexStringToByteArray(toHex(Texp)));
		/*
		 * Compute the key Ks
		 */
//		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
//		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
//				ecp.getSeed());
//		/* Generate a random number with a fixed size of 32 bytes */
//		SecureRandom random = new SecureRandom();
//		resRegRandomR = new byte[ServerConstants.randomNumberSize];
//		random.nextBytes(resRegRandomR); // Fill the array with random bytes
//		System.out.println("R = " + toHex(resRegRandomR));
//
//		/* Elliptic curve multiplication using the random number */
//		ECPoint pointR = domainParams.getG().multiply(new BigInteger(resRegRandomR));
//		byte[] SecretpointR = pointR.getEncoded(true);
//		byte[] Ks = sha256(SecretpointR);
		System.out.println("Symmetric key Ks: " + toHex(ServerConstants.Ks));

//		// Generate a random number
//		SecureRandom random = new SecureRandom(); 
//		byte[] r = new byte[ServerConstants.randomNumberSize]; // Create a byte array with a size of 32 bytes
//		random.nextBytes(r); // Fill the array with random bytes

		/* Compute the key Qu = H(d*P_DAS||Tr) */

//		byte[] secretTimestampConcat = concatByteArrays(hexStringToByteArray(toHex(clientID)),
//				hexStringToByteArray(toHex(c)));
//		/* Do the sha256 of the secretTimestampConcat byte array */
//		byte[] Qu = sha256(secretTimestampConcat);
//
//		System.out.println("Qu: " + toHex(Qu));
		
		byte[] Ks = hexStringToByteArray(ServerConstants.Ks);
		
		byte[] clientIDBytes = hexStringToByteArray(clientID);
		// Concatenate the identity with the random number generated during resource
		// registration
		byte[] IDresRegRandomConcat = concatByteArrays(clientIDBytes, hexStringToByteArray(c));
		// Do the sha256 of the concatenation
		byte[] Qu = sha256(IDresRegRandomConcat);
		System.out.println("Qu: " + toHex(Qu));

		// Compute the key Kt = H(Qu||Ks)
		byte[] IDprivRandConcat = concatByteArrays(Qu, Ks);
		byte[] Kt = sha256(IDprivRandConcat);
		System.out.println("Kt :" + toHex(Kt));

		// Compute the Ticket for the client
		// Generate a nonce (12 bytes) to be used for AES_256_CCM_8
		SecureRandom random = new SecureRandom();
		random = new SecureRandom();
		byte[] n1 = new byte[ServerConstants.nonceSize];
		random.nextBytes(n1); // Fill the nonce with random bytes
		System.out.println("nonce1 = " + toHex(n1));

		// Encrypt the Ticket use Kt
		CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
		ccm.init(true, new ParametersWithIV(new KeyParameter(Kt), n1));
		byte[] ticket = new byte[tokenIDResConcat.length + 8];
		int len = ccm.processBytes(tokenIDResConcat, 0, tokenIDResConcat.length, ticket, 0);
		try {
			len += ccm.doFinal(ticket, len);
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("Ticket: " + toHex(ticket));

		random = new SecureRandom();
		byte[] n2 = new byte[ServerConstants.nonceSize];
		random.nextBytes(n2); // Fill the nonce with random bytes
		System.out.println("nonce2 = " + toHex(n2));
		System.out.println("Texp = " + Texp);
        
		String Ticket = toHex(ticket);
		// Tai sao phai doi sang String: Vi tach ban tin se dung split(chi dung tren String) 
		//nen Ticket phai dua ve String sau do dua ve ByteArray
		byte[] ticketTexp = concatByteArrays(hexStringToByteArray(toHex(Ticket)), hexStringToByteArray(toHex(sepSymb)));
		ticketTexp = concatByteArrays(ticketTexp, hexStringToByteArray(Texp));
		CCMBlockCipher ccm1 = new CCMBlockCipher(new AESEngine());
		ccm1.init(true, new ParametersWithIV(new KeyParameter(hexStringToByteArray(Kr)), n2));
		byte[] ET = new byte[ticketTexp.length + 8];
		int len2 = ccm1.processBytes(ticketTexp, 0, ticketTexp.length, ET, 0);
		try {
			len2 += ccm1.doFinal(ET, len2);
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("ET: " + toHex(ET));

		return toHex(ET) + "|" + toHex(Kt) + "|" + toHex(n1) + "|" + toHex(n2);
	}

	public static String createSessionKey(String clientID, String timestamp) {
		// Compute the symmetric session key SKsession = H(k*Pu||Ts)
		// Elliptic curve multiplication
		ECPublicKeyParameters pubKeyClient = clientsPublicKeys.get(clientID);
		ECPoint secretPoint = pubKeyClient.getQ().multiply(privateKey.getD());
		byte[] encodedSecretPoint = secretPoint.getEncoded(true);
		// Concatenate encoded secret point with the received timestamp
		byte[] secretTimestampEncoded = concatByteArrays(encodedSecretPoint, hexStringToByteArray(timestamp));
		// Do sha256 to obtain the symmetric key
		byte[] SKsession = sha256(secretTimestampEncoded);
		System.out.println("Symmetric session key: " + toHex(SKsession));
		return toHex(SKsession);
	}

	public static ECPrivateKeyParameters getPrivateKey() {
		return privateKey;
	}

	public static ECPublicKeyParameters getPublicKey() {
		return publicKey;
	}

	public static Map<String, String> getClientIDandq() {
		return clientsIDandq;
	}
}
