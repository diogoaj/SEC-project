package test.java;

import static org.junit.Assert.*;

import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.junit.BeforeClass;
import org.junit.Test;

import main.java.API;
import main.java.Crypto;
import main.java.InterfaceRMI;
import main.java.Token;

public class RegisterTest {

	private static API library;
	private static KeyStore ks;
	private static PublicKey serverKey;
	private static PublicKey publicKey;
	private static PrivateKey privateKey;
	private static InterfaceRMI stub;
	private static SecureRandom rand = new SecureRandom();
	
	
	@BeforeClass
	public static void oneTimeSetUp() throws Exception {
		library = new API();
		ks = KeyStore.getInstance("JKS");
		library.init(ks, "0", "banana");
		publicKey = library.getPublicKey();
		privateKey = library.getPrivateKey();
		serverKey = library.getServerPublicKey();
		stub = library.getStub();
	}
	
	@Test
	public void registerSuccess() {
		int value = library.register_user();
		assertEquals(value,2);
	}
	
	@Test
	public void registerWrongToken() throws RemoteException {
		byte[][] bytes = stub.getChallenge(publicKey);
		
		long l = rand.nextLong();
		byte[] t = String.valueOf(l).getBytes();
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
		byte[][] returnValue = stub.register(publicKey,
			      token,
		          Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
		int value = library.getFeedback(returnValue, bytes, t);
		assertEquals(value,1);
	}
	
	@Test
	public void registerWrongSignature() throws RemoteException {
		byte[][] bytes = stub.getChallenge(publicKey);

		long l = rand.nextLong();
		byte[] t = String.valueOf(l).getBytes();
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
		byte[] token_wrong = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(Token.nextToken(t))));
		byte[][] returnValue = stub.register(publicKey,
			      token,
		          Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token_wrong)));
		int value = library.getFeedback(returnValue, bytes, t);
		assertEquals(value,0);
	}
	
	@Test
	public void registerWrongServerSignature() throws RemoteException {
		byte[][] bytes = stub.getChallenge(publicKey);
		byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
		byte[][] returnValue = stub.register(publicKey,
			      token,
		          Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));

		long l = rand.nextLong();
		byte[] t2 = String.valueOf(l).getBytes();
		byte[] token2 = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t2)));
		
		returnValue[1] = token2;
		
		int value = library.getFeedback(returnValue, bytes, token);
		
		assertEquals(value,-1);
	}

}
