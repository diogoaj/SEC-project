package test.java;

import static org.junit.Assert.*;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import org.junit.BeforeClass;
import org.junit.Test;

import main.java.API;
import main.java.Crypto;
import main.java.InterfaceRMI;
import main.java.Time;
import main.java.Token;

public class RetrieveTest{
	private static API library;
	private static KeyStore ks;
	private static PublicKey serverKey;
	private static PublicKey publicKey;
	private static PrivateKey privateKey;
	private static InterfaceRMI stub;
	private static SecureRandom rand = new SecureRandom();
	private static SecretKey secretKey;
	
	
	@BeforeClass
	public static void oneTimeSetUp() throws Exception {
		library = new API();
		ks = KeyStore.getInstance("JKS");
		library.init(ks, "0", "banana");
		publicKey = library.getPublicKey();
		privateKey = library.getPrivateKey();
		serverKey = library.getServerPublicKey();
		stub = library.getStub();
		secretKey = library.getSecretKey();
		library.register_user();
		library.save_password("gmail".getBytes(), "rito".getBytes(), "cruz".getBytes());
	}
	
	@Test
	public void retrieveSuccess() throws Exception{
		byte[][] bytes = stub.getChallenge(publicKey);
		Long timestamp = library.getTimestampFromKey(new String("gmail") + "||" + new String("rito"));

		byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
		
		byte[] d = Crypto.encodeBase64(
				   library.encrypt(secretKey, 
						   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(timestamp))));
		byte[] u = Crypto.encodeBase64(
				   library.encrypt(secretKey, 
						   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(timestamp+1))));
		
		byte[][] returnValue = stub.get(publicKey, 
				                   d, 
				                   u, 
				                   token,
				                   Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,token)));
		
		int value = library.getFeedback(returnValue, bytes, t);
		assertEquals(value, 3);
	}
	
	@Test
	public void retrieveSuccess2() throws Exception{
		library.save_password("facebook".getBytes(), "user1".getBytes(), "pass1".getBytes());
		byte[] pw = library.retrieve_password("facebook".getBytes(), "user1".getBytes());

		String pass = new String(pw);
		pass = pass.split("\\|\\|")[0];
		assertEquals(pass, "pass1");
	}
	
	@Test
	public void retrieveFail1() throws Exception{
		byte[] pw = library.retrieve_password("tecnico".getBytes(), "Fernando".getBytes());
		assertNull(pw);
	}
	
	@Test
	public void retrieveFail2() throws Exception{
		byte[] pw = library.retrieve_password("facebook".getBytes(), "Alberto".getBytes());
		assertNull(pw);
	}
	
	@Test
	public void retrieveWrongToken() throws Exception{
		byte[][] bytes = stub.getChallenge(publicKey);
		Long timestamp = library.getTimestampFromKey(new String("gmail") + "||" + new String("rito"));

		long l = rand.nextLong();
		byte[] t = String.valueOf(l).getBytes();
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
		
		byte[] d = Crypto.encodeBase64(
				   library.encrypt(secretKey, 
						   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(timestamp))));
		byte[] u = Crypto.encodeBase64(
				   library.encrypt(secretKey, 
						   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(timestamp+1))));
		
		byte[][] returnValue = stub.get(publicKey, 
				                   d, 
				                   u, 
				                   token,
				                   Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,token)));
		
		int value = library.getFeedback(returnValue, bytes, t);
		assertEquals(value, 2);
	}
	
	@Test
	public void retrieveWrongSignature() throws Exception{
		byte[][] bytes = stub.getChallenge(publicKey);
		Long timestamp = library.getTimestampFromKey(new String("gmail") + "||" + new String("rito"));

		long l = rand.nextLong();
		byte[] t = String.valueOf(l).getBytes();
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
		byte[] token_wrong = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(Token.nextToken(t))));
		
		byte[] d = Crypto.encodeBase64(
				   library.encrypt(secretKey, 
						   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(timestamp))));
		byte[] u = Crypto.encodeBase64(
				   library.encrypt(secretKey, 
						   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(timestamp+1))));
		
		byte[][] returnValue = stub.get(publicKey, 
				                   d, 
				                   u, 
				                   token,
				                   Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,token_wrong)));
		
		int value = library.getFeedback(returnValue, bytes, t);
		assertEquals(value, 1);
	}
	
	@Test
	public void retrieveWrongServerSignature() throws Exception{
		byte[][] bytes = stub.getChallenge(publicKey);
		Long timestamp = library.getTimestampFromKey(new String("gmail") + "||" + new String("rito"));

		long l = rand.nextLong();
		byte[] t = String.valueOf(l).getBytes();
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
		byte[] token_wrong = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(Token.nextToken(t))));
		
		byte[] d = Crypto.encodeBase64(
				   library.encrypt(secretKey, 
						   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(timestamp))));
		byte[] u = Crypto.encodeBase64(
				   library.encrypt(secretKey, 
						   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(timestamp+1))));
		
		byte[][] returnValue = stub.get(publicKey, 
				                   d, 
				                   u, 
				                   token,
				                   Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,token_wrong)));
		
		long l2 = rand.nextLong();
		byte[] t2 = String.valueOf(l2).getBytes();
		byte[] token2 = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t2)));
		
		returnValue[1] = token2;
		
		int value = library.getFeedback(returnValue, bytes, t);
		assertEquals(value, -1);
	}
	

}