package test.java;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import main.java.Crypto;
import main.java.InterfaceImpl;
import main.java.Time;
import main.java.Token;
import main.java.business.PasswordEntry;
import main.java.business.PasswordManager;

public class ServerGetTest {
	private static InterfaceImpl interfacermi;
	private static PasswordManager pm;
	
	private static KeyPairGenerator keyGen;
	private static KeyGenerator keyGenSecret;
	
	private static PublicKey public1; 
	private static PrivateKey private1;
	
	private static PublicKey public2;
	private static PrivateKey private2;

	private static SecretKey secretKey;

    @BeforeClass
    public static void oneTimeSetUp() throws Exception {
    	keyGen = KeyPairGenerator.getInstance("RSA");
		interfacermi = new InterfaceImpl(new PasswordManager());
		pm = interfacermi.getManager();

		// Generate two keypairs
		keyGen.initialize(2048);
		KeyPair kp = keyGen.generateKeyPair();
    	public1 = kp.getPublic();
    	private1 = kp.getPrivate();
    	
    	kp = keyGen.generateKeyPair();
    	public2 = kp.getPublic();
    	private2 = kp.getPrivate();
    
		keyGenSecret = KeyGenerator.getInstance("AES");
    	keyGenSecret.init(128); 
    	secretKey = keyGenSecret.generateKey();
		
    	// Register user1
    	byte[][] received = interfacermi.getChallenge(public1, Crypto.signData(private1, public1.getEncoded()));
    	byte[] t = Crypto.decryptRSA(private1, Crypto.decodeBase64(received[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	interfacermi.register(public1, token, Crypto.signData(private1, Crypto.concatenateBytes(public1.getEncoded(), token)));
    	
    	// Register user2
    	received = interfacermi.getChallenge(public2, Crypto.signData(private2, public2.getEncoded()));
    	t = Crypto.decryptRSA(private2, Crypto.decodeBase64(received[0]));
		token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	interfacermi.register(public2, token, Crypto.signData(private2, Crypto.concatenateBytes(public2.getEncoded(), token)));
    }
    
    @After
    public void tearDown() {
    	pm.getUsers().get(public1).getData().clear();
    	pm.getUsers().get(public2).getData().clear();
    }
    
    @Test
    public void getTestSuccess() throws Exception{
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
    	long currentTime = Time.getTimeLong();

    	// Add a password entry to the user
  		byte[] d1 = Crypto.encodeBase64(
  				    Crypto.encrypt(secretKey, 
  					Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
  		byte[] u1 = Crypto.encodeBase64(
  				    Crypto.encrypt(secretKey, 
  					Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
  		byte[] p1 = Crypto.encodeBase64(
  				    Crypto.encrypt(secretKey, 
  				    Crypto.concatenateBytes(password.getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
  		
    	pm.getUser(public1).addPasswordEntry(new PasswordEntry(d1,u1,p1));
    	
    	// Call get method
    	byte[][] returned = interfacermi.getChallenge(public1, Crypto.signData(private1, public1.getEncoded()));
    	
    	boolean verified = Crypto.verifySignature(pm.getServerPublicKey(), returned[0], returned[1]);
    	assertTrue(verified);
    	
    	byte[] t = Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
		returned = interfacermi.getChallenge(public1, Crypto.signData(private1, public1.getEncoded()));

		byte[] d2 = Crypto.encodeBase64(
				    Crypto.encrypt(secretKey, 
				    Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
		byte[] u2 = Crypto.encodeBase64(
				    Crypto.encrypt(secretKey, 
				    Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
		t = Crypto.decryptRSA(
				   private1, 
				   Crypto.decodeBase64(returned[0]));
		
		token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
		returned = interfacermi.get(public1, 
						 d2, 
						 u2, 
						 token,
						 Crypto.signData(private1, Crypto.concatenateBytes(d2,u2,token)));
		
		
		assertEquals(Integer.valueOf(3), Integer.valueOf(new String(Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0])))));
		assertTrue(Arrays.equals(p1, returned[3]));
    }
    
    @Test
    public void getTestNullPassword() throws Exception{
    	String domain = "facebook";
    	String username = "user1";
    	
    	byte[][] returned = interfacermi.getChallenge(public1, Crypto.signData(private1, public1.getEncoded()));
    	
    	byte[] t = Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
		returned = interfacermi.getChallenge(public1, Crypto.signData(private1, public1.getEncoded()));
    	
    	long currentTime = Time.getTimeLong();

		byte[] d = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
				   Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
		byte[] u = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
				   Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
		t = Crypto.decryptRSA(private1, 
				              Crypto.decodeBase64(returned[0]));
		
		token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
		returned = interfacermi.get(public1, 
									d, 
									u, 
									token,
									Crypto.signData(private1, Crypto.concatenateBytes(d,u,token)));
		
		assertEquals(Integer.valueOf(3), Integer.valueOf(new String(Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0])))));
		assertNull(returned[3]);
    }
    
    @Test
    public void getTestOtherUserPassword() throws Exception{
    	String domain = "facebook";
    	String username = "user1";
    	
    	byte[][] returned = interfacermi.getChallenge(public1, Crypto.signData(private1, public1.getEncoded()));
    	
    	byte[] t = Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
		returned = interfacermi.getChallenge(public1, Crypto.signData(private1, public1.getEncoded()));
    	
    	long currentTime = Time.getTimeLong();

		byte[] d = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
				   Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
		byte[] u = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
				   Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
		t = Crypto.decryptRSA(private1, 
				              Crypto.decodeBase64(returned[0]));
		
		token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
		returned = interfacermi.get(public2, 
									d, 
									u, 
									token,
									Crypto.signData(private1, Crypto.concatenateBytes(d,u,token)));
		
		// Check for the return code 1 (Invalid signature)
		// The attacker can't actually see this message because it is ciphered with 
		// the client's publickey.
		assertEquals(Integer.valueOf(1), Integer.valueOf(new String(Crypto.decryptRSA(private2, Crypto.decodeBase64(returned[0])))));
    }
    
    @Test
    public void getTestRepeatedMessage() throws Exception{
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
    	long currentTime = Time.getTimeLong();

    	// Add a password entry to the user
  		byte[] d1 = Crypto.encodeBase64(
  				    Crypto.encrypt(secretKey, 
  					Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
  		byte[] u1 = Crypto.encodeBase64(
  				    Crypto.encrypt(secretKey, 
  					Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
  		byte[] p1 = Crypto.encodeBase64(
  				    Crypto.encrypt(secretKey, 
  				    Crypto.concatenateBytes(password.getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
  		
    	pm.getUser(public1).addPasswordEntry(new PasswordEntry(d1,u1,p1));
    	
    	// Call get method
    	byte[][] returned = interfacermi.getChallenge(public1, Crypto.signData(private1, public1.getEncoded()));
    	
    	boolean verified = Crypto.verifySignature(pm.getServerPublicKey(), returned[0], returned[1]);
    	assertTrue(verified);
    	
    	byte[] t = Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
		returned = interfacermi.getChallenge(public1, Crypto.signData(private1, public1.getEncoded()));

		byte[] d2 = Crypto.encodeBase64(
				    Crypto.encrypt(secretKey, 
				    Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
		byte[] u2 = Crypto.encodeBase64(
				    Crypto.encrypt(secretKey, 
				    Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
		t = Crypto.decryptRSA(
				   private1, 
				   Crypto.decodeBase64(returned[0]));
		
		token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
		interfacermi.get(public1, 
						 d2, 
						 u2, 
						 token,
						 Crypto.signData(private1, Crypto.concatenateBytes(d2,u2,token)));
		
		returned = interfacermi.get(public1, 
									d2, 
									u2, 
									token,
									Crypto.signData(private1, Crypto.concatenateBytes(d2,u2,token)));
		
		// After get was called two times, the return error the second time should
		// indicate a replay attack, code 2.
		assertEquals(Integer.valueOf(2), Integer.valueOf(new String(Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0])))));
		assertNull(returned[3]);
    }
}
