package test.java;

import static org.junit.Assert.*;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.ToolTipManager;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import main.java.Crypto;
import main.java.InterfaceImpl;
import main.java.Time;
import main.java.Token;
import main.java.business.PasswordManager;
import main.java.business.User;

public class ServerPutTest {
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
    	byte[][] received = interfacermi.getChallenge(public1);
    	byte[] t = Crypto.decryptRSA(private1, Crypto.decodeBase64(received[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	interfacermi.register(public1, token, Crypto.signData(private1, Crypto.concatenateBytes(public1.getEncoded(), token)));
    	
    	// Register user2
    	received = interfacermi.getChallenge(public2);
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
    public void putSuccess() throws Exception{
    	User user1 = pm.getUsers().get(public1);
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
    	byte[][] returned = interfacermi.getChallenge(public1);
    	
    	boolean verified = Crypto.verifySignature(pm.getServerPublicKey(), returned[0], returned[1]);
    	assertTrue(verified);
    	
    	byte[] t = Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
    	returned = interfacermi.getChallenge(public1);

	    long currentTime = Time.getTimeLong();

		byte[] d = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
		byte[] u = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
		byte[] p = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(password.getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
		t = Crypto.decryptRSA(
				   private1, 
				   Crypto.decodeBase64(returned[0]));
		
		
		token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
		interfacermi.put(public1, 
						 d, 
						 u, 
						 p, 
						 token,
						 Crypto.signData(private1, Crypto.concatenateBytes(d,u,p,token)));
		
		assertTrue(Arrays.equals(d, user1.getData().get(0).getDomain()));
		assertTrue(Arrays.equals(u, user1.getData().get(0).getUsername()));
		assertTrue(Arrays.equals(p, user1.getData().get(0).getPassword()));
		assertEquals(user1.getData().size(), 1);
    }
    
    

    @Test
    public void putTestUpdateSuccess() throws Exception{
    	User user1 = pm.getUsers().get(public1);
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
    	byte[][] returned = interfacermi.getChallenge(public1);
    	
    	Crypto.verifySignature(pm.getServerPublicKey(), returned[0], returned[1]);
    	
    	byte[] t = Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
    	returned = interfacermi.getChallenge(public1);

	    long currentTime = Time.getTimeLong();

		byte[] d = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
		byte[] u = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
		byte[] p = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(password.getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
		t = Crypto.decryptRSA(
				   private1, 
				   Crypto.decodeBase64(returned[0]));
		
		
		token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
		interfacermi.put(public1, 
						 d, 
						 u, 
						 p, 
						 token,
						 Crypto.signData(private1, Crypto.concatenateBytes(d,u,p,token)));
		
        returned = interfacermi.getChallenge(public1);
    	
    	Crypto.verifySignature(pm.getServerPublicKey(), returned[0], returned[1]);
    	
    	t = Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0]));
		token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
    	returned = interfacermi.getChallenge(public1);

		d = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
		u = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
		p = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(password.getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
		t = Crypto.decryptRSA(
				   private1, 
				   Crypto.decodeBase64(returned[0]));
		
		assertTrue(Arrays.equals(d, user1.getData().get(0).getDomain()));
		assertTrue(Arrays.equals(u, user1.getData().get(0).getUsername()));
		assertTrue(Arrays.equals(p, user1.getData().get(0).getPassword()));
		assertEquals(user1.getData().size(), 1);
    }
    

    @Test
    public void putTestUserNotExists() throws Exception{
    	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey public3 = kp.getPublic();
    	PrivateKey private3 = kp.getPrivate();
    	
    	User user3 = new User(public3);
    	
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
    	byte[][] returned = interfacermi.getChallenge(public3);
    	
    	Crypto.verifySignature(pm.getServerPublicKey(), returned[0], returned[1]);
    	
    	byte[] t = Crypto.decryptRSA(private3, Crypto.decodeBase64(returned[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
    	returned = interfacermi.getChallenge(public3);

	    long currentTime = Time.getTimeLong();

		byte[] d = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
		byte[] u = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
		byte[] p = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(password.getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
		t = Crypto.decryptRSA(
				   private3, 
				   Crypto.decodeBase64(returned[0]));
		
		
		token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
		interfacermi.put(public3, 
						 d, 
						 u, 
						 p, 
						 token,
						 Crypto.signData(private3, Crypto.concatenateBytes(d,u,p,token)));
		
        returned = interfacermi.getChallenge(public3);
    	
    	Crypto.verifySignature(pm.getServerPublicKey(), returned[0], returned[1]);
    	
    	t = Crypto.decryptRSA(private3, Crypto.decodeBase64(returned[0]));
		token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));

		assertEquals(user3.getData().size(), 0);
		assertEquals(pm.getUsers().size(), 2);
		assertEquals(pm.getUsers().get(public1).getData().size(), 0);
		assertEquals(pm.getUsers().get(public2).getData().size(), 0);
    }
    
    // Testing with same domain, user and password that the byte[] are always different
    @Test 
    public void putTestNoLeak() throws Exception {
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
	    long currentTime = Time.getTimeLong();

		byte[] d1 = Crypto.encodeBase64(
				    Crypto.encrypt(secretKey, 
					Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
		byte[] u1 = Crypto.encodeBase64(
				    Crypto.encrypt(secretKey, 
					Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
		byte[] p1 = Crypto.encodeBase64(
				    Crypto.encrypt(secretKey, 
					Crypto.concatenateBytes(password.getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
		
		currentTime = Time.getTimeLong() + 1;
		
		byte[] d2 = Crypto.encodeBase64(
				    Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
		byte[] u2 = Crypto.encodeBase64(
				    Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
		byte[] p2 = Crypto.encodeBase64(
				    Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(password.getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
		
		assertFalse(Arrays.equals(d1, d2));
		assertFalse(Arrays.equals(u1, u2));
		assertFalse(Arrays.equals(p1, p2));
    }
    
    @Test
    public void putTestOtherUser() throws Exception{
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
    	byte[][] returned = interfacermi.getChallenge(public1);
    	
    	byte[] t = Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
    	returned = interfacermi.getChallenge(public1);

	    long currentTime = Time.getTimeLong();

		byte[] d = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(domain.getBytes(),Time.convertTime(currentTime))));
		byte[] u = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(username.getBytes(),Time.convertTime(currentTime+1))));
		byte[] p = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes(password.getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
		t = Crypto.decryptRSA(
				   private1, 
				   Crypto.decodeBase64(returned[0]));
		
		
		token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
		returned = interfacermi.put(public2, 
								    d, 
								    u, 
								    p, 
								    token,
								    Crypto.signData(private1, Crypto.concatenateBytes(d,u,p,token)));
		
		// Check for the return code 1 (Invalid signature)
		// The attacker can't actually see this message because it is ciphered with 
		// the client's publickey.
    	assertEquals(Integer.valueOf(1), Integer.valueOf(new String(Crypto.decryptRSA(private2, Crypto.decodeBase64(returned[0])))));
    }
    
    
}
