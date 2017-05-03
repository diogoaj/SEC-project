package test.java;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
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
import main.java.business.User;

public class ServerHighestTimestampTest {
	private static InterfaceImpl interfacermi;
	private static PasswordManager pm;
	
	private static KeyPairGenerator keyGen;
	private static KeyGenerator keyGenSecret;
	
	private static PublicKey public1; 
	private static PrivateKey private1;

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
    
		keyGenSecret = KeyGenerator.getInstance("AES");
    	keyGenSecret.init(128); 
    	secretKey = keyGenSecret.generateKey();
		
    	// Register user1
    	byte[][] received = interfacermi.getChallenge(public1, Crypto.signData(private1, public1.getEncoded()));
    	byte[] t = Crypto.decryptRSA(private1, Crypto.decodeBase64(received[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	received = interfacermi.register(public1, token, Crypto.signData(private1, Crypto.concatenateBytes(public1.getEncoded(), token)));
    }
    
    @After
    public void tearDown() {
    	pm.getUsers().get(public1).getData().clear();
    }
    
    @Test
    public void getTimestampSuccess(){
    	User u = pm.getUser(public1);
    	
    	pm.addPasswordEntry(u, 
    			            "user1".getBytes(),
    						"sec".getBytes(), 
    						"123".getBytes(), 
    						String.valueOf(0).getBytes());
    	
    	
    	pm.addPasswordEntry(u, 
				            "user2".getBytes(),
							"sec1".getBytes(), 
							"1231".getBytes(), 
							String.valueOf(1).getBytes());
    	
    	pm.addPasswordEntry(u, 
				            "user3".getBytes(),
							"sec2".getBytes(), 
							"1232".getBytes(), 
							String.valueOf(2).getBytes());
    	
    	byte[][] returned = interfacermi.getChallenge(public1, Crypto.signData(private1, public1.getEncoded()));
    	
    	byte[] t = Crypto.decryptRSA(private1, Crypto.decodeBase64(returned[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
		
		returned = interfacermi.getHighestTimestamp(public1, token, Crypto.signData(private1, Crypto.concatenateBytes(public1.getEncoded(), token)));
		
		ArrayList<byte[]> wtsList = new ArrayList<byte[]>();
		
		int size = returned.length;
		
		assertEquals(6, size);
		
		for (int i = 3; i < size; i++){
			wtsList.add(returned[i]);
		}
		
		for (int i = 0; i < wtsList.size(); i++){			
			assertEquals(String.valueOf(i), new String(wtsList.get(i)));
		}
    }
}
