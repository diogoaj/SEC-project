package test.java;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import main.java.Crypto;
import main.java.InterfaceImpl;
import main.java.Token;
import main.java.business.PasswordManager;


public class ServerRegisterTest {
	
	private static InterfaceImpl interfacermi;
	private static PasswordManager pm;
	private static KeyPairGenerator keyGen;

    @BeforeClass
    public static void oneTimeSetUp() throws Exception {
    	keyGen = KeyPairGenerator.getInstance("RSA");
    	keyGen.initialize(2048);
		interfacermi = new InterfaceImpl(new PasswordManager());
		pm = interfacermi.getManager();
    }
    
    @After
    public void tearDown() {
    	pm.getUsers().clear();
    }
    
    @Test
    public void registerSuccess() throws Exception{
    	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publicKey = kp.getPublic();
    	PrivateKey privateKey = kp.getPrivate();

    	byte[][] received = interfacermi.getChallenge(publicKey);
    	
    	boolean verified = Crypto.verifySignature(pm.getServerPublicKey(), received[0], received[1]);
    	assertTrue(verified);
    	
    	byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(received[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
		
    	interfacermi.register(publicKey, token, Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
    	
    	assertTrue(pm.getUsers().size() == 1);
    }
    

    @Test
    public void registerSameUser() throws Exception{
     	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publicKey = kp.getPublic();
    	PrivateKey privateKey = kp.getPrivate();
    
    	for (int i = 0; i < 2; i++){
	    	byte[][] received = interfacermi.getChallenge(publicKey);
	
	    	boolean verified = Crypto.verifySignature(pm.getServerPublicKey(), received[0], received[1]);
	    	assertTrue(verified);
	    	
	    	byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(received[0]));
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
			
	    	interfacermi.register(publicKey, token, Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
    	}
    	
    	assertTrue(pm.getUsers().size() == 1);
    }
    
   
    @Test
    public void registerUserRepeatedMessage() throws Exception{
    	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publicKey = kp.getPublic();
    	PrivateKey privateKey = kp.getPrivate();

    	byte[][] received = interfacermi.getChallenge(publicKey);
    	byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(received[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
		// First register successfull, return code OK
    	byte[][] returned = interfacermi.register(publicKey, token, Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
    	assertEquals(Integer.valueOf(2), Integer.valueOf(new String(Crypto.decryptRSA(privateKey, Crypto.decodeBase64(returned[0])))));
    	
    	// Repeated register, check for the return code of the replay attack
    	returned = interfacermi.register(publicKey, token, Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
    	assertEquals(Integer.valueOf(1), Integer.valueOf(new String(Crypto.decryptRSA(privateKey, Crypto.decodeBase64(returned[0])))));
    }
    
    @Test 
    public void registerOtherUserFail() throws Exception{
    	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publicKey = kp.getPublic();
    	PrivateKey privateKey = kp.getPrivate();
    	
    	kp = keyGen.generateKeyPair();
    	PublicKey publicKeyAttacker = kp.getPublic();
    	PrivateKey privateKeyAttacker = kp.getPrivate();
    	
    	byte[][] received = interfacermi.getChallenge(publicKeyAttacker);
    	
    	boolean verified = Crypto.verifySignature(pm.getServerPublicKey(), received[0], received[1]);
    	assertTrue(verified);
    	
    	byte[] t = Crypto.decryptRSA(privateKeyAttacker, Crypto.decodeBase64(received[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
        byte[][] returned = interfacermi.register(publicKey, token, Crypto.signData(privateKeyAttacker, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
    	
    	assertTrue(pm.getUsers().size() == 0);
    	// Check for the return code 0 (Invalid signature)
    	assertEquals(Integer.valueOf(0), Integer.valueOf(new String(Crypto.decryptRSA(privateKey, Crypto.decodeBase64(returned[0])))));
    }
    
    @Test
    public void registerUserTampered() throws Exception{
    	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publicKey = kp.getPublic();
    	PrivateKey privateKey = kp.getPrivate();
    	
    	kp = keyGen.generateKeyPair();
    	PublicKey publicKeyAttacker = kp.getPublic();
    	
    	
    	byte[][] received = interfacermi.getChallenge(publicKey);
    	
    	boolean verified = Crypto.verifySignature(pm.getServerPublicKey(), received[0], received[1]);
    	assertTrue(verified);
    	
    	byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(received[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(pm.getServerPublicKey(), Token.nextToken(t)));
    	
        byte[][] returned = interfacermi.register(publicKey, token, Crypto.signData(privateKey, Crypto.concatenateBytes(publicKeyAttacker.getEncoded(), token)));
        
        assertTrue(pm.getUsers().size() == 0);
    	// Check for the return code 0 (Invalid signature)
    	assertEquals(Integer.valueOf(0), Integer.valueOf(new String(Crypto.decryptRSA(privateKey, Crypto.decodeBase64(returned[0])))));
    }

}
