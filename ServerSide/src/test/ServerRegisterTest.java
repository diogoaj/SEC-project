package test;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import main.Crypto;
import main.InterfaceImpl;
import main.business.PasswordManager;


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
    	byte[] t = Crypto.decrypt(privateKey, Crypto.decodeBase64(received[0]));
    	
		byte[] token = Crypto.encodeBase64(Crypto.encrypt(pm.getServerPublicKey(), Crypto.nextToken(t)));
		
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
	    	byte[] t = Crypto.decrypt(privateKey, Crypto.decodeBase64(received[0]));
	    	
			byte[] token = Crypto.encodeBase64(Crypto.encrypt(pm.getServerPublicKey(), Crypto.nextToken(t)));
			
	    	interfacermi.register(publicKey, token, Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
    	}
    	
    	assertTrue(pm.getUsers().size() == 1);
    }
    
    /*
    @Test 
    public void registerUserRepeatedMessage() throws Exception{
    	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publicKey = kp.getPublic();
    	PrivateKey privateKey = kp.getPrivate();

    	byte[][] received = interfacermi.getChallenge(publicKey);
    	byte[] t = Crypto.decrypt(privateKey, Crypto.decodeBase64(received[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encrypt(pm.getServerPublicKey(), Crypto.nextToken(t)));
    	
    	interfacermi.register(publicKey, token, Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
    	
    	// Replay attack should not be possible
    	interfacermi.register(publicKey, token, Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
    }*/
    
    @Test 
    public void registerOtherUserFail() throws Exception{
    	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publicKey = kp.getPublic();
    	
    	kp = keyGen.generateKeyPair();
    	PublicKey publicKeyAttacker = kp.getPublic();
    	PrivateKey privateKeyAttacker = kp.getPrivate();
    	
    	byte[][] received = interfacermi.getChallenge(publicKeyAttacker);
    	byte[] t = Crypto.decrypt(privateKeyAttacker, Crypto.decodeBase64(received[0]));
		byte[] token = Crypto.encodeBase64(Crypto.encrypt(pm.getServerPublicKey(), Crypto.nextToken(t)));
    	
    	interfacermi.register(publicKey, token, Crypto.signData(privateKeyAttacker, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
    	
    	assertTrue(pm.getUsers().size() == 0);
    }

}
