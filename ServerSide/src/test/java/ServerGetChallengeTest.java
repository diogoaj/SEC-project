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
import main.java.business.PasswordManager;


public class ServerGetChallengeTest {
	
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
    public void getChallengeSuccess() throws Exception{
    	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publicKey = kp.getPublic();
    	PrivateKey privateKey = kp.getPrivate();

    	byte[][] bytes = interfacermi.getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
    	
    	assertTrue(Crypto.verifySignature(pm.getServerPublicKey(), bytes[0], bytes[1]));
    }
    
    @Test
    public void getChallengeTampered() throws Exception{
    	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publicKey = kp.getPublic();
    	PrivateKey privateKey = kp.getPrivate();

    	byte[][] bytes = interfacermi.getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
    	
    	byte[] tamperedToken = String.valueOf(110100100).getBytes();
    	
    	assertFalse(Crypto.verifySignature(pm.getServerPublicKey(), tamperedToken, bytes[1]));
    }
}
