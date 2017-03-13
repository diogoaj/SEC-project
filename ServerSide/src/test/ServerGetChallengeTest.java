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
    public void getChallengeTestSuccess() throws Exception{
    	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publicKey = kp.getPublic();

    	byte[][] token = interfacermi.getChallenge(publicKey);
    	
    	assertTrue(Crypto.verifySignature(pm.getServerPublicKey(), token[0], token[1]));
    }
}
