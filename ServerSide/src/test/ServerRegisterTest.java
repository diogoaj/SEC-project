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
    public void registerTestSuccess() throws Exception{
    	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publickey = kp.getPublic();
    	PrivateKey privatekey = kp.getPrivate();
    	
    	byte[] t = Crypto.encodeBase64(Crypto.encrypt(pm.getServerPublicKey(), Crypto.getTime()));
		
		interfacermi.register(publickey, 
				      		  t, 
				              Crypto.signData(privatekey, Crypto.concatenateBytes("Integrity".getBytes(), t)));
    	
    	assertTrue(pm.getUsers().size() == 1);
    }
    

    @Test
    public void registerTestSameUser() throws Exception{
     	KeyPair kp = keyGen.generateKeyPair();
    	PublicKey publickey = kp.getPublic();
    	PrivateKey privatekey = kp.getPrivate();

    	byte[] t = Crypto.encodeBase64(Crypto.encrypt(pm.getServerPublicKey(), Crypto.getTime()));
		
		interfacermi.register(publickey, 
				      		  t, 
				              Crypto.signData(privatekey, Crypto.concatenateBytes("Integrity".getBytes(), t)));
		
		t = Crypto.encodeBase64(Crypto.encrypt(pm.getServerPublicKey(), Crypto.getTime()));
		interfacermi.register(publickey, 
	      		  t, 
	              Crypto.signData(privatekey, Crypto.concatenateBytes("Integrity".getBytes(), t)));
    
    	assertTrue(pm.getUsers().size() == 1);
    }
    
    @Test 
    public void registerOtherUserFail() throws Exception{
    	KeyPair kp1 = keyGen.generateKeyPair();
    	PrivateKey privatekey1 = kp1.getPrivate();
    	
    	KeyPair kp2 = keyGen.generateKeyPair();
    	PublicKey publickey2 = kp2.getPublic();
    	
    	byte[] t = Crypto.encodeBase64(Crypto.encrypt(pm.getServerPublicKey(), Crypto.getTime()));
		
		interfacermi.register(publickey2, 
				      		  t, 
				              Crypto.signData(privatekey1, Crypto.concatenateBytes("Integrity".getBytes(), t)));
		
		assertTrue(pm.getUsers().size() == 0);
    }

}
