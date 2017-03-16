package test.java;

import static org.junit.Assert.assertTrue;

import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import main.java.Crypto;
import main.java.InterfaceImpl;
import main.java.Token;
import main.java.business.PasswordManager;
import main.java.business.User;

public class ServerPutTest {
	private static InterfaceImpl interfacermi;
	private static PasswordManager pm;
	private static KeyPairGenerator keyGen;

    @BeforeClass
    public static void oneTimeSetUp() throws Exception {
    	keyGen = KeyPairGenerator.getInstance("RSA");
		interfacermi = new InterfaceImpl(new PasswordManager());
		pm = interfacermi.getManager();
		
		// Generate two keypairs
		keyGen.initialize(2048);
    	PublicKey public1 = keyGen.genKeyPair().getPublic();
    	PrivateKey private1 = keyGen.genKeyPair().getPrivate();
    	
    	PublicKey public2 = keyGen.genKeyPair().getPublic();
    	PrivateKey private2 = keyGen.genKeyPair().getPrivate();
    	
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
    	pm.getUsers().get(0).getData().clear();
    	pm.getUsers().get(1).getData().clear();
    }
    
    @Test
    public void putSuccess() throws Exception{
    	User user1 = pm.getUsers().get(0);
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
    	byte[][] returned = interfacermi.getChallenge(user1.getKey());
    	
    	interfacermi.put(user1.getKey(), domain.getBytes(), username.getBytes(), password.getBytes(), null, null);
    	
    	assertTrue(user1.getData().size() == 1);
    	assertTrue(Arrays.equals(user1.getData().get(0).getDomain(), domain.getBytes()));
    	assertTrue(Arrays.equals(user1.getData().get(0).getUsername(), username.getBytes()));
    	assertTrue(Arrays.equals(user1.getData().get(0).getPassword(), password.getBytes()));
    	assertTrue(new String(user1.getData().get(0).getPassword()).equals(password));
    }
    
    /*
    @Test
    public void putTestSuccess2() throws Exception{
    	User user1 = pm.getUsers().get(0);
    	User user2 = pm.getUsers().get(1);
    	String domain = "facebook";
    	String username = "user1";
    	String username2 = "user2";
    	String password = "123123";
    	
    	interfacermi.put(user1.getKey(), domain.getBytes(), username.getBytes(), password.getBytes(), null, null);
    	interfacermi.put(user2.getKey(), domain.getBytes(), username.getBytes(), password.getBytes(), null, null);
    	interfacermi.put(user2.getKey(), domain.getBytes(), username2.getBytes(), password.getBytes(), null, null);
    	
    	assertTrue(user1.getData().size() == 1);
    	assertTrue(user2.getData().size() == 2);
    }
    
    @Test
    public void putTestUpdateSuccess() throws Exception{
    	User user1 = pm.getUsers().get(0);
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
    	interfacermi.put(user1.getKey(), domain.getBytes(), username.getBytes(), password.getBytes(), null, null);
    	
    	password = "strongerpassword";
    	interfacermi.put(user1.getKey(), domain.getBytes(), username.getBytes(), password.getBytes(), null, null);
    	
    	assertTrue(user1.getData().size() == 1);
    }
    
    @Test
    public void putTestUserNotExists() throws Exception{
    	User user1 = new User(keyGen.genKeyPair().getPublic());
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
    	interfacermi.put(user1.getKey(), domain.getBytes(), username.getBytes(), password.getBytes(), null, null);
    	
    	assertTrue(pm.getUsers().size() == 2);
    	assertTrue(user1.getData().size() == 0);
    	
    }*/
    
    

}
