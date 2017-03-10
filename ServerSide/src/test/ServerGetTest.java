package test;

import static org.junit.Assert.assertTrue;

import java.security.Key;
import java.security.KeyPairGenerator;
import java.util.Arrays;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import main.InterfaceImpl;
import main.business.PasswordManager;
import main.business.User;

public class ServerGetTest {
	private static InterfaceImpl interfacermi;
	private static PasswordManager pm;

    @BeforeClass
    public static void oneTimeSetUp() throws Exception {
    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		interfacermi = new InterfaceImpl(new PasswordManager());
		pm = interfacermi.getManager();
		
		keyGen.initialize(512);
    	Key k = keyGen.genKeyPair().getPublic();
    	Key k2 = keyGen.generateKeyPair().getPublic();

		interfacermi.register(k, null);
		interfacermi.register(k2, null);
    }
    
    @After
    public void tearDown() {
    	pm.getUsers().get(0).getData().clear();
    	pm.getUsers().get(1).getData().clear();
    }
    
    @Test
    public void getTestSuccess() throws Exception{
    	User user1 = pm.getUsers().get(0);
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
    	interfacermi.put(user1.getKey(), domain.getBytes(), username.getBytes(), password.getBytes(), null);
    	
    	byte[] pwd = interfacermi.get(user1.getKey(), domain.getBytes(), username.getBytes(), null);
    	
    	assertTrue(Arrays.equals(password.getBytes(), pwd));
    	assertTrue(new String(pwd).equals(password));
    }
}
