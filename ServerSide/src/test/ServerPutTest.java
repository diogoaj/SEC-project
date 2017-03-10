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

public class ServerPutTest {
	private static InterfaceImpl interfacermi;
	private static PasswordManager pm;
	private static KeyPairGenerator keyGen;

    @BeforeClass
    public static void oneTimeSetUp() throws Exception {
    	keyGen = KeyPairGenerator.getInstance("RSA");
		interfacermi = new InterfaceImpl(new PasswordManager());
		pm = interfacermi.getManager();
		
		keyGen.initialize(512);
    	Key k = keyGen.genKeyPair().getPublic();
    	Key k2 = keyGen.generateKeyPair().getPublic();

		interfacermi.register(k, null, null);
		interfacermi.register(k2, null, null);
    }
    
    @After
    public void tearDown() {
    	pm.getUsers().get(0).getData().clear();
    	pm.getUsers().get(1).getData().clear();
    }
    
    @Test
    public void putTestSuccess() throws Exception{
    	User user1 = pm.getUsers().get(0);
    	String domain = "facebook";
    	String username = "user1";
    	String password = "123123";
    	
    	interfacermi.put(user1.getKey(), domain.getBytes(), username.getBytes(), password.getBytes(), null, null);
    	
    	assertTrue(user1.getData().size() == 1);
    	assertTrue(Arrays.equals(user1.getData().get(0).getDomain(), domain.getBytes()));
    	assertTrue(Arrays.equals(user1.getData().get(0).getUsername(), username.getBytes()));
    	assertTrue(Arrays.equals(user1.getData().get(0).getPassword(), password.getBytes()));
    	assertTrue(new String(user1.getData().get(0).getPassword()).equals(password));
    }
    
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
    	
    }
    
    

}
