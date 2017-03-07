package test;

import static org.junit.Assert.assertTrue;

import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import main.InterfaceImpl;
import main.business.PasswordManager;


public class ServerRegisterTest {
	
	private static InterfaceImpl interfacermi;
	private static PasswordManager pm;
	private static KeyPairGenerator keyGen;

    @BeforeClass
    public static void oneTimeSetUp() throws Exception {
    	keyGen = KeyPairGenerator.getInstance("RSA");
		interfacermi = new InterfaceImpl(new PasswordManager());
		pm = interfacermi.getManager();
    }
    
    @After
    public void tearDown() {
    	pm.getUsers().clear();
    }
    
    @Test
    public void registerTestSuccess() throws Exception{
    	keyGen.initialize(512);
    	Key k = keyGen.genKeyPair().getPublic();
    	interfacermi.register(k);
    	
    	assertTrue(pm.getUsers().size() == 1);
    }
    
    @Test
    public void registerTestSameUser() throws Exception{
    	keyGen.initialize(512);
    	Key k = keyGen.genKeyPair().getPublic();
    	interfacermi.register(k);	
    	interfacermi.register(k);
    	assertTrue(pm.getUsers().size() == 1);
    }

}
