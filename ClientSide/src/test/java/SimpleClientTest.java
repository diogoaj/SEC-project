package test.java;

import static org.junit.Assert.*;

import java.security.KeyStore;
import java.util.Arrays;

import org.junit.BeforeClass;
import org.junit.Test;

import main.java.API;
import main.java.Crypto;

public class SimpleClientTest{
	private static API library;
	private static KeyStore ks;
	
	@BeforeClass
	public static void oneTimeSetUp() throws Exception {
		library = new API();
		ks = KeyStore.getInstance("JKS");
		library.init(ks, "0", "banana");
	}
	
	@Test
	public void SimpleClientTestSuccess() throws Exception{
		library.register_user();
		library.save_password("facebook".getBytes(), "user1".getBytes(), "pass1".getBytes());
		byte[] pw = library.retrieve_password("facebook".getBytes(), "user1".getBytes());

		String pass = new String(pw);
		pass = pass.split("\\|\\|")[0];
		assertEquals(pass, "pass1");
	}
	
	@Test
	public void SimpleClientWrongRetrieve1() throws Exception{
		library.register_user();
		byte[] pw = library.retrieve_password("tecnico".getBytes(), "Fernando".getBytes());
		assertNull(pw);
	}
	
	@Test
	public void SimpleClientWrongRetrieve2() throws Exception{
		library.register_user();
		byte[] pw = library.retrieve_password("facebook".getBytes(), "Alberto".getBytes());
		assertNull(pw);
	}
	
	@Test
	public void savePasswordSuccess(){
		library.register_user();
		int value = library.save_password("facebook".getBytes(), "user1".getBytes(), "pass1".getBytes());
		assertEquals(value, 3);
	}
}