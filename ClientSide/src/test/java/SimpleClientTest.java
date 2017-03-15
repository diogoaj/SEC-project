package test.java;

import static org.junit.Assert.*;

import java.security.KeyStore;

import org.junit.BeforeClass;
import org.junit.Test;

import main.java.API;

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
		
		assertEquals(pw, "pass1".getBytes());
	}
	/*
	@Test(expected = Exception.class)
	public void SimpleClientWrong1Test() throws Exception{
		library.register_user();
		library.save_password("facebook".getBytes(), "Fernando".getBytes(), "Pessoa".getBytes());
		byte[] pw = library.retrieve_password("tecnico".getBytes(), "Fernando".getBytes());
	}
	
	@Test(expected = Exception.class)
	public void SimpleClientWrong2Test() throws Exception{
		library.register_user();
		library.save_password("facebook".getBytes(), "Fernando".getBytes(), "Pessoa".getBytes());
		byte[] pw = library.retrieve_password("facebook".getBytes(), "Alberto".getBytes());
	}
	*/
}