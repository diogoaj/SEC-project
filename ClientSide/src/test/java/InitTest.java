package test.java;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.BeforeClass;
import org.junit.Test;

import main.java.API;

public class InitTest{
	
	private static PublicKey serverKey;
	private static PublicKey publicKey;
	private static PrivateKey privateKey;
	private static KeyStore keyStore;
	
	@BeforeClass
    public static void oneTimeSetUp() throws Exception {
		CertificateFactory f = CertificateFactory.getInstance("X.509");
    	X509Certificate certificate = (X509Certificate)f.generateCertificate(new FileInputStream("src/main/resources/server.cer"));
    	serverKey = certificate.getPublicKey();
    	
    	keyStore = KeyStore.getInstance("JKS");
    	keyStore.load(new FileInputStream("src/main/resources/keystore_" + "0" +".jks"), "banana".toCharArray());
    	
    	privateKey = (PrivateKey)keyStore.getKey("clientkeystore", "banana".toCharArray());
    	publicKey = keyStore.getCertificate("clientkeystore").getPublicKey();
    }
	
	@Test
	public void InitTestSuccess() throws Exception {
		API library = new API();
		KeyStore ks = KeyStore.getInstance("JKS");
    	library.init(ks, "0", "banana");
    	   	
    	assertEquals(serverKey, library.getServerPublicKey());
    	assertEquals(publicKey, library.getPublicKey());
    	assertEquals(privateKey, library.getPrivateKey());
	}
	
	@Test
	public void InitTestFail() throws Exception {
		API library = new API();
		KeyStore ks = KeyStore.getInstance("JKS");
    	library.init(ks, "99999", "banana");
    	   
    	assertNull(library.getServerPublicKey());
    	assertNull(library.getPublicKey());
    	assertNull(library.getPrivateKey());
	}

}