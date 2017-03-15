package test.java;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.Test;

import main.java.API;

public class InitTest{
	
	private PublicKey serverKey;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private KeyStore keyStore;
	/*
	@Test
	public void InitTestSuccess() throws Exception {
		API library = new API();
		KeyStore ks = KeyStore.getInstance("JKS");
    	library.init(ks, "0", "banana");
    	
    	CertificateFactory f = CertificateFactory.getInstance("X.509");
    	X509Certificate certificate = (X509Certificate)f.generateCertificate(new FileInputStream("src/main/resources/server.cer"));
    	serverKey = certificate.getPublicKey();
    	privateKey = (PrivateKey)keyStore.getKey("clientkeystore", "pass".toCharArray());
    	publicKey = keyStore.getCertificate("clientkeystore").getPublicKey();
    	    	
    	assertEquals(serverKey, library.getServerPublicKey());
    	assertEquals(publicKey, library.getPublicKey());
    	assertEquals(privateKey, library.getPrivateKey());

	}
	
	
	@Test(expected = Exception.class)
    public void InitFail1Test() throws Exception{
    	API library = new API();
    	KeyStore ks = KeyStore.getInstance("JKS");
    	library.init(ks, "999", "banana");
    }
    
    @Test(expected = Exception.class)
    public void InitFail2Test() throws Exception{
    	API library = new API();
    	KeyStore ks = KeyStore.getInstance("JKS");
    	library.init(ks, "0", "apple");
    }
    */
}