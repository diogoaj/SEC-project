package main;

import java.io.FileInputStream;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class API {

	private KeyStore keyStore;
	private String password;
	private InterfaceRMI stub;
	private PublicKey serverKey;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	
	public void init(KeyStore key, String id, String pass){
		keyStore = key;
		password = pass;
				
		try{
			keyStore.load(new FileInputStream("./keystore_" + id +".jks"), password.toCharArray());
			Registry registry = LocateRegistry.getRegistry(8000);
	    	stub = (InterfaceRMI) registry.lookup("Interface");
	    	
	    	CertificateFactory f = CertificateFactory.getInstance("X.509");
	    	X509Certificate certificate = (X509Certificate)f.generateCertificate(new FileInputStream("server.cer"));
	    	serverKey = certificate.getPublicKey();
	    	
	    	privateKey = (PrivateKey)keyStore.getKey("clientkeystore", password.toCharArray());
	    	publicKey = keyStore.getCertificate("clientkeystore").getPublicKey();
		}
		catch (Exception e) {
        	System.err.println("Client exception: " + e.toString());
        	e.printStackTrace();
    	}
	}
	
	public void register_user(){
		try{
			byte[] t = Crypto.encodeBase64(Crypto.encrypt(serverKey, Crypto.getTime()));
			
			stub.register(publicKey, t, signData(Crypto.concatenateBytes("Integrity".getBytes(), t)));
		}
		catch(Exception e){
			System.err.println("Register user exception: " + e.toString());
        	e.printStackTrace();
		}
	}
	
	//FIXME MISSING INTEGRITY
	public void save_password(byte[] domain, byte[] username, byte[] password){
		try{
			byte[] d = Crypto.encodeBase64(Crypto.encrypt(serverKey, domain));
			byte[] u = Crypto.encodeBase64(Crypto.encrypt(serverKey, username));
			byte[] p = Crypto.encodeBase64(Crypto.encrypt(publicKey, password));
			byte[] t = Crypto.encodeBase64(Crypto.encrypt(serverKey, Crypto.getTime()));
		
			stub.put(publicKey, d, u, p, t, signData(Crypto.concatenateBytes(d,u,p,t)));
		}
		catch(Exception e){
			System.err.println("Save password exception: " + e.toString());
        	e.printStackTrace();
		}
	}
	
	public byte[] retrieve_password(byte[] domain, byte[] username){
		try{
			byte[] d = Crypto.encodeBase64(Crypto.encrypt(serverKey, domain));
			byte[] u = Crypto.encodeBase64(Crypto.encrypt(serverKey, username));
			byte[] t = Crypto.encodeBase64(Crypto.encrypt(serverKey, Crypto.getTime()));
			byte[] password = stub.get(publicKey, d, u, t, signData(Crypto.concatenateBytes(d,u,t)));
			if(password != null){
				return Crypto.decrypt(privateKey, Crypto.decodeBase64(password));
			}
			else{
				return null;
			}
		}
		catch(Exception e){
			System.err.println("Retrieve password exception: " + e.toString());
        	e.printStackTrace();
		}
		return null;
	}
	
	public void close(){
		System.exit(0);
	}
	
	private byte[] signData(byte[] data){
		try{
			// generating a signature
			Signature dsaForSign = Signature.getInstance("SHA1withRSA");
			dsaForSign.initSign(privateKey);
			dsaForSign.update(data);
			return dsaForSign.sign();
		}
		catch(Exception e){
			System.err.println("Signature exception: " + e.toString());
        	e.printStackTrace();
		}
		return null;
	}	
}
