package main;

import java.io.FileInputStream;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyStore;;

public class API {

	private KeyStore keyStore;
	private String password;
	private InterfaceRMI stub;
	
	public void init(KeyStore key, String id, String pass){
		keyStore = key;
		password = pass;
				
		try{
			keyStore.load(new FileInputStream("./keystore_" + id +".jks"), password.toCharArray());
			Registry registry = LocateRegistry.getRegistry(8000);
	    	stub = (InterfaceRMI) registry.lookup("Interface");
		}
		catch (Exception e) {
        	System.err.println("Client exception: " + e.toString());
        	e.printStackTrace();
    	}
	}
	
	public void register_user(){
		
	}
	
	public void save_password(byte[] domain, byte[] username, byte[] password){
		
	}
	
	public byte[] retrieve_password(byte[] domain, byte[] username){
		return "dummy".getBytes();
	}
	
	public void close(){
		System.exit(0);
	}
	
}
