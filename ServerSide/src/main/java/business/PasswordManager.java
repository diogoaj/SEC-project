package main.java.business;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class PasswordManager {
	
	private Map<PublicKey, User> users;
	private PublicKey serverPublicKey;
	private PrivateKey serverPrivateKey;
	
	public PasswordManager(int id){
		users = new HashMap<PublicKey, User>();
		try{
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream("src/main/resources/keystore_"+id+".jks"), "server".toCharArray());
			serverPublicKey = ks.getCertificate("serverkeystore").getPublicKey();
			serverPrivateKey = (PrivateKey)ks.getKey("serverkeystore", "server".toCharArray());
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	public synchronized boolean addUser(User user) {
		if(users.containsKey(user.getKey())){
			System.out.println("User already exists!");
			return false;
		}
		users.put((PublicKey) user.getKey(), user);
		return true;
	}
	
	public synchronized User getUser(Key key){
		return users.get(key);
	}
	
	public synchronized void addPasswordEntry(User user, byte[] d, byte[] u, byte[] password, byte[] wts) {
		user.addPasswordEntry(new PasswordEntry(d, u, password, wts));
	}
	
	public synchronized byte[] getUserPassword(User user, byte[] domain, byte[] username) {
		return user.getPassword(domain, username);
	}
	
	public synchronized byte[] getUserWts(User user, byte[] domain, byte[] username) {
		return user.getWts(domain, username);
	}
	
	public HashMap<PublicKey, User> getUsers(){
		return (HashMap<PublicKey, User>) users;
	}
	
	public PublicKey getServerPublicKey(){
		return serverPublicKey;
	}
	
	public PrivateKey getServerPrivateKey(){
		return serverPrivateKey;
	}
}
