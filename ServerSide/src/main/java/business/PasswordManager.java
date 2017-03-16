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
	
	public PasswordManager(){
		users = new HashMap<PublicKey, User>();
		try{
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream("src/main/resources/server_keystore.jks"), "serverpass".toCharArray());
			serverPublicKey = ks.getCertificate("serverkeystore").getPublicKey();
			serverPrivateKey = (PrivateKey)ks.getKey("serverkeystore", "serverpass".toCharArray());
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	public void addUser(User user){
		if(users.containsKey(user.getKey())){
			System.out.println("User already exists!");
			return;
		}
		users.put((PublicKey) user.getKey(), user);
		saveData();
	}
	
	public User getUser(Key key){
		return users.get(key);
	}
	
	public void addPasswordEntry(User user, byte[] d, byte[] u, byte[] password) {
		user.addPasswordEntry(new PasswordEntry(d, u, password));
		saveData();
	}
	
	public byte[] getUserPassword(User user, byte[] domain, byte[] username) {
		return user.getPassword(domain, username);
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
	
	@SuppressWarnings("unchecked")
	public void loadData(){
		try{
			FileInputStream fileIn = new FileInputStream("src/main/resources/userData.ser");
			ObjectInputStream in = new ObjectInputStream(fileIn);
			users = (HashMap<PublicKey, User>)in.readObject();
			in.close();
			fileIn.close();
		}catch(FileNotFoundException f){
			System.out.println("User data not found, not loading file...");
		}catch(IOException e){
			e.printStackTrace();
		}catch(ClassNotFoundException c){
	        c.printStackTrace();
		}
	}
	
	public void saveData(){
		try{
			FileOutputStream fileOut = new FileOutputStream("src/main/resources/userData.ser");
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			out.writeObject(users);
			out.close();
			fileOut.close();
		}catch(IOException e){
			e.printStackTrace();
		}
	}


}
