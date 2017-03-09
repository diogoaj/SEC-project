package main;

import java.io.FileInputStream;
import java.rmi.RemoteException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import main.business.PasswordEntry;
import main.business.PasswordManager;
import main.business.User;


public class InterfaceImpl implements InterfaceRMI{
	
	private PasswordManager manager;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	
	public InterfaceImpl(PasswordManager manager) throws Exception{
		this.manager = manager;
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream("./server_keystore.jks"), "serverpass".toCharArray());
		publicKey = ks.getCertificate("serverkeystore").getPublicKey();
		privateKey = (PrivateKey)ks.getKey("serverkeystore", "serverpass".toCharArray());
	}
	
	public PasswordManager getManager(){
		return manager;
	}
	
	public void register(Key publicKey, byte[] signedData) throws RemoteException {
		if(verifySignature((PublicKey) publicKey, "Integrity".getBytes(), signedData)){
			User user = new User(publicKey);
			manager.addUser(user);
		}
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		
		User user = null;
		for (User u: manager.getUsers()){
			if(publicKey.equals(u.getKey())){
				user = u;
				break;
			}
		}
		if(user != null){
			byte[] d = Crypto.decrypt(privateKey, Crypto.decodeBase64(domain));
			byte[] u = Crypto.decrypt(privateKey, Crypto.decodeBase64(username));
			user.addPasswordEntry(new PasswordEntry(d, u, password));
		}else{
			System.out.println("User does not exist!");
		}
		
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		User user = null;
		for (User u: manager.getUsers()){
			if(publicKey.equals(u.getKey())){
				user = u;
				break;
			}
		}
		if(user != null){
			byte[] d = Crypto.decrypt(privateKey, Crypto.decodeBase64(domain));
			byte[] u = Crypto.decrypt(privateKey, Crypto.decodeBase64(username));
			return user.getPassword(d, u);
		}else{
			System.out.println("User does not exist!");
			return null;
		}
	}
	
	private boolean verifySignature(PublicKey publicKey, byte[] data, byte[] signature){
		try{
			Signature dsaForVerify = Signature.getInstance("SHA1withRSA");
			dsaForVerify.initVerify(publicKey);
			dsaForVerify.update(data);
			return dsaForVerify.verify(signature);
		}
		catch(Exception e){
			System.err.println("Retrieve password exception: " + e.toString());
        	e.printStackTrace();
		}
		return false;
	}

}
