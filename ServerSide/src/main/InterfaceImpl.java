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
	private PublicKey serverPublicKey;
	private PrivateKey serverPrivateKey;
	
	public InterfaceImpl(PasswordManager manager) throws Exception{
		this.manager = manager;
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream("./server_keystore.jks"), "serverpass".toCharArray());
		serverPublicKey = ks.getCertificate("serverkeystore").getPublicKey();
		serverPrivateKey = (PrivateKey)ks.getKey("serverkeystore", "serverpass".toCharArray());
	}
	
	public PasswordManager getManager(){
		return manager;
	}
	
	public void register(Key publicKey, byte[] timestamp, byte[] signedData) throws RemoteException {
		if(verifySignature((PublicKey) publicKey, Crypto.concatenateBytes("Integrity".getBytes(), timestamp), signedData)){
			byte[] t = Crypto.decrypt(serverPrivateKey, Crypto.decodeBase64(timestamp));
			long receivedTime = Crypto.decodeTime(t);
			if(Crypto.withinTime(receivedTime)){
				User user = new User(publicKey);
				manager.addUser(user);
			}
			else{
				System.out.println("Replay attack incoming");
			}
		}
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] timestamp, byte[] signedData) throws RemoteException {
		
		User user = null;
		for (User u: manager.getUsers()){
			if(publicKey.equals(u.getKey())){
				user = u;
				break;
			}
		}
		if(user != null){
			if(verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(domain,username,password,timestamp), signedData)){
				byte[] t = Crypto.decrypt(serverPrivateKey, Crypto.decodeBase64(timestamp));
				long receivedTime = Crypto.decodeTime(t);
				byte[] d = Crypto.decrypt(serverPrivateKey, Crypto.decodeBase64(domain));
				byte[] u = Crypto.decrypt(serverPrivateKey, Crypto.decodeBase64(username));
				if(Crypto.withinTime(receivedTime)){
					user.addPasswordEntry(new PasswordEntry(d, u, password));
				}
				else{
					System.out.println("Replay attack incoming");
				}
			}
		}else{
			System.out.println("User does not exist!");
		}
		
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username, byte[] timestamp, byte[] signedData) throws RemoteException {
		User user = null;
		for (User u: manager.getUsers()){
			if(publicKey.equals(u.getKey())){
				user = u;
				break;
			}
		}
		if(user != null){
			if(verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(domain,username, timestamp), signedData)){
				byte[] t = Crypto.decrypt(serverPrivateKey, Crypto.decodeBase64(timestamp));
				long receivedTime = Crypto.decodeTime(t);
				byte[] d = Crypto.decrypt(serverPrivateKey, Crypto.decodeBase64(domain));
				byte[] u = Crypto.decrypt(serverPrivateKey, Crypto.decodeBase64(username));
				if(Crypto.withinTime(receivedTime)){
					return user.getPassword(d, u);
				}
				else{
					System.out.println("Replay attack incoming");
					return null;
				}
			}
			else{
				return null;
			}
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
