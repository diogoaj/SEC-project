package main.java;

import java.rmi.RemoteException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import main.java.business.PasswordManager;
import main.java.business.User;


public class InterfaceImpl implements InterfaceRMI{
	
	private PasswordManager manager;
	private SecureRandom rand = new SecureRandom();
	private Map<Key, Long> tokenMap = new HashMap<Key, Long>();
	
	public InterfaceImpl(PasswordManager manager) throws Exception{
		this.manager = manager;
	}
	
	public PasswordManager getManager(){
		return manager;
	}
	
	public byte[][] getChallenge(Key publicKey){
		long l = rand.nextLong();
		byte[] token = Crypto.encodeBase64(Crypto.encrypt((PublicKey) publicKey, String.valueOf(l).getBytes()));
		tokenMap.put(publicKey, l + 1);
		return Crypto.getByteList(token, Crypto.signData(manager.getServerPrivateKey(), token));
	}
	
	public void register(Key publicKey, byte[] token, byte[] signedData) throws RemoteException {
		if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(publicKey.getEncoded(), token), signedData)){
			byte[] t = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(token));
			long tokenToVerify = Crypto.getLong(t);
			if(tokenToVerify == tokenMap.get(publicKey)){
				tokenMap.put(publicKey, (long) 0);
				User user = new User(publicKey);
				manager.addUser(user);
			}else{
				System.out.println("Invalid Signature!");
			}
		}
		else{
			System.out.println("Token not correct");
		}
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] token, byte[] signedData) throws RemoteException {
		User user = manager.getUser(publicKey);
		if(user != null){
			if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(domain,username,password,token), signedData)){
				byte[] t = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(token));
				long tokenToVerify = Crypto.getLong(t);
				if(tokenToVerify == tokenMap.get(publicKey)){
					manager.addPasswordEntry(user,domain,username,password);
				}
				else{
					System.out.println("Token incorrect!");
				}
			}
			else{
				System.out.println("Signature not correct!");
			}
		}else{
			System.out.println("User does not exist!");
		}
		
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username, byte[] token, byte[] signedData) throws RemoteException {
		User user = manager.getUser(publicKey);
		if(user != null){
			if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(domain,username,token), signedData)){
				byte[] t = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(token));
				long tokenToVerify = Crypto.getLong(t);
				if(tokenToVerify == tokenMap.get(publicKey)){
					return manager.getUserPassword(user,domain,username);
				}
				else{
					System.out.println("Incorrect token");
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
}
