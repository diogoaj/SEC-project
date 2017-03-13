package main;

import java.rmi.RemoteException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.security.Key;
import java.security.PublicKey;
import main.business.PasswordManager;
import main.business.User;


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

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] signedData) throws RemoteException {
		
		User user = null;
		for (User u: manager.getUsers()){
			if(publicKey.equals(u.getKey())){
				user = u;
				break;
			}
		}
		if(user != null){
			if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(domain,username,password), signedData)){
				byte[] d = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(domain));
				byte[] u = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(username));
				manager.addPasswordEntry(user,d,u,password);
			}
		}else{
			System.out.println("User does not exist!");
		}
		
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username, byte[] signedData) throws RemoteException {
		User user = null;
		for (User u: manager.getUsers()){
			if(publicKey.equals(u.getKey())){
				user = u;
				break;
			}
		}
		if(user != null){
			if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(domain,username), signedData)){
				byte[] d = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(domain));
				byte[] u = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(username));
				return user.getPassword(d, u);
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
