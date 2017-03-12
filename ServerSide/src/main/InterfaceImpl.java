package main;

import java.rmi.RemoteException;
import java.security.Key;
import java.security.PublicKey;
import main.business.PasswordEntry;
import main.business.PasswordManager;
import main.business.User;


public class InterfaceImpl implements InterfaceRMI{
	
	private PasswordManager manager;
	
	public InterfaceImpl(PasswordManager manager) throws Exception{
		this.manager = manager;
	}
	
	public PasswordManager getManager(){
		return manager;
	}
	
	public void register(Key publicKey, byte[] timestamp, byte[] signedData) throws RemoteException {
		if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes("Integrity".getBytes(), timestamp), signedData)){
			byte[] t = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(timestamp));
			long receivedTime = Crypto.decodeTime(t);
			if(Crypto.withinTime(receivedTime)){
				User user = new User(publicKey);
				manager.addUser(user);
			}
			else{
				System.out.println("Replay attack detected!");
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
			if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(domain,username,password,timestamp), signedData)){
				byte[] t = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(timestamp));
				long receivedTime = Crypto.decodeTime(t);
				byte[] d = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(domain));
				byte[] u = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(username));
				if(Crypto.withinTime(receivedTime)){
					manager.addPasswordEntry(user,d,u,password);
				}
				else{
					System.out.println("Replay attack detected!");
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
			if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(domain,username, timestamp), signedData)){
				byte[] t = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(timestamp));
				long receivedTime = Crypto.decodeTime(t);
				byte[] d = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(domain));
				byte[] u = Crypto.decrypt(manager.getServerPrivateKey(), Crypto.decodeBase64(username));
				if(Crypto.withinTime(receivedTime)){
					return user.getPassword(d, u);
				}
				else{
					System.out.println("Replay attack detected!");
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
