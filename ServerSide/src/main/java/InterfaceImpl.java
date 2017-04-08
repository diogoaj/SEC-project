package main.java;

import java.rmi.RemoteException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.security.Key;
import java.security.PublicKey;
import main.java.business.PasswordManager;
import main.java.business.User;


public class InterfaceImpl implements InterfaceRMI{
	
	private PasswordManager manager;
	private SecureRandom rand = new SecureRandom();
	private Map<Key, Long> tokenMap = new ConcurrentHashMap<Key, Long>();
	
	public InterfaceImpl(PasswordManager manager) throws Exception{
		this.manager = manager;
	}
	
	public PasswordManager getManager(){
		return manager;
	}
	
	public byte[][] getChallenge(Key publicKey, byte[] signedData){
		if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(publicKey.getEncoded()), signedData)){
			long l = rand.nextLong();
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA((PublicKey) publicKey, String.valueOf(l).getBytes()));
			tokenMap.put(publicKey, l + 1);
			return Token.getByteList(token, Crypto.signData(manager.getServerPrivateKey(), token));
		}
		else{
			System.out.println("Signature failed");
			return null;
		}
	}
	
	public byte[][] register(Key publicKey, byte[] token, byte[] signedData) throws RemoteException {
		byte[] t = Crypto.decryptRSA(manager.getServerPrivateKey(), Crypto.decodeBase64(token));
		long tokenToVerify = Time.getLong(t);
		if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(publicKey.getEncoded(), token), signedData)){
			if(tokenToVerify == tokenMap.get(publicKey)){
				tokenMap.put(publicKey, (long) 0);
				User user = new User(publicKey);
				boolean added = manager.addUser(user);
				if(added)
					return dataToSend(publicKey, 3, tokenToVerify+1, null);
				else
					return dataToSend(publicKey, 2, tokenToVerify+1, null);
			}else{
				System.out.println("Token not correct");
				return dataToSend(publicKey, 1, tokenToVerify+1, null);
			}
		}
		else{
			System.out.println("Invalid Signature!");
			return dataToSend(publicKey, 0, tokenToVerify+1, null);
		}
	}

	public byte[][] put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] token, byte[] signedData) throws RemoteException {
		User user = manager.getUser(publicKey);
		byte[] t = Crypto.decryptRSA(manager.getServerPrivateKey(), Crypto.decodeBase64(token));
		long tokenToVerify = Time.getLong(t);
		if(user != null){
			if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(domain,username,password,token), signedData)){
				if(tokenToVerify == tokenMap.get(publicKey)){
					tokenMap.put(publicKey, (long) 0);
					manager.addPasswordEntry(user,domain,username,password);
					return dataToSend(publicKey, 3, tokenToVerify+1, null);
				}
				else{
					System.out.println("Token incorrect!");
					return dataToSend(publicKey, 2, tokenToVerify+1, null);
				}
			}
			else{
				System.out.println("Signature not correct!");
				return dataToSend(publicKey, 1, tokenToVerify+1, null);
			}
		}else{
			System.out.println("User does not exist!");
			return dataToSend(publicKey, 0, tokenToVerify+1, null);
		}
	}

	public byte[][] get(Key publicKey, byte[] domain, byte[] username, byte[] token, byte[] signedData) throws RemoteException {
		User user = manager.getUser(publicKey);
		byte[] t = Crypto.decryptRSA(manager.getServerPrivateKey(), Crypto.decodeBase64(token));
		long tokenToVerify = Time.getLong(t);
		if(user != null){
			if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(domain,username,token), signedData)){
				if(tokenToVerify == tokenMap.get(publicKey)){
					tokenMap.put(publicKey, (long) 0);
					return dataToSend(publicKey, 3, tokenToVerify+1, manager.getUserPassword(user,domain,username));
				}
				else{
					System.out.println("Incorrect token");
					return dataToSend(publicKey, 2, tokenToVerify+1, null);
				}
			}
			else{
				System.out.println("Signature not correct!");
				return dataToSend(publicKey, 1, tokenToVerify+1, null);
			}
		}else{
			System.out.println("User does not exist!");
			return dataToSend(publicKey, 0, tokenToVerify+1, null);
		}
	}
		
	private byte[][] dataToSend(Key publicKey, int value, long token, byte[] password){
		byte[] valueBytes = String.valueOf(value).getBytes();
		valueBytes = Crypto.encodeBase64(Crypto.encryptRSA((PublicKey) publicKey, valueBytes));
		byte[] tokenBytes = String.valueOf(token).getBytes();
		tokenBytes = Crypto.encodeBase64(Crypto.encryptRSA((PublicKey) publicKey, tokenBytes));
		byte[] signed;
		if(password != null)
			signed = Crypto.signData(manager.getServerPrivateKey(), Crypto.concatenateBytes(valueBytes,tokenBytes,password));
		else
			signed = Crypto.signData(manager.getServerPrivateKey(), Crypto.concatenateBytes(valueBytes,tokenBytes));
			
		return Token.getByteList(valueBytes, tokenBytes, signed, password);

	}
	
}
