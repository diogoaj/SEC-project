package main.java;

import java.rmi.RemoteException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.security.Key;
import java.security.PublicKey;

import main.java.business.PasswordEntry;
import main.java.business.PasswordManager;
import main.java.business.User;


public class InterfaceImpl implements InterfaceRMI{
	
	private PasswordManager manager;
	private SecureRandom rand = new SecureRandom();
	private Map<Key, Long> tokenMap = new ConcurrentHashMap<Key, Long>();
	
	private Map<Key,ArrayList<byte[]>> log = new ConcurrentHashMap<Key,ArrayList<byte[]>>();
	
	private HashMap<byte[], byte[]> signatures = new HashMap<byte[], byte[]>();
	
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
			
			addToLog(publicKey, signedData);
			
			return Token.getByteList(token, Crypto.signData(manager.getServerPrivateKey(), token));
		}
		else{
			System.out.println("Signature failed");
			return null;
		}
	}
	
	public byte[][] getHighestTimestamp(Key publicKey, byte[] token, byte[] signedData){
		byte[] t = Crypto.decryptRSA(manager.getServerPrivateKey(), Crypto.decodeBase64(token));
		long tokenToVerify = Time.getLong(t);
		if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(publicKey.getEncoded(), token), signedData)){
			if(tokenToVerify == tokenMap.get(publicKey)){		
				tokenMap.put(publicKey, (long) 0);
				
				User u = manager.getUser(publicKey);
				// For the test
				try{
					int size = u.getData().size();
					byte[][] dataToSend = new byte[size + 3][];
					
					byte[] valueBytes = String.valueOf(3).getBytes();
					valueBytes = Crypto.encodeBase64(Crypto.encryptRSA((PublicKey) publicKey, valueBytes));
					byte[] tokenBytes = String.valueOf(tokenToVerify + 1).getBytes();
					tokenBytes = Crypto.encodeBase64(Crypto.encryptRSA((PublicKey) publicKey, tokenBytes));
					byte[] signed = Crypto.signData(manager.getServerPrivateKey(), Crypto.concatenateBytes(valueBytes,tokenBytes));
					
					dataToSend[0] = valueBytes;
					dataToSend[1] = tokenBytes;
					dataToSend[2] = signed;

					for (int i = 3; i < size + 3; i++){
						dataToSend[i] = u.getData().get(i-3).getWts();
					}
					
					return dataToSend;		
				}catch(NullPointerException e){
					e.printStackTrace();
				}
					
			}			
			
			return null;
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
				addToLog(publicKey, signedData);
				boolean added = manager.addUser(user);
				if(added)
					return dataToSend(publicKey, 3, tokenToVerify+1, null, null, null);
				else
					return dataToSend(publicKey, 2, tokenToVerify+1, null, null, null);
			}else{
				System.out.println("Token not correct");
				return dataToSend(publicKey, 1, tokenToVerify+1, null, null, null);
			}
		}
		else{
			System.out.println("Invalid Signature!");
			return dataToSend(publicKey, 0, tokenToVerify+1, null, null, null);
		}
	}

	public byte[][] put(Key publicKey, byte[] wts, byte[] domain, byte[] username, byte[] password, byte[] token, byte[] signedData) throws RemoteException {
		User user = manager.getUser(publicKey);
		byte[] t = Crypto.decryptRSA(manager.getServerPrivateKey(), Crypto.decodeBase64(token));
		long tokenToVerify = Time.getLong(t);
		if(user != null){
			if(Crypto.verifySignature((PublicKey) publicKey, Crypto.concatenateBytes(wts,domain,username,password,token), signedData)){ 
				if(tokenToVerify == tokenMap.get(publicKey)){
					tokenMap.put(publicKey, (long) 0);		
					manager.addPasswordEntry(user,domain,username,password,wts);
					signatures.put(Crypto.concatenateBytes(domain,username), signedData);
					addToLog(publicKey, signedData);

					return dataToSend(publicKey, 3, tokenToVerify+1, null, null, null);
				}
				else{
					System.out.println("Token incorrect!");
					return dataToSend(publicKey, 2, tokenToVerify+1, null, null, null);
				}
			}
			else{
				System.out.println("Signature not correct!");
				return dataToSend(publicKey, 1, tokenToVerify+1, null, null, null);
			}
		}else{
			System.out.println("User does not exist!");
			return dataToSend(publicKey, 0, tokenToVerify+1, null, null, null);
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
					byte[] signatureToSend = signatures.get(Crypto.concatenateBytes(domain,username));
					addToLog(publicKey, signedData);
					return dataToSend(
							publicKey, 
							3, 
							tokenToVerify+1, 
							manager.getUserPassword(user,domain,username), 
							manager.getUserWts(user,domain,username),
							signatureToSend);
				}
				else{
					System.out.println("Incorrect token");
					return dataToSend(publicKey, 2, tokenToVerify+1, null, null, null);
				}
			}
			else{
				System.out.println("Signature not correct!");
				return dataToSend(publicKey, 1, tokenToVerify+1, null, null, null);
			}
		}else{
			System.out.println("User does not exist!");
			return dataToSend(publicKey, 0, tokenToVerify+1, null, null, null);
		}
	}
		
	private byte[][] dataToSend(Key publicKey, int value, long token, byte[] password, byte[] wts, byte[] signature){
		byte[] valueBytes = String.valueOf(value).getBytes();
		valueBytes = Crypto.encodeBase64(Crypto.encryptRSA((PublicKey) publicKey, valueBytes));
		byte[] tokenBytes = String.valueOf(token).getBytes();
		tokenBytes = Crypto.encodeBase64(Crypto.encryptRSA((PublicKey) publicKey, tokenBytes));
		byte[] signed;
		if(password != null)
			signed = Crypto.signData(manager.getServerPrivateKey(), Crypto.concatenateBytes(valueBytes,tokenBytes,password));
		else
			signed = Crypto.signData(manager.getServerPrivateKey(), Crypto.concatenateBytes(valueBytes,tokenBytes));
			
		return Token.getByteList(valueBytes, tokenBytes, signed, password, wts, signature);

	}
	
	private void addToLog(Key publicKey, byte[] signedData){
		if(log.containsKey(publicKey)){
			ArrayList<byte[]> temp;
			temp = log.get(publicKey);
			temp.add(signedData);
			log.put(publicKey, temp);
		}
		else{
			ArrayList<byte[]> temp = new ArrayList<byte[]>();
			temp.add(signedData);
			log.put(publicKey, temp);
		}
	}
	
}
