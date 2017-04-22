package main.java;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.rmi.NotBoundException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class API {
	
	private static final int MAX_SERVERS = 4;
	
	private KeyStore keyStore;
	private String clientId;
	private String password;
	private PublicKey serverKey;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private SecretKey secretKey;
	private byte[] salt_bytes = "salty".getBytes();
	private Map<String, Long> timestampMap;
	private List<InterfaceRMI> servers;
	
	// Algorithm
	private int wts = 0;
	private ArrayList<Integer> ackList = new ArrayList<Integer>();
	private ArrayList<byte[][]> readList = new ArrayList<byte[][]>();
	
	private HashMap<byte[], byte[]> signatures = new HashMap<byte[], byte[]>();
	
	
	public void init(KeyStore key, String id, String pass)throws NoSuchAlgorithmException, CertificateException, IOException, NotBoundException, UnrecoverableKeyException, KeyStoreException, InvalidKeySpecException{
		keyStore = key;
		password = pass;
		clientId = id;
		
		servers = new ArrayList<InterfaceRMI>();
		
		timestampMap = new HashMap<String, Long>();
		keyStore.load(new FileInputStream("src/main/resources/keystore_" + id +".jks"), password.toCharArray());
		for(int i = 0; i < MAX_SERVERS; i++){
			Registry registry = LocateRegistry.getRegistry(8000 + i);
	    	InterfaceRMI stub = (InterfaceRMI) registry.lookup("Interface"+i);
	    	servers.add(stub);
		}
    	
    	CertificateFactory f = CertificateFactory.getInstance("X.509");
    	X509Certificate certificate = (X509Certificate)f.generateCertificate(new FileInputStream("src/main/resources/server.cer"));
    	serverKey = certificate.getPublicKey();
    	
    	privateKey = (PrivateKey)keyStore.getKey("clientkeystore", password.toCharArray());
    	publicKey = keyStore.getCertificate("clientkeystore").getPublicKey();
    	
    	// Generate static secret key
    	SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(new String(privateKey.getEncoded()).toCharArray(), salt_bytes, 1024, 128);
		SecretKey tmp = factory.generateSecret(spec);
		secretKey = new SecretKeySpec(tmp.getEncoded(), "AES"); 
	}
	
	public int register_user(){
		ArrayList<Integer> responses = new ArrayList<Integer>();
		for (InterfaceRMI server : servers){
			try{
				byte[][] bytes = server.getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
				if(bytes != null){
					if(Crypto.verifySignature(serverKey, bytes[0], bytes[1])){
						byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
						byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
						byte[][] returnValue = server.register(publicKey,
								      token,
							          Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
						
						responses.add(getFeedback(returnValue,bytes,t));
					}
				}		
			}
			catch(Exception e){
				System.err.println("Register user exception: " + e.toString());
	        	e.printStackTrace();
	        	return -1;
			}
		}
		
		return responses.get(0);
	}
	
	public int save_password(byte[] domain, byte[] username, byte[] password){
		for (int i = 0; i < servers.size(); i++){
			try{
				long currentTime;
				byte[][] bytes = servers.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
				
				if(bytes != null){
					if(Crypto.verifySignature(serverKey, bytes[0], bytes[1])){
						String mapKey = new String(domain) + "||" + new String(username);
						if(timestampMap.containsKey(mapKey)){
							currentTime = getTimestampFromKey(mapKey);
						}else{
							currentTime = Time.getTimeLong();
						}	
						
						wts++;
						ackList.clear();

						byte[] d = Crypto.encodeBase64(
								   Crypto.encrypt(secretKey, 
										   Crypto.concatenateBytes(domain,Time.convertTime(currentTime))));
						byte[] u = Crypto.encodeBase64(
								   Crypto.encrypt(secretKey, 
										   Crypto.concatenateBytes(username,Time.convertTime(currentTime+1))));
						byte[] p = Crypto.encodeBase64(
								   Crypto.encrypt(secretKey, 
										   Crypto.concatenateBytes(password,"||".getBytes(),Time.convertTime(currentTime+2))));
						byte[] t = Crypto.decryptRSA(
								   privateKey, 
								   Crypto.decodeBase64(bytes[0]));
						
						byte[] wtsEncoded = Crypto.encodeBase64(Crypto.encrypt(secretKey, Integer.toString(wts).getBytes())); 
										
						saveTimestampData(new String(domain) + "||" + new String(username), currentTime);
										
						byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
						
						byte[] signature = Crypto.signData(privateKey, Crypto.concatenateBytes(wtsEncoded,d,u,p,token));
						byte[][] returnValue = servers.get(i).put(
								 publicKey, 
								 wtsEncoded,
								 d, 
								 u, 
								 p, 
								 token,
								 signature);
						
						signatures.put(Crypto.concatenateBytes(Integer.toString(i).getBytes(), d, u), signature);
						
						ackList.add(getFeedback(returnValue, bytes, t));
					}
				}
			}
			catch(Exception e){
				System.err.println("Save password exception: " + e.toString());
	        	e.printStackTrace();
	        	return -1;
			}
		}
		Map<Integer, Integer> counter = new HashMap<Integer, Integer>();
		if (ackList.size() > (MAX_SERVERS + 1) / 2){
			ackList.clear();
			
			for (int i = 0; i< ackList.size(); i++){
				if (!counter.containsKey(ackList.get(i))){
					counter.put(ackList.get(i), 1);
				}else{
					int count = counter.get(ackList.get(i));
					count++;
					counter.put(ackList.get(i), count);
				}
			}
			
			int index = -5;
			int max = 0;
			for (Integer key : counter.keySet()){
				if (counter.get(key) > max){
					max = counter.get(key);
					index = key;
				}
			}
			return index;
		}
		
		return -1;
	}
	
	public byte[] retrieve_password(byte[] domain, byte[] username){
		for (int i = 0; i < servers.size(); i++){
			try{
				byte[][] bytes = servers.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
				if(bytes != null){
					if(Crypto.verifySignature(serverKey, bytes[0], bytes[1])){
					Long timestamp = getTimestampFromKey(new String(domain) + "||" + new String(username));
					if(timestamp == null){
						return null;
					}
					
					readList.clear();
					
					byte[] d = Crypto.encodeBase64(
							   Crypto.encrypt(secretKey, 
									   Crypto.concatenateBytes(domain,Time.convertTime(timestamp))));
					byte[] u = Crypto.encodeBase64(
							   Crypto.encrypt(secretKey, 
									   Crypto.concatenateBytes(username,Time.convertTime(timestamp+1))));
					byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
					byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
					byte[][] returnValue = servers.get(i).get(publicKey, 
							                   d, 
							                   u, 
							                   token,
							                   Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,token)));
						
					int value = getFeedback(returnValue, bytes, t);
					if(value == 3){
						byte[] password = returnValue[3];
						if(password != null){
							if (Arrays.equals(returnValue[returnValue.length - 1], signatures.get(Crypto.concatenateBytes(Integer.toString(i).getBytes(), d, u)))){
								byte[] wtsEnc = Crypto.decrypt(secretKey, Crypto.decodeBase64(returnValue[returnValue.length - 2]));
								byte[] pw = Crypto.decrypt(secretKey, Crypto.decodeBase64(password));
								readList.add(Token.getByteList(wtsEnc,pw));
							}
							
						}
					}
				}
			}
		}catch(Exception e){
			System.err.println("Retrieve password exception: " + e.toString());
        	e.printStackTrace();
        	}
		}
		
		byte[] pw = null;
		if (readList.size() > (MAX_SERVERS + 1) / 2){	
			int max = -1;
			for (int i = 0; i< readList.size(); i++){
				if (Integer.parseInt(new String(readList.get(i)[0])) > max){
					max = Integer.parseInt(new String(readList.get(i)[0]));
					pw = readList.get(i)[1];
				}
			}
		}
		readList.clear();
		
		return pw;
			
		
	}

	public void close(){
		System.exit(0);
	}

	public PublicKey getServerPublicKey() {
		return serverKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	
	public SecretKey getSecretKey(){
		return secretKey;
	}
	
	/*
	public InterfaceRMI getStub(){
		return stub;
	}
	*/
	
	public void saveTimestampData(String key, long value){
		timestampMap.put(key, value);
	}
	
	public Long getTimestampFromKey(String key){
		return timestampMap.get(key);
	}
	
	public Map<String, Long> getMap(){
		return timestampMap;
	}
	
	public int getFeedback(byte[][] returnValue, byte[][] bytes, byte[] t){
		boolean check;
		if(returnValue.length == 4){
			if(returnValue[3] != null)
				check = Crypto.verifySignature(serverKey, Crypto.concatenateBytes(returnValue[0], returnValue[1], returnValue[3]), returnValue[2]);
			else
				check = Crypto.verifySignature(serverKey, Crypto.concatenateBytes(returnValue[0], returnValue[1]), returnValue[2]);
		}
		else{
			check = Crypto.verifySignature(serverKey, Crypto.concatenateBytes(returnValue[0], returnValue[1]), returnValue[2]);
		}
		if(check){
			long returnToken = Long.valueOf(new String(Crypto.decryptRSA(privateKey, Crypto.decodeBase64(returnValue[1]))));
			long lastToken = Long.valueOf(new String(t)) + 1;
			if(returnToken == lastToken + 1){
				return Integer.valueOf(new String(Crypto.decryptRSA(privateKey, Crypto.decodeBase64(returnValue[0]))));
			}
			else{
				System.out.println("Server token was incorrect");
				return -1;
			}
		}
		else{
			System.out.println("Server signature was incorrect");
			return -1;
		}
	}
}
