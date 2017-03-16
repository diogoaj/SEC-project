package main.java;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
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
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class API {

	private KeyStore keyStore;
	private String clientId;
	private String password;
	private InterfaceRMI stub;
	private PublicKey serverKey;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private SecretKey secretKey;
	private byte[] salt_bytes = "salty".getBytes();
	
	private Map<String, Long> timestampMap;
	
	public void init(KeyStore key, String id, String pass)throws NoSuchAlgorithmException, CertificateException, IOException, NotBoundException, UnrecoverableKeyException, KeyStoreException, InvalidKeySpecException{
		keyStore = key;
		password = pass;
		clientId = id;
		
		timestampMap = new HashMap<String, Long>();
		keyStore.load(new FileInputStream("src/main/resources/keystore_" + id +".jks"), password.toCharArray());
		Registry registry = LocateRegistry.getRegistry(8000);
    	stub = (InterfaceRMI) registry.lookup("Interface");
    	
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
		
		loadData();
	}
	
	public int register_user(){
		try{
			byte[][] bytes = stub.getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
			if(bytes != null){
				if(Crypto.verifySignature(serverKey, bytes[0], bytes[1])){
					byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
					byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
					byte[][] returnValue = stub.register(publicKey,
							      token,
						          Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
					
					return getFeedback(returnValue, bytes, t);
				}
				else{
					System.out.println("Server signature not correct!");
					return -1;
				}
			}
			else{
				System.out.println("Server failed to check signature");
				return -1;
			}
			
		}
		catch(Exception e){
			System.err.println("Register user exception: " + e.toString());
        	e.printStackTrace();
        	return -1;
		}
	}
	
	public int save_password(byte[] domain, byte[] username, byte[] password){
		try{
			long currentTime;
			byte[][] bytes = stub.getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
			
			if(bytes != null){
				if(Crypto.verifySignature(serverKey, bytes[0], bytes[1])){
					String mapKey = new String(domain) + "||" + new String(username);
					if(timestampMap.containsKey(mapKey)){
						currentTime = getTimestampFromKey(mapKey);
					}else{
						currentTime = Time.getTimeLong();
					}
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
					
					saveTimestampData(new String(domain) + "||" + new String(username), currentTime);
					
					byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
					byte[][] returnValue = stub.put(publicKey, 
							 d, 
							 u, 
							 p, 
							 token,
							 Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,p,token)));
					
					return getFeedback(returnValue, bytes, t);
				}
				else{
					System.out.println("Signature not correct!");
					return -1;
				}
			}
			else{
				System.out.println("Server failed to check signature");
				return -1;
			}
		}
		catch(Exception e){
			System.err.println("Save password exception: " + e.toString());
        	e.printStackTrace();
        	return -1;
		}
	}
	
	public byte[] retrieve_password(byte[] domain, byte[] username){
		try{
			byte[][] bytes = stub.getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
			if(bytes != null){
				if(Crypto.verifySignature(serverKey, bytes[0], bytes[1])){
				Long timestamp = getTimestampFromKey(new String(domain) + "||" + new String(username));
				if(timestamp == null){
					return null;
				}
				byte[] d = Crypto.encodeBase64(
						   Crypto.encrypt(secretKey, 
								   Crypto.concatenateBytes(domain,Time.convertTime(timestamp))));
				byte[] u = Crypto.encodeBase64(
						   Crypto.encrypt(secretKey, 
								   Crypto.concatenateBytes(username,Time.convertTime(timestamp+1))));
				byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
				byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
				byte[][] returnValue = stub.get(publicKey, 
						                   d, 
						                   u, 
						                   token,
						                   Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,token)));
				
				int value = getFeedback(returnValue, bytes, t);
				if(value == 3){
					byte[] password = returnValue[3];
					if(password != null){
						return Crypto.decrypt(secretKey, Crypto.decodeBase64(password));
					}
					else{
						return null;
					}
				}
				else{
					return null;
				}
			}
			else{
				System.out.println("Server failed to check signature");
				return null;
			}
			}
			else{
				System.out.println("Signature incorrect!");
			}
		}
		catch(Exception e){
			System.err.println("Retrieve password exception: " + e.toString());
        	e.printStackTrace();
		}
		return null;
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
	
	public InterfaceRMI getStub(){
		return stub;
	}
		
	@SuppressWarnings("unchecked")
	public void loadData(){
		try{
			FileInputStream fileIn = new FileInputStream("src/main/resources/timestamps"+clientId+".ser");
			ObjectInputStream in = new ObjectInputStream(fileIn);
			timestampMap = (HashMap<String, Long>)in.readObject();
			in.close();
			fileIn.close();
		}catch(FileNotFoundException f){
			System.out.println("Timestamp data not found, not loading file...");
		}catch(IOException e){
			e.printStackTrace();
		}catch(ClassNotFoundException c){
	        c.printStackTrace();
		}
	}
	
	public void saveData(){
		try{
			FileOutputStream fileOut = new FileOutputStream("src/main/resources/timestamps"+clientId+".ser");
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			out.writeObject(timestampMap);
			out.close();
			fileOut.close();
		}catch(IOException e){
			e.printStackTrace();
		}
	}
	
	public void saveTimestampData(String key, long value){
		timestampMap.put(key, value);
		saveData();
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
