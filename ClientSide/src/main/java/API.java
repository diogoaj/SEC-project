package main.java;

import java.io.FileInputStream;
import java.io.IOException;
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
import java.util.Properties;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class API {
	
	private int max_servers;
	private int faults;
	private KeyStore keyStore;
	private String clientId;
	private String password;
	private HashMap<Integer, PublicKey> serverKey = new HashMap<Integer, PublicKey>();
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
	
	
	
	public void init(KeyStore key, String id, String pass, int faults)throws NoSuchAlgorithmException, CertificateException, IOException, NotBoundException, UnrecoverableKeyException, KeyStoreException, InvalidKeySpecException{
		Properties props = System.getProperties();
		props.setProperty("sun.rmi.transport.tcp.responseTimeout", "5000");
		
		keyStore = key;
		password = pass;
		clientId = id;	
		this.faults = faults;
		
		max_servers = 3*faults + 1;
		
		servers = new ArrayList<InterfaceRMI>();
		
		timestampMap = new HashMap<String, Long>();
		keyStore.load(new FileInputStream("src/main/resources/keystore_" + id +".jks"), password.toCharArray());
		for(int i = 0; i < max_servers; i++){
			Registry registry = LocateRegistry.getRegistry(8000 + i);
	    	InterfaceRMI stub = (InterfaceRMI) registry.lookup("Interface"+i);
	    	servers.add(stub);
		}
		
		for(int i = 0; i < max_servers; i++){
	       	CertificateFactory f = CertificateFactory.getInstance("X.509");
	    	X509Certificate certificate = (X509Certificate)f.generateCertificate(new FileInputStream("src/main/resources/certificate_"+i+".crt"));
	    	serverKey.put(i,certificate.getPublicKey());
		}
    	
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
		for (int i = 0; i < max_servers; i++){
			try{
				byte[][] bytes = servers.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
				if(bytes != null){
					if(Crypto.verifySignature(serverKey.get(i), bytes[0], bytes[1])){
						byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
						byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey.get(i), Token.nextToken(t)));
						byte[][] returnValue = servers.get(i).register(publicKey,
								      token,
							          Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(), token)));
						
						responses.add(getFeedback(returnValue,bytes,t,i));
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
		ackList.clear();

		ArrayList<Integer> wtsList = new ArrayList<Integer>();
		for(int i = 0; i < servers.size(); i++){
			try{
				byte[][] bytes = servers.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
				if(bytes != null){
					if(Crypto.verifySignature(serverKey.get(i), bytes[0], bytes[1])){
						byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
						byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey.get(i), Token.nextToken(t)));
						byte[] signedData = Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(),token));
						byte[][] returned = servers.get(i).getHighestTimestamp(publicKey, token, signedData);
						
						if (returned == null)
							return -1;
						
						if(Crypto.verifySignature(serverKey.get(i), Crypto.concatenateBytes(returned[0],returned[1]), returned[2])){
							int size = returned.length;
							int max = -1;
							for(int j = 3; j<size; j++){
								int wtsReceived = Integer.valueOf(new String(Crypto.decrypt(secretKey, Crypto.decodeBase64(returned[j]))));
								if(wtsReceived > max){
									max = wtsReceived;
								}
							}
							if(max != -1)
								wtsList.add(max);
						}						
					}
				}
			}catch(java.rmi.ConnectException c){
				System.err.println("Server with port " + (8000+ i)  + " crashed...");
			}catch(Exception e){
				e.printStackTrace();
			}
		}
		
		Map<Integer, Integer> counter2 = new HashMap<Integer, Integer>();
		for (int i = 0; i< wtsList.size(); i++){
			if (!counter2.containsKey(wtsList.get(i))){
				counter2.put(wtsList.get(i), 1);
			}else{
				int count = counter2.get(wtsList.get(i));
				count++;
				counter2.put(wtsList.get(i), count);
			}
		}
		
		wts = 0;
		for (Integer key : counter2.keySet()){
			if (counter2.get(key) > (max_servers + faults) / 2){
				wts = key + 1;
			}
		}
		
		for (int i = 0; i < servers.size(); i++){
			try{
				long currentTime;
				byte[][] bytes = servers.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
				
				if(bytes != null){
					if(Crypto.verifySignature(serverKey.get(i), bytes[0], bytes[1])){
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
						
						byte[] wtsEncoded = Crypto.encodeBase64(Crypto.encrypt(secretKey, String.valueOf(wts).getBytes())); 
										
						saveTimestampData(new String(domain) + "||" + new String(username), currentTime);
										
						byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey.get(i), Token.nextToken(t)));
						
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
						
						
						ackList.add(getFeedback(returnValue, bytes, t,i));
					}
				}
			}catch(java.rmi.ConnectException c){
				System.err.println("Server with port " + (8000+ i) + " crashed...");
			}catch(java.rmi.UnmarshalException u){
				System.err.println("Server " + (8000+ i)  + " took too long to answer...");
			}
			catch(Exception e){
				e.printStackTrace();
			}
		}
		
		Map<Integer, Integer> counter= new HashMap<Integer, Integer>();
		if (ackList.size() > (max_servers + faults) / 2){	
			
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
		readList.clear();
			
		for (int i = 0; i < servers.size(); i++){
			try{
				byte[][] bytes = servers.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
				if(bytes != null){
					if(Crypto.verifySignature(serverKey.get(i), bytes[0], bytes[1])){
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
					byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey.get(i), Token.nextToken(t)));
					byte[][] returnValue = servers.get(i).get(publicKey, 
							                   d, 
							                   u, 
							                   token,
							                   Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,token)));
						
					int value = getFeedback(returnValue, bytes, t,i);
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
		}catch(java.rmi.ConnectException c){
			System.err.println("Server with port 800" + i + " crashed...");
		}catch(Exception e){
			e.printStackTrace();
		}
        	
		}
		
		byte[] pw = null;
		if (readList.size() > (max_servers + faults) / 2){	
			int max = -1;
			for (int i = 0; i< readList.size(); i++){
				if (Integer.parseInt(new String(readList.get(i)[0])) > max){
					max = Integer.parseInt(new String(readList.get(i)[0]));
					pw = readList.get(i)[1];
				}
			}
		}
		
		if(pw != null){
			save_password(domain, username, pw);
		}
		
		return pw;
			
		
	}

	public void close(){
		System.exit(0);
	}

	public PublicKey getServerPublicKey(int i) {
		return serverKey.get(i);
	}
	
	public int getWts(){
		return wts;
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
	
	public List<InterfaceRMI> getStub(){
		return servers;
	}
	
	public void saveTimestampData(String key, long value){
		timestampMap.put(key, value);
	}
	
	public Long getTimestampFromKey(String key){
		return timestampMap.get(key);
	}
	
	public Map<String, Long> getMap(){
		return timestampMap;
	}
	
	public int getFeedback(byte[][] returnValue, byte[][] bytes, byte[] t, int i){
		boolean check;
		if(returnValue[3] != null){
			check = Crypto.verifySignature(serverKey.get(i), Crypto.concatenateBytes(returnValue[0], returnValue[1], returnValue[3]), returnValue[2]);
		}
		else
			check = Crypto.verifySignature(serverKey.get(i), Crypto.concatenateBytes(returnValue[0], returnValue[1]), returnValue[2]);

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
