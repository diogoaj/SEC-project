package test.java;

import static org.junit.Assert.*;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import main.java.API;
import main.java.Crypto;
import main.java.InterfaceRMI;
import main.java.Token;

public class WtsTest {

	private static API library;
	private static KeyStore ks;
	private static HashMap<Integer,PublicKey> serverKey = new HashMap<Integer,PublicKey>();
	private static PublicKey publicKey;
	private static PrivateKey privateKey;
	private static List<InterfaceRMI> stubs;
	private static SecureRandom rand = new SecureRandom();
	private static SecretKey secretKey;
	
	
	@BeforeClass
	public static void oneTimeSetUp() throws Exception {
		library = new API();
		ks = KeyStore.getInstance("JKS");
		library.init(ks, "0", "banana", 1);
		publicKey = library.getPublicKey();
		privateKey = library.getPrivateKey();
		
		stubs = library.getStub();
		
		for(int i = 0; i < stubs.size(); i++){
    		serverKey.put(i, library.getServerPublicKey(i));
    	}
		secretKey = library.getSecretKey();
		library.register_user();
		library.save_password("gmail".getBytes(), "rito".getBytes(), "cruz".getBytes());
		library.save_password("ola".getBytes(), "zvcx".getBytes(), "2134".getBytes());
		library.save_password("hotmail".getBytes(), "ewq".getBytes(), "fsad".getBytes());
		library.save_password("adeus".getBytes(), "fds".getBytes(), "bvxc".getBytes());
	}
	
	@Test
	public void testWTS() throws Exception {		
		ArrayList<Integer> wtsList = new ArrayList<Integer>();
		for(int i = 0; i < stubs.size(); i++){
			try{
				byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
				if(bytes != null){
					if(Crypto.verifySignature(serverKey.get(i), bytes[0], bytes[1])){
						byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
						byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey.get(i), Token.nextToken(t)));
						byte[] signedData = Crypto.signData(privateKey, Crypto.concatenateBytes(publicKey.getEncoded(),token));
						byte[][] returned = stubs.get(i).getHighestTimestamp(publicKey, token, signedData);
						
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
				System.err.println("Server with port 800" + i + " crashed...");
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
		
		int wts = 0;
		for (Integer key : counter2.keySet()){
			if (counter2.get(key) > (stubs.size() + 1) / 2){
				wts = key + 1;
			}
		}
		
		assertEquals(4,wts);
	}
}
