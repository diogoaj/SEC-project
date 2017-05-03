package test.java;

import static org.junit.Assert.*;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
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
import main.java.Time;
import main.java.Token;

public class Replication {

	private static API library;
	private static KeyStore ks;
	private static PublicKey serverKey;
	private static PublicKey publicKey;
	private static PrivateKey privateKey;
	private static List<InterfaceRMI> stubs;
	private static SecureRandom rand = new SecureRandom();
	private static SecretKey secretKey;
	private static ArrayList<Integer> ackList = new ArrayList<Integer>();
	private static ArrayList<byte[][]> readList = new ArrayList<byte[][]>();
	private static HashMap<byte[], byte[]> signatures = new HashMap<byte[], byte[]>();
	
	@BeforeClass
	public static void oneTimeSetUp() throws Exception {
		library = new API();
		ks = KeyStore.getInstance("JKS");
		library.init(ks, "0", "banana", 1);
		publicKey = library.getPublicKey();
		privateKey = library.getPrivateKey();
		serverKey = library.getServerPublicKey();
		stubs = library.getStub();
		secretKey = library.getSecretKey();
		library.register_user();
		library.save_password("gmail".getBytes(), "rito".getBytes(), "cruz".getBytes());
	}
	
	@After
	public void tear() throws Exception{
		ackList.clear();
		readList.clear();
	}
	
	@AfterClass
	public static void tearDown() throws Exception {
		signatures.clear();
	}
	
	@Test
	public void savePasswordWithOneFailure() throws Exception{
		for(int i = 0; i<stubs.size()-1; i++){
			byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
			
			long currentTime;
			String mapKey = new String("gmail") + "||" + new String("rito");
			if(library.getMap().containsKey(mapKey)){
				currentTime = library.getTimestampFromKey(mapKey);
			}else{
				currentTime = Time.getTimeLong();
			}
			
			byte[] t = Crypto.decryptRSA(
					   privateKey, 
					   Crypto.decodeBase64(bytes[0]));
			
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
			
			byte[] d = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(currentTime))));
			byte[] u = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(currentTime+1))));
			byte[] p = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("cruz".getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
			
			byte[] wtsEncoded = Crypto.encodeBase64(Crypto.encrypt(secretKey, String.valueOf(library.getWts()).getBytes())); 
			
			byte[] signature = Crypto.signData(privateKey, Crypto.concatenateBytes(wtsEncoded,d,u,p,token));
			
			byte[][] returnValue = stubs.get(i).put(publicKey, 
					 wtsEncoded,
					 d, 
					 u, 
					 p, 
					 token,
					 signature);
					
			signatures.put(Crypto.concatenateBytes(Integer.toString(i).getBytes(), d, u), signature);
			ackList.add(library.getFeedback(returnValue, bytes, t));
		}
		
		int index = -5;
		Map<Integer, Integer> counter = new HashMap<Integer, Integer>();
		if (ackList.size() > (stubs.size() + 1) / 2){	
			
			for (int i = 0; i< ackList.size(); i++){
				if (!counter.containsKey(ackList.get(i))){
					counter.put(ackList.get(i), 1);
				}else{
					int count = counter.get(ackList.get(i));
					count++;
					counter.put(ackList.get(i), count);
				}
			}
			
			int max = 0;
			for (Integer key : counter.keySet()){
				if (counter.get(key) > max){
					max = counter.get(key);
					index = key;
				}
			}
		}
		
		assertEquals(index,3);
	}
	
	@Test
	public void savePasswordWithTwoFailures() throws Exception{
		for(int i = 0; i<stubs.size()-2; i++){
			byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
			
			long currentTime;
			String mapKey = new String("gmail") + "||" + new String("rito");
			if(library.getMap().containsKey(mapKey)){
				currentTime = library.getTimestampFromKey(mapKey);
			}else{
				currentTime = Time.getTimeLong();
			}
			
			byte[] t = Crypto.decryptRSA(
					   privateKey, 
					   Crypto.decodeBase64(bytes[0]));
			
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
			
			byte[] d = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(currentTime))));
			byte[] u = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(currentTime+1))));
			byte[] p = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("cruz".getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
			
			byte[] wtsEncoded = Crypto.encodeBase64(Crypto.encrypt(secretKey, String.valueOf(library.getWts()).getBytes()));
			
			byte[] signature = Crypto.signData(privateKey, Crypto.concatenateBytes(wtsEncoded,d,u,p,token));
			
			byte[][] returnValue = stubs.get(i).put(publicKey, 
					 wtsEncoded,
					 d, 
					 u, 
					 p, 
					 token,
					 signature);
					
			signatures.put(Crypto.concatenateBytes(Integer.toString(i).getBytes(), d, u), signature);
					
			ackList.add(library.getFeedback(returnValue, bytes, t));
		}
		
		int index = -1;
		Map<Integer, Integer> counter = new HashMap<Integer, Integer>();
		if (ackList.size() > (stubs.size() + 1) / 2){	
			
			for (int i = 0; i< ackList.size(); i++){
				if (!counter.containsKey(ackList.get(i))){
					counter.put(ackList.get(i), 1);
				}else{
					int count = counter.get(ackList.get(i));
					count++;
					counter.put(ackList.get(i), count);
				}
			}
			
			int max = 0;
			for (Integer key : counter.keySet()){
				if (counter.get(key) > max){
					max = counter.get(key);
					index = key;
				}
			}
		}
		
		assertEquals(index,-1);
	}
	
	@Test
	public void savePasswordWithOneWrong() throws Exception{
		for(int i = 0; i<stubs.size()-1; i++){
			byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
			
			long currentTime;
			String mapKey = new String("gmail") + "||" + new String("rito");
			if(library.getMap().containsKey(mapKey)){
				currentTime = library.getTimestampFromKey(mapKey);
			}else{
				currentTime = Time.getTimeLong();
			}
			
			byte[] t = Crypto.decryptRSA(
					   privateKey, 
					   Crypto.decodeBase64(bytes[0]));
			
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
			
			byte[] d = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(currentTime))));
			byte[] u = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(currentTime+1))));
			byte[] p = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("cruz".getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
			
			byte[] wtsEncoded = Crypto.encodeBase64(Crypto.encrypt(secretKey, String.valueOf(library.getWts()).getBytes())); 
			
			byte[] signature = Crypto.signData(privateKey, Crypto.concatenateBytes(wtsEncoded,d,u,p,token));
			
			byte[][] returnValue = stubs.get(i).put(publicKey, 
					 wtsEncoded,
					 d, 
					 u, 
					 p, 
					 token,
					 signature);
					
			signatures.put(Crypto.concatenateBytes(Integer.toString(i).getBytes(), d, u), signature);
					
			ackList.add(library.getFeedback(returnValue, bytes, t));
		}
		
		ackList.add(2);
		
		int index = -5;
		Map<Integer, Integer> counter = new HashMap<Integer, Integer>();
		if (ackList.size() > (stubs.size() + 1) / 2){	
			
			for (int i = 0; i< ackList.size(); i++){
				if (!counter.containsKey(ackList.get(i))){
					counter.put(ackList.get(i), 1);
				}else{
					int count = counter.get(ackList.get(i));
					count++;
					counter.put(ackList.get(i), count);
				}
			}
			
			int max = 0;
			for (Integer key : counter.keySet()){
				if (counter.get(key) > max){
					max = counter.get(key);
					index = key;
				}
			}
		}
		
		assertEquals(index,3);
	}
	
	@Test
	public void retrieveWithOneFailure() throws Exception{
		for(int i = 0; i<stubs.size()-1; i++){
			byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
			Long timestamp = library.getTimestampFromKey(new String("gmail") + "||" + new String("rito"));
	
			byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
			
			byte[] d = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(timestamp))));
			byte[] u = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(timestamp+1))));
			
			byte[][] returnValue = stubs.get(i).get(publicKey, 
					                   d, 
					                   u, 
					                   token,
					                   Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,token)));
			
			int value = library.getFeedback(returnValue, bytes, t);
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
		
		byte[] pw = null;
		if (readList.size() > (stubs.size() + 1) / 2){	
			int max = -1;
			for (int i = 0; i< readList.size(); i++){
				if (Integer.parseInt(new String(readList.get(i)[0])) > max){
					max = Integer.parseInt(new String(readList.get(i)[0]));
					pw = readList.get(i)[1];
				}
			}
		}
		
		assertNotNull(pw);
		
		String pass = new String(pw);
		pass = pass.split("\\|\\|")[0];
		assertEquals(pass, "cruz");
	}
	
	@Test
	public void retrieveWithTwoFailures() throws Exception{
		for(int i = 0; i<stubs.size()-2; i++){
			byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
			Long timestamp = library.getTimestampFromKey(new String("gmail") + "||" + new String("rito"));
	
			byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
			
			byte[] d = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(timestamp))));
			byte[] u = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(timestamp+1))));
			
			byte[][] returnValue = stubs.get(i).get(publicKey, 
					                   d, 
					                   u, 
					                   token,
					                   Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,token)));
			
			int value = library.getFeedback(returnValue, bytes, t);
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
		
		byte[] pw = null;
		if (readList.size() > (stubs.size() + 1) / 2){	
			int max = -1;
			for (int i = 0; i< readList.size(); i++){
				if (Integer.parseInt(new String(readList.get(i)[0])) > max){
					max = Integer.parseInt(new String(readList.get(i)[0]));
					pw = readList.get(i)[1];
				}
			}
		}
		
		assertNull(pw);
	}

	@Test
	public void retrieveandUpdate() throws Exception{
		for(int i = 0; i<stubs.size()-1; i++){
			byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
			
			long currentTime;
			String mapKey = new String("gmail") + "||" + new String("rito");
			if(library.getMap().containsKey(mapKey)){
				currentTime = library.getTimestampFromKey(mapKey);
			}else{
				currentTime = Time.getTimeLong();
			}
			
			byte[] t = Crypto.decryptRSA(
					   privateKey, 
					   Crypto.decodeBase64(bytes[0]));
			
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
			
			byte[] d = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(currentTime))));
			byte[] u = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(currentTime+1))));
			byte[] p = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("cruz".getBytes(),"||".getBytes(),Time.convertTime(currentTime+2))));
			
			byte[] wtsEncoded = Crypto.encodeBase64(Crypto.encrypt(secretKey, String.valueOf(library.getWts()).getBytes()));
			
			byte[] signature = Crypto.signData(privateKey, Crypto.concatenateBytes(wtsEncoded,d,u,p,token));
			
			byte[][] returnValue = stubs.get(i).put(publicKey, 
					 wtsEncoded,
					 d, 
					 u, 
					 p, 
					 token,
					 signature);
					
			signatures.put(Crypto.concatenateBytes(Integer.toString(i).getBytes(), d, u), signature);
			ackList.add(library.getFeedback(returnValue, bytes, t));
		}
		
		byte[][] bytes3 = stubs.get(3).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
		
		long currentTime3;
		String mapKey3 = new String("gmail") + "||" + new String("rito");
		if(library.getMap().containsKey(mapKey3)){
			currentTime3 = library.getTimestampFromKey(mapKey3);
		}else{
			currentTime3 = Time.getTimeLong();
		}
		
		byte[] t3 = Crypto.decryptRSA(
				   privateKey, 
				   Crypto.decodeBase64(bytes3[0]));
		
		byte[] token3 = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t3)));
		
		byte[] d3 = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(currentTime3))));
		byte[] u3 = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(currentTime3+1))));
		byte[] p3 = Crypto.encodeBase64(
				   Crypto.encrypt(secretKey, 
						   Crypto.concatenateBytes("banana".getBytes(),"||".getBytes(),Time.convertTime(currentTime3+2))));
		
		byte[] wtsEncoded3 = Crypto.encodeBase64(Crypto.encrypt(secretKey, String.valueOf(library.getWts()).getBytes()));
		
		byte[] signature3 = Crypto.signData(privateKey, Crypto.concatenateBytes(wtsEncoded3,d3,u3,p3,token3));
		
		byte[][] returnValue3 = stubs.get(3).put(publicKey, 
				 wtsEncoded3,
				 d3, 
				 u3, 
				 p3, 
				 token3,
				 signature3);
				
		signatures.put(Crypto.concatenateBytes(Integer.toString(3).getBytes(), d3, u3), signature3);
		ackList.add(library.getFeedback(returnValue3, bytes3, t3));
		
		for(int i = 0; i<stubs.size(); i++){
			byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
			Long timestamp = library.getTimestampFromKey(new String("gmail") + "||" + new String("rito"));
	
			byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
			
			byte[] d = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(timestamp))));
			byte[] u = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(timestamp+1))));
			
			byte[][] returnValue = stubs.get(i).get(publicKey, 
					                   d, 
					                   u, 
					                   token,
					                   Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,token)));
			
			int value = library.getFeedback(returnValue, bytes, t);
			if(value == 3){
				byte[] password = returnValue[3];
				if(password != null){					
					if (Arrays.equals(returnValue[returnValue.length - 1], signatures.get(Crypto.concatenateBytes(Integer.toString(i).getBytes(), d, u)))){
						byte[] wtsEnc = Crypto.decrypt(secretKey, Crypto.decodeBase64(returnValue[returnValue.length - 2]));
						byte[] pw = Crypto.decrypt(secretKey, Crypto.decodeBase64(password));
						readList.add(Token.getByteList(wtsEnc,pw));
					}
		
					if(i!=3){
						String pass = new String(readList.get(i)[1]);
						pass = pass.split("\\|\\|")[0];
						assertEquals(pass, "cruz");
					}
					else{
						String pass = new String(readList.get(i)[1]);
						pass = pass.split("\\|\\|")[0];
						assertEquals(pass, "banana");
					}
				}
			}
		}
		
		byte[] pw4 = null;
		if (readList.size() > (stubs.size() + 1) / 2){	
			int max = -1;
			for (int i = 0; i< readList.size(); i++){
				if (Integer.parseInt(new String(readList.get(i)[0])) > max){
					max = Integer.parseInt(new String(readList.get(i)[0]));
					pw4 = readList.get(i)[1];
				}
			}
		}
		
		assertNotNull(pw4);
		
		String pass2 = new String(pw4);
		pass2 = pass2.split("\\|\\|")[0];
		assertEquals(pass2, "cruz");
		
		byte[] pw1 = library.retrieve_password("gmail".getBytes(), "rito".getBytes());
		readList.clear();
		
		for(int i = 0; i<stubs.size(); i++){
			byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
			Long timestamp = library.getTimestampFromKey(new String("gmail") + "||" + new String("rito"));
	
			byte[] t = Crypto.decryptRSA(privateKey, Crypto.decodeBase64(bytes[0]));
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey, Token.nextToken(t)));
			
			byte[] d = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("gmail".getBytes(),Time.convertTime(timestamp))));
			byte[] u = Crypto.encodeBase64(
					   Crypto.encrypt(secretKey, 
							   Crypto.concatenateBytes("rito".getBytes(),Time.convertTime(timestamp+1))));
			
			byte[][] returnValue = stubs.get(i).get(publicKey, 
					                   d, 
					                   u, 
					                   token,
					                   Crypto.signData(privateKey, Crypto.concatenateBytes(d,u,token)));
			
			int value = library.getFeedback(returnValue, bytes, t);
			if(value == 3){
				byte[] password = returnValue[3];
				if(password != null){					
					if (Arrays.equals(returnValue[returnValue.length - 1], signatures.get(Crypto.concatenateBytes(Integer.toString(i).getBytes(), d, u)))){
						byte[] wtsEnc = Crypto.decrypt(secretKey, Crypto.decodeBase64(returnValue[returnValue.length - 2]));
						byte[] pw = Crypto.decrypt(secretKey, Crypto.decodeBase64(password));
						readList.add(Token.getByteList(wtsEnc,pw));
					}

					String pass = new String(readList.get(i)[1]);
					pass = pass.split("\\|\\|")[0];
					assertEquals("cruz",pass);
				}
			}
		}
		
		String pass = new String(pw1);
		pass = pass.split("\\|\\|")[0];
		assertEquals(pass, "cruz");
	}
}
