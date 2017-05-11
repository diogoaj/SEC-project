package test.java;

import static org.junit.Assert.*;

import java.io.IOException;
import java.rmi.NotBoundException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import org.junit.BeforeClass;
import org.junit.Test;

import main.java.API;
import main.java.Crypto;
import main.java.InterfaceRMI;
import main.java.Time;
import main.java.Token;

public class SaveTest {

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
		for(int i = 0; i < stubs.size(); i++){
    		serverKey.put(i, library.getServerPublicKey(i));
    	}
		stubs = library.getStub();
		secretKey = library.getSecretKey();
		library.register_user();
	}
	
	@Test
	public void saveWithoutRegister() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, IOException, NotBoundException{
		API library2 = new API();
		KeyStore ks2 = KeyStore.getInstance("JKS");
		library2.init(ks2, "2", "banana", 1);
		int value = library2.save_password("facebook2".getBytes(), "user2".getBytes(), "pass2".getBytes());
		assertEquals(value, 0);
	}
	
	@Test
	public void savePasswordSuccess(){
		int value = library.save_password("facebook".getBytes(), "user1".getBytes(), "pass1".getBytes());
		assertEquals(value, 3);
	}
	
	@Test
	public void saveWrongToken() throws Exception{
		for(int i = 0; i<stubs.size(); i++){
			byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
	
			long currentTime;
			String mapKey = new String("gmail") + "||" + new String("rito");
			if(library.getMap().containsKey(mapKey)){
				currentTime = library.getTimestampFromKey(mapKey);
			}else{
				currentTime = Time.getTimeLong();
			}
			
			long l = rand.nextLong();
			byte[] t = String.valueOf(l).getBytes();
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey.get(i), Token.nextToken(t)));
			
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
			
			byte[][] returnValue = stubs.get(i).put(publicKey, 
					 wtsEncoded,
					 d, 
					 u, 
					 p, 
					 token,
					 Crypto.signData(privateKey, Crypto.concatenateBytes(wtsEncoded,d,u,p,token)));
	
			
			int value = library.getFeedback(returnValue, bytes, t,i);
			assertEquals(value,2);
		}
	}
	
	@Test
	public void saveWrongSignature() throws Exception{
		for(int i = 0; i<stubs.size(); i++){
			byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
	
			long currentTime;
			String mapKey = new String("gmail") + "||" + new String("rito");
			if(library.getMap().containsKey(mapKey)){
				currentTime = library.getTimestampFromKey(mapKey);
			}else{
				currentTime = Time.getTimeLong();
			}
			
			long l = rand.nextLong();
			byte[] t = String.valueOf(l).getBytes();
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey.get(i), Token.nextToken(t)));
			byte[] token_wrong = Crypto.encodeBase64(Crypto.encryptRSA(serverKey.get(i), Token.nextToken(Token.nextToken(t))));
			
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
			
			byte[][] returnValue = stubs.get(i).put(publicKey, 
					 wtsEncoded,
					 d, 
					 u, 
					 p, 
					 token,
					 Crypto.signData(privateKey, Crypto.concatenateBytes(wtsEncoded,d,u,p,token_wrong)));
	
			
			int value = library.getFeedback(returnValue, bytes, t,i);
			assertEquals(value,1);
		}
	}
	
	@Test
	public void saveWrongServerSignature() throws Exception {
		for(int i = 0; i<stubs.size(); i++){
			byte[][] bytes = stubs.get(i).getChallenge(publicKey, Crypto.signData(privateKey, publicKey.getEncoded()));
	
			long currentTime;
			String mapKey = new String("gmail") + "||" + new String("rito");
			if(library.getMap().containsKey(mapKey)){
				currentTime = library.getTimestampFromKey(mapKey);
			}else{
				currentTime = Time.getTimeLong();
			}
			
			long l = rand.nextLong();
			byte[] t = String.valueOf(l).getBytes();
			byte[] token = Crypto.encodeBase64(Crypto.encryptRSA(serverKey.get(i), Token.nextToken(t)));
			byte[] token_wrong = Crypto.encodeBase64(Crypto.encryptRSA(serverKey.get(i), Token.nextToken(Token.nextToken(t))));
			
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
			
			byte[][] returnValue = stubs.get(i).put(publicKey, 
					 wtsEncoded,
					 d, 
					 u, 
					 p, 
					 token,
					 Crypto.signData(privateKey, Crypto.concatenateBytes(wtsEncoded,d,u,p,token_wrong)));
	
			
			long l2 = rand.nextLong();
			byte[] t2 = String.valueOf(l2).getBytes();
			byte[] token2 = Crypto.encodeBase64(Crypto.encryptRSA(serverKey.get(i), Token.nextToken(t2)));
			
			returnValue[1] = token2;
			
			int value = library.getFeedback(returnValue, bytes, t,i);
			assertEquals(value,-1);
		}
	}	
}