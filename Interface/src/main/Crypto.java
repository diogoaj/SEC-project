package main;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class Crypto {
	
	public static byte[] encrypt(PublicKey key, byte[] plaintext){
		try{
		    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");   
		    cipher.init(Cipher.ENCRYPT_MODE, key);  
		    return cipher.doFinal(plaintext);
		}
		catch(Exception e){
			System.err.println("Signature exception: " + e.toString());
        	e.printStackTrace();
		}
		return null;
	}
	
	public static byte[] decrypt(PrivateKey key, byte[] ciphertext){
		try{
		    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");   
		    cipher.init(Cipher.DECRYPT_MODE, key);  
		    return cipher.doFinal(ciphertext);
		}
		catch(Exception e){
			System.err.println("Signature exception: " + e.toString());
        	e.printStackTrace();
		}
		return null;
	}
	
	public static byte[] decodeBase64(byte[] src){
		return Base64.getDecoder().decode(src);
	}
	
	public static byte[] encodeBase64(byte[] src){
		return Base64.getEncoder().encode(src);
	}
	
}
