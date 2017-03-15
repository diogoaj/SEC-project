package main.java;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;

public class Crypto {
	
	public static byte[] encryptRSA(PublicKey key, byte[] plaintext){
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
	
	public static byte[] decryptRSA(PrivateKey key, byte[] ciphertext){
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
	
	public static byte[] signData(PrivateKey k, byte[] data){
		try{
			// generating a signature
			Signature dsaForSign = Signature.getInstance("SHA1withRSA");
			dsaForSign.initSign(k);
			dsaForSign.update(data);
			return dsaForSign.sign();
		}
		catch(Exception e){
			System.err.println("Signature exception: " + e.toString());
        	e.printStackTrace();
		}
		return null;
	}	
	
	public static boolean verifySignature(PublicKey publicKey, byte[] data, byte[] signature){
		try{
			Signature dsaForVerify = Signature.getInstance("SHA1withRSA");
			dsaForVerify.initVerify(publicKey);
			dsaForVerify.update(data);
			return dsaForVerify.verify(signature);
		}
		catch(Exception e){
			System.err.println("Retrieve password exception: " + e.toString());
        	e.printStackTrace();
		}
		return false;
	}
	
	public static byte[] decodeBase64(byte[] src){
		return Base64.getDecoder().decode(src);
	}
	
	public static byte[] encodeBase64(byte[] src){
		return Base64.getEncoder().encode(src);
	}
	
	public static byte[] concatenateBytes(byte[]... data){
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		for(int i = 0; i < data.length; i++){
			try {
				outputStream.write(data[i]);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return outputStream.toByteArray();
	}
}
