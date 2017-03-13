package main.java;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;

public class Crypto {
	
	private static long MILLISECONDS = 2000;
	
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
	
	public static byte[] getTime(){
		long curTime = System.currentTimeMillis();
		String time = String.valueOf(curTime);
		return time.getBytes();
	}
	
	public static long decodeTime(byte[] time){
		String curTime = new String(time);
		return Long.valueOf(curTime);
	}
	
	public static boolean withinTime(long receivedTime){
		long time = System.currentTimeMillis();
		return (time >= receivedTime && time <= receivedTime + MILLISECONDS);
	}
	
	public static byte[][] getByteList(byte[] ... data){
		int count = data.length;
		byte[][] bytes = new byte[2][];
		for(int i = 0; i< count; i++){
			bytes[i] = data[i];
		}
		return bytes;
	}
	
	public static byte[] nextToken(byte[] data){
		String tokenString = new String(data);
		long tokenToSend = Long.valueOf(tokenString) + 1;
		tokenString = String.valueOf(tokenToSend);
		return tokenString.getBytes();
	}
	
	public static long getLong(byte[] data){
		String tokenString = new String(data);
		return Long.valueOf(tokenString);
	}
	
}
