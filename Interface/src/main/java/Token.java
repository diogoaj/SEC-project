package main.java;

public class Token {
	public static byte[][] getByteList(byte[] ... data){
		int count = data.length;
		byte[][] bytes = new byte[count][];
		for(int i = 0; i < count; i++){
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
}
