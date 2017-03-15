package main.java;

public class Time {
	public static byte[] getTime(){
		long curTime = System.currentTimeMillis();
		String time = String.valueOf(curTime);
		return time.getBytes();
	}
	
	public static long getTimeLong(){
		long curTime = System.currentTimeMillis();
		return curTime;
	}
	
	public static byte[] convertTime(long time){
		String t = String.valueOf(time);
		return t.getBytes();
	}
	
	public static long decodeTime(byte[] time){
		String curTime = new String(time);
		return Long.valueOf(curTime);
	}
	
	public static long getLong(byte[] data){
		String tokenString = new String(data);
		return Long.valueOf(tokenString);
	}
}
