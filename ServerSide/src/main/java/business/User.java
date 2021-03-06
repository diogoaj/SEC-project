package main.java.business;

import java.io.Serializable;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class User implements Serializable{
	
	private static final long serialVersionUID = 1L;
	
	private Key key;
	private List<PasswordEntry> userData;
	
	public User(Key key){
		this.key = key;
		userData = new ArrayList<PasswordEntry>();
	}
	
	public Key getKey(){
		return key;
	}
	
	public void addPasswordEntry(PasswordEntry p){
		for (int i = 0; i < userData.size(); i++) {
			if(Arrays.equals(userData.get(i).getDomain(), p.getDomain()) &&
				Arrays.equals(userData.get(i).getUsername(), p.getUsername())){
				userData.get(i).setPassword(p.getPassword());
				userData.get(i).setWts(p.getWts());
				System.out.println("Password Updated");
				return;
			}
		}
		userData.add(p);
	}
	
	public byte[] getPassword(byte[] domain, byte[] username){
		for (PasswordEntry p : userData){
			if(Arrays.equals(p.getDomain(), domain) &&
			   Arrays.equals(p.getUsername(), username)){
				return p.getPassword();
			}
		}
		return null;
	}
	
	public byte[] getWts(byte[] domain, byte[] username){
		for (PasswordEntry p : userData){
			if(Arrays.equals(p.getDomain(), domain) &&
			   Arrays.equals(p.getUsername(), username)){
				return p.getWts();
			}
		}
		return null;
	}

	
	public ArrayList<PasswordEntry> getData(){
		return (ArrayList<PasswordEntry>) userData;
	}

}
