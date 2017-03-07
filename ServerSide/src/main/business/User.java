package main.business;

import java.io.Serializable;
import java.security.Key;
import java.util.ArrayList;
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
		int found = 0;
		for (int i = 0; i < userData.size(); i++) {
			if(userData.get(i).getDomain().equals(p.getDomain()) &&
			   userData.get(i).getUsername().equals(p.getUsername())){
				userData.get(i).setPassword(p.getPassword());
				System.out.println("Password Updated");
				found = 1;
				break;
			}
		}
		
		if (found == 0){
			userData.add(p);
		}
	}
	
	public byte[] getPassword(byte[] domain, byte[] username){
		for (PasswordEntry p : userData){
			if(p.getDomain().equals(domain) &&
			   p.getUsername().equals(username)){
				return p.getPassword();
			}
		}
		return null;
	}

}
