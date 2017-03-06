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

}
