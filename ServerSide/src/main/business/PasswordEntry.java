package main.business;

import java.io.Serializable;

public class PasswordEntry implements Serializable{

	private static final long serialVersionUID = 1L;
	
	private byte[] domain;
	private byte[] username;
	private byte[] password;
	
	public PasswordEntry(byte[] domain, byte[] username, byte[] password){
		this.domain = domain;
		this.username = username;
		this.password = password;
	}
	
	public byte[] getDomain(){
		return domain;
	}
	
	public byte[] getUsername(){
		return username;
	}
	
	public byte[] getPassword(){
		return password;
	}
	
	public void setPassword(byte[] password){
		this.password = password;
	}
}
