package main.java.business;

import java.io.Serializable;

public class PasswordEntry implements Serializable{

	private static final long serialVersionUID = 1L;
	
	private byte[] domain;
	private byte[] username;
	private byte[] password;
	private byte[] wts;
	
	public PasswordEntry(byte[] domain, byte[] username, byte[] password, byte[] wts){
		this.domain = domain;
		this.username = username;
		this.password = password;
		this.wts = wts;
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
	
	public byte[] getWts(){
		return wts;
	}
	
	public void setWts(byte[] wts){
		this.wts = wts;
	}
	
	public void setPassword(byte[] password){
		this.password = password;
	}
}
