package business;

import java.io.Serializable;

public class PasswordEntry implements Serializable{

	private static final long serialVersionUID = 2L;
	
	private byte[] domain;
	private byte[] username;
	private byte[] password;
}
