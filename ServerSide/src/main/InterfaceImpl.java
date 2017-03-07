package main;

import java.rmi.RemoteException;
import java.security.Key;

import main.business.PasswordEntry;
import main.business.PasswordManager;
import main.business.User;


public class InterfaceImpl implements InterfaceRMI{
	
	private PasswordManager manager;
	
	public InterfaceImpl(PasswordManager manager){
		this.manager = manager;
	}
	
	public PasswordManager getManager(){
		return manager;
	}
	
	public void register(Key publicKey) throws RemoteException {
		User user = new User(publicKey);
		manager.addUser(user);
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		User user = null;
		for (User u: manager.getUsers()){
			if(publicKey.equals(u.getKey())){
				user = u;
				break;
			}
		}
		if(user != null){
			user.addPasswordEntry(new PasswordEntry(domain, username, password));
		}else{
			System.out.println("User does not exist!");
		}
		
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		// TODO Auto-generated method stub
		return null;
	}

}
