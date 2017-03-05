import java.rmi.RemoteException;
import java.security.Key;

import business.PasswordManager;
import business.User;

public class InterfaceImpl implements InterfaceRMI{
	
	private PasswordManager manager;
	
	public InterfaceImpl(PasswordManager manager){
		this.manager = manager;
	}
	
	public PasswordManager getManager(){
		return manager;
	}
	
	public void register(Key publicKey) throws RemoteException {
		User u = new User(publicKey);
		manager.addUser(u);
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		// TODO Auto-generated method stub
		
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		// TODO Auto-generated method stub
		return null;
	}

}
