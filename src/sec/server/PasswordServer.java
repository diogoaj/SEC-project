package sec.server;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.Key;

public class PasswordServer implements InterfaceRMI{

	@Override
	public void register(Key publicKey) throws RemoteException {
		// TODO Auto-generated method stub
	}

	@Override
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		// TODO Auto-generated method stub
	}

	@Override
	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		// TODO Auto-generated method stub
		return null;
	}
	
	public static void main(String[] args) {
		try{
			PasswordServer s = new PasswordServer();
			InterfaceRMI stub = (InterfaceRMI) UnicastRemoteObject.exportObject(s, 0);
			
			Registry registry = LocateRegistry.getRegistry();
			registry.bind("Interface", stub);
			
			System.out.println("Server ready");
		} catch(Exception e){
			System.err.println("Server exception: " + e.toString());
			e.printStackTrace();
		}
	}


}
