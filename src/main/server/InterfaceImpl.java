package main.server;

import java.rmi.RemoteException;
import java.security.Key;

import main.interfaces.InterfaceRMI;

public class InterfaceImpl implements InterfaceRMI{

	public void register(Key publicKey) throws RemoteException {
		// TODO Auto-generated method stub
		
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		// TODO Auto-generated method stub
		
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		// TODO Auto-generated method stub
		return null;
	}

}
