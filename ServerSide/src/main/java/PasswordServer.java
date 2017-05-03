package main.java;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import main.java.business.PasswordManager;

public class PasswordServer{
	
	public static final int DEFAULT_PORT = 8000;
	
	public static void main(String[] args) {
		
		int faults = Integer.parseInt(args[0]);
		int servers = 3*faults + 1;
			
		try{
			for (int k = 0; k < servers; k++){
				InterfaceImpl i = new InterfaceImpl(new PasswordManager());
				InterfaceRMI stub = (InterfaceRMI) UnicastRemoteObject.exportObject(i, 0);
				Registry registry = LocateRegistry.createRegistry(DEFAULT_PORT + k);
				registry.rebind("Interface"+k, stub);
				System.out.println("Server is ready at port " + (DEFAULT_PORT + k));
			}

		} catch(Exception e){
			e.printStackTrace();
		} 
	}
}
