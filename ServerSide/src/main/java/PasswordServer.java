package main.java;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import main.java.business.PasswordManager;

public class PasswordServer{
	
	public static final int DEFAULT_PORT = 8000;
	
	public static void main(String[] args) {
		
		int k = Integer.parseInt(args[0]);
			
		try{
			InterfaceImpl i = new InterfaceImpl(new PasswordManager(k));
			InterfaceRMI stub = (InterfaceRMI) UnicastRemoteObject.exportObject(i, 0);
			Registry registry = LocateRegistry.createRegistry(DEFAULT_PORT + k);
			registry.rebind("Interface"+k, stub);
			System.out.println("Server is ready at port " + (DEFAULT_PORT + k));


		} catch(Exception e){
			e.printStackTrace();
		} 
	}
}
