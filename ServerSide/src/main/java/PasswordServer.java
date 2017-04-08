package main.java;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import main.java.business.PasswordManager;

public class PasswordServer{
	
	public static void main(String[] args) {
		try{
			InterfaceImpl i = new InterfaceImpl(new PasswordManager());
			InterfaceRMI stub = (InterfaceRMI) UnicastRemoteObject.exportObject(i, 0);
			Registry registry = LocateRegistry.createRegistry(8000 + Integer.parseInt(args[0]));
			registry.rebind("Interface"+Integer.parseInt(args[0]), stub);
			System.out.println("Server is ready at port 800" + args[0]);
			
			i.getManager().loadData();
			
		} catch(Exception e){
			e.printStackTrace();
		} 
	}
}
