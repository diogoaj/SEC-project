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
			Registry registry = LocateRegistry.createRegistry(8000);
			registry.rebind("Interface", stub);
			System.out.println("Server is ready at port 8000");
			
			i.getManager().loadData();
			while(true);
			
		} catch(Exception e){
			e.printStackTrace();
		} 
	}
}
