package main.server;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import main.interfaces.InterfaceRMI;

public class PasswordServer{

	public static void main(String[] args) {
		
		try{
			InterfaceRMI stub = new InterfaceImpl();
			Registry registry = LocateRegistry.createRegistry(2100);
			registry.rebind("Interface", stub);
			System.out.println("Server ready");
		} catch(Exception e){
			e.printStackTrace();
		}
	}
}
