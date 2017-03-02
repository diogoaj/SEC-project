package main.client;

import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import main.server.InterfaceRMI;

public class Client {

	public static void main(String[] args) {
		
		String host = (args.length < 1) ? null : args[0];
		
		try {
        	Registry registry = LocateRegistry.getRegistry(host);
        	InterfaceRMI stub = (InterfaceRMI) registry.lookup("Interface");
        	System.out.println("stub found");
        } catch (Exception e) {
        	System.err.println("Client exception: " + e.toString());
        	e.printStackTrace();
    	}
	}
}