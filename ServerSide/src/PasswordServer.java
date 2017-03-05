import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import business.PasswordManager;

public class PasswordServer{
	
	public static void main(String[] args) {
		try{
			InterfaceImpl i = new InterfaceImpl(new PasswordManager());
			InterfaceRMI stub = (InterfaceRMI) UnicastRemoteObject.exportObject(i, 0);
			Registry registry = LocateRegistry.createRegistry(8000);
			registry.rebind("Interface", stub);
			System.out.println("Server is ready at port 8000");
			
			i.getManager().loadData();
			
		} catch(Exception e){
			e.printStackTrace();
		} 
	}
}
