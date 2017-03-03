import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

public class PasswordServer{

	public static void main(String[] args) {
		
		try{
			InterfaceRMI stub = (InterfaceRMI) UnicastRemoteObject.exportObject(new InterfaceImpl(), 0);
			Registry registry = LocateRegistry.createRegistry(8000);
			registry.rebind("Interface", stub);
			System.out.println("Server ready");
		} catch(Exception e){
			e.printStackTrace();
		}
	}
}
