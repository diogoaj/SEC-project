import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;

public class Client {

	public static void main(String[] args) {
		
		try {
        	Registry registry = LocateRegistry.getRegistry(8000);
        	InterfaceRMI stub = (InterfaceRMI) registry.lookup("Interface");
        	stub.register(null);
        	
        } catch (Exception e) {
        	System.err.println("Client exception: " + e.toString());
        	e.printStackTrace();
    	}
	}
}