import java.security.KeyStore;
import java.io.FileInputStream;
import java.security.PrivateKey;

public class Client {

	public static void main(String[] args) {
		
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
        	API library = new API();
        	library.init(ks, "banana");
        	
        	//ks.getCertificate("clientkeystore").getPublicKey()
        	//(PrivateKey)ks.getKey("clientkeystore", "banana".toCharArray())
        	
        } catch (Exception e) {
        	System.err.println("Client exception: " + e.toString());
        	e.printStackTrace();
    	}
	}
}