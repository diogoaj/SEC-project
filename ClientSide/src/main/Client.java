package main;

import java.io.Console;
import java.security.KeyStore;

public class Client {

	//FIXME
	//CONFIRM I CAN HAVE STATIC API
	private static API library = new API();
	private static Console console = System.console();
	
	public static void main(String[] args) {
		
		if(args.length != 2){
			System.out.println("USAGE: <KeyStoreID> <password>");
			System.exit(0);
		}
		
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
        	library.init(ks, args[0], args[1]);

        	System.out.println("Welcome to Password Manager!");
        	
        	int n;
        	
        	while(true){
            	System.out.println("Choose your command:");
            	System.out.println("\n1- Register \n2- Save Password \n3- Get Password\n4- Exit");
            	
            	try { 
            		n = Integer.parseInt(console.readLine());
                } catch(NumberFormatException e) { 
                	System.out.println("Unknown Command");
                	continue;
                }
            	
            	switch(n){
            		case 1:
            			library.register_user();
            			System.out.println("User registered\n");
            			break;
            		
            		case 2:
            			save();
            			System.out.println("Password saved\n");
            			break;
            		
            		case 3:
            			byte[] retrieved = retrieve();
            			if(retrieved == null){
            				System.out.println("Password not found!\n");
            			}
            			else{
            				System.out.println("Your password is: " + new String(retrieved, "UTF-8") + "\n");
            			}
            			break;
            			
            		case 4:
            			library.close();
            			break;
            		
            		default:
            			System.out.println("Unknown Command");
            			break;
            	}
        	}
        	
        	//ks.getCertificate("clientkeystore").getPublicKey()
        	//(PrivateKey)ks.getKey("clientkeystore", "banana".toCharArray())
        	
        } catch (Exception e) {
        	System.err.println("Client exception: " + e.toString());
        	e.printStackTrace();
    	}
	}
	
	private static void save(){
		System.out.println("What domain?");
		String domain = console.readLine();
		System.out.println("What username?");
		String username = console.readLine();
		System.out.println("What password?");
		String password = console.readPassword().toString();
		library.save_password(domain.getBytes(), username.getBytes(), password.getBytes());
	}
	
	private static byte[] retrieve(){
		System.out.println("What domain?");
		String domain = console.readLine();
		System.out.println("What username?");
		String username = console.readLine();
		return library.retrieve_password(domain.getBytes(), username.getBytes());
	}
	
}