package main.java;

import java.io.Console;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;

public class Client {

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
            		case 1:{
            			int value = library.register_user();
            			
            			if(value == -1)
        					break;
        				
        				if(value == 2){
        					System.out.println("User registered\n");
        				}
        				else if(value == 1){
        					System.out.println("User token was incorrect\n");
        				}
        				else if(value == 0){
        					System.out.println("User signature was invalid\n");
        				}
        				else{
        					System.out.println("Unknown problem\n");
        				}
            			break;
            		}
            		
            		case 2:{
            			int value = save();
            			if(value == -1)
        					break;
        				
        				if(value == 3){
        					System.out.println("Passowrd saved\n");
        				}
        				else if(value == 2){
        					System.out.println("User token was incorrect\n");
        				}
        				else if(value == 1){
        					System.out.println("User signature was invalid\n");
        				}
        				else if(value == 0){
        					System.out.println("Register first!\n");
        				}
        				else{
        					System.out.println("Unknown problem\n");
        				}
            			break;
            		}
            		
            		case 3:{
            			byte[] retrieved = retrieve();
            			if(retrieved == null){
            				System.out.println("Password not found!\n");
            			}
            			else{
            				String received = new String(retrieved);
            				String[] pwd = received.split("\\|\\|");
            				System.out.println("Your password is: " + pwd[0] + "\n");
            			}
            			break;
            		}
            			
            		case 4:
            			library.close();
            			break;
            		
            		default:
            			System.out.println("Unknown Command");
            			break;
            	}
        	}        	
        } catch (Exception e) {
        	System.err.println("Client exception: " + e.toString());
        	e.printStackTrace();
    	}
	}
	
	private static int save() throws UnsupportedEncodingException{
		System.out.println("What domain?");
		String domain = console.readLine();
		System.out.println("What username?");
		String username = console.readLine();
		System.out.println("What password?");
		String password = String.valueOf(console.readPassword());
		return library.save_password(domain.getBytes(), username.getBytes(), password.getBytes());
	}
	
	private static byte[] retrieve() throws UnsupportedEncodingException{
		System.out.println("What domain?");
		String domain = console.readLine();
		System.out.println("What username?");
		String username = console.readLine();
		return library.retrieve_password(domain.getBytes(), username.getBytes());
	}
	
}