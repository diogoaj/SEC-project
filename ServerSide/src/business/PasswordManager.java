package business;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

public class PasswordManager {
	
	private List<User> users;
	
	public void addUser(User user){
		users.add(user);
	}
	
	@SuppressWarnings("unchecked")
	public void loadData(){
		try{
			FileInputStream fileIn = new FileInputStream("userData.ser");
			ObjectInputStream in = new ObjectInputStream(fileIn);
			users = (ArrayList<User>)in.readObject();
			in.close();
			fileIn.close();
		}catch(IOException e){
			e.printStackTrace();
		}catch(ClassNotFoundException c){
	        c.printStackTrace();
		}
	}
	
	public void saveData(){
		try{
			FileOutputStream fileOut = new FileOutputStream("userData.ser");
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			out.writeObject(users);
			out.close();
			fileOut.close();
		}catch(IOException e){
			e.printStackTrace();
		}
	}
}
