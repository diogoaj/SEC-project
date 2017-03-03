import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Key;

public interface InterfaceRMI extends Remote {
    void register(Key publicKey) throws RemoteException;
    void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException;
    byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException;
}