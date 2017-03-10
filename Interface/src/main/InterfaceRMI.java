package main;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Key;

public interface InterfaceRMI extends Remote {
    void register(Key publicKey, byte[] timestamp, byte[] signedData) throws RemoteException;
    void put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] timestamp, byte[] signedData) throws RemoteException;
    byte[] get(Key publicKey, byte[] domain, byte[] username, byte[] timestamp, byte[] signedData) throws RemoteException;
}