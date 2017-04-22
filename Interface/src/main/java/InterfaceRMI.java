package main.java;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Key;

public interface InterfaceRMI extends Remote {
    byte[][] register(Key publicKey, byte[] token, byte[] signedData) throws RemoteException;
    byte[][] put(Key publicKey, byte[] wts, byte[] domain, byte[] username, byte[] password, byte[] token, byte[] signedData) throws RemoteException;
    byte[][] get(Key publicKey, byte[] domain, byte[] username, byte[] token, byte[] signedData) throws RemoteException;
    byte[][] getChallenge(Key publicKey, byte[] signedData) throws RemoteException;
}