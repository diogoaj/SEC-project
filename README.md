# SEC-project
Repository for the SEC project course

## To compile the project:
```
1. Compile in the main folder SEC-project/
2. mvn install compile
```

### To run Server:
```
cd ServerSide/
mvn exec:java -Dexec.mainClass="main.java.PasswordServer"
```

### To run Client:
```
cd ClientSide/
mvn exec:java -Dexec.mainClass="main.java.Client" -Dexec.args="{keystore_id} {keystore_password}"
```
