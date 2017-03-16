# SEC-project
Instructions

## To compile the project [With Maven]:
```
Compile in the main folder SEC-project/
mvn install compile
```
## Without Maven [Recommended] 
### To run Server:
```
cd ServerSide/
java -cp "target/classes/;../Interface/target/classes" main.java.PasswordServer
```

### To run Client:
```
cd ClientSide/
java -cp "target/classes/;../Interface/target/classes" main.java.Client {keystore_id} {keystore_pass}
```

## With Maven ( It is possible to run with maven but the server stops right away )
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

## To run Server tests:
```
cd ServerSide/
mvn test
```

## To run Client tests:
```
run Server on another terminal
cd ClientSide/
mvn test
```
