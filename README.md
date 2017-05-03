# SEC-project
Instructions:

Note: To run the tests again it is required to always delete the .ser files in the respective folders:
- ServerSide/src/main/resources/
- ClientSide/src/main/resources/

And run the ServerSide again

## To compile the project [With Maven]:
```
Compile in the main folder SEC-project/
mvn clean install compile -DskipTests
```
## Without Maven [Recommended] 
### To run Server:
```
cd ServerSide/
java -cp "target/classes/;../Interface/target/classes" main.java.PasswordServer {number_of_faults}
```

### To run Client:
```
cd ClientSide/
java -cp "target/classes/;../Interface/target/classes" main.java.Client {keystore_id} {keystore_pass} {number_of_faults}
```

## With Maven ( It is possible to run with maven but the server stops right away )
### To run Server:
```
cd ServerSide/
mvn exec:java -Dexec.mainClass="main.java.PasswordServer -Dexec.args="{number_of_faults}""
```

### To run Client:
```
cd ClientSide/
mvn exec:java -Dexec.mainClass="main.java.Client" -Dexec.args="{keystore_id} {keystore_password} {number_of_faults}"
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
