# SEC-project
Instructions:

## To compile the project [With Maven]:
```
Compile in the main folder SEC-project/
mvn clean install compile -DskipTests
```
## To run the project
```
cd ServerSide/
python run.py {number_of_faults}
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
