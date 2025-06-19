SPECIFIC INFORMATION:

- Main needs to be stopped in order to obtain the tls_handshake_date.txt file from the information capture.


```
mvn clean compile &&
mvn dependency:copy-dependencies &&
mvn exec:java -Dexec.mainClass="application.Main"
```