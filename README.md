# RSA for Dart 

A new Flutter module for making RSA constant key pairs from constant password.

## Getting Started

This project is a starting point for a Flutter application.

In this progect i made comfort fro me RSA algo. 

This module can create a constant privet key from constant password.
```dart
import "package:RsaKey/RsaKey.dart";
RsaKey.generate(1024,password: 'Hello World') == RsaKey.generate(1024,password: 'Hello World'); // True
RsaKey.generate(1024,password: 'Hello World') == RsaKey.generate(1024,password: 'Hi'); // False
```

In this module represented OpenSSH only for publick keys format for RSA algo;
```dart
import "package:RsaKey/RsaKey.dart";
RsaKey privateKey = RsaKey.generate(1024,password: 'Hello World');
String openSsh = privateKey.exportKey(format:'OpenSSH');
//ssh-rsa AAAAB2Fzci1oc3MAAACBAKY6/B7ZzZYuFcYDN9V4TKNA0ofQEsgQjpoeQpS8EVR2r0Y6/DCfss7oxfnDoIx7KuBIBbLdDfkZNtLqELZGD2kJ5MmIUMynNCvdKCpq2F6m8I90pjVBj4kJWyJHXUl4VUDBsweE4oWP61WS2h/aO4lIfvw0vQ5YE/4mNPZ2mGvhAAAAFgZHEX2WupYuqQwy+F0a/lLDBhKwpvU=
RsaKey publicKey = RsaKey.importKey(openSsh);
print(publicKey == privateKey.publickey()); // True
```
