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
String openSsh = privateKey.exportKey(format:'OpenSSH'));
//
RsaKey publicKey = RsaKey.importKey(openSsh);
print(publicKey == privateKey.publickey()); // True
```
