import 'dart:convert';
import 'dart:typed_data';


import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'src/RsaKey.dart';

void main() {
  RsaKey privateKey = RsaKey.generate(1024,password: 'Hello World');
  String openSsh = privateKey.exportKey(format:'OpenSSH');
  print(openSsh);
}