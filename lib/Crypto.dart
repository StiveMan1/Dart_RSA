import 'dart:convert';
import 'dart:typed_data';


import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'src/RsaKey.dart';

void main() {
  RsaKey privateKey = RsaKey.generate(1024,password: 'Hello World');
  String openSsh = privateKey.exportKey(format:'OpenSSH');
  print(openSsh);
  // group('A group of RSA Key Tests', () {
  //   RSAKeypair rsaKeypair;
  //   Uint8List message;

  //   setUp(() {
  //     rsaKeypair = RSAKeypair.fromRandom(keySize: 1024);
  //     message =
  //         utf8.encode(DateTime.now().millisecondsSinceEpoch.toRadixString(16));
  //   });

  //   test('Private Key to String and back', () {
  //     var privateKeyString = rsaKeypair.privateKey.toString();
  //     print(privateKeyString);
  //     var privateKey = RSAPrivateKey.fromString(privateKeyString);
  //     expect(privateKey.toString(), privateKeyString);
  //   });

  //   test('Public Key to string and back', () {
  //     var publicKeyString = rsaKeypair.publicKey.toString();
  //     print(publicKeyString);
  //     var publicKey = RSAPublicKey.fromString(publicKeyString);
  //     expect(publicKey.toString(), publicKeyString);
  //   });

  //   test('Get Public Key from Privat Key', () {
  //     var publicKeyString = rsaKeypair.privateKey.publicKey.toString();
  //     expect(publicKeyString, rsaKeypair.publicKey.toString());
  //   });

  //   test('Get Public Key from PEM-String', () {
  //     var publicKeyString = rsaKeypair.publicKey.toString();
  //     var publicKey = RSAPublicKey.fromPEM(rsaKeypair.publicKey.toPEM());
  //     expect(publicKey.toString(), publicKeyString);
  //   });

  //   test('Get Private Key from PEM-String', () {
  //     var privateKeyString = rsaKeypair.privateKey.toString();
  //     var privateKey = RSAPrivateKey.fromPEM(rsaKeypair.privateKey.toPEM());
  //     expect(privateKey.toString(), privateKeyString);
  //   });

  //   test('Sign and Verify deprecated', () {
  //     var signature =
  //         // ignore: deprecated_member_use_from_same_package
  //         rsaKeypair.privateKey.createSignature(utf8.decode(message));
  //     var verified =
  //         // ignore: deprecated_member_use_from_same_package
  //         rsaKeypair.publicKey.verifySignature(utf8.decode(message), signature);
  //     expect(verified, isTrue);
  //   });

  //   test('Sign and Verify SHA-256', () {
  //     var signature = rsaKeypair.privateKey.createSHA256Signature(message);
  //     var verified =
  //         rsaKeypair.publicKey.verifySHA256Signature(message, signature);
  //     expect(verified, isTrue);
  //   });
  //   test('Sign and Verify SHA-512', () {
  //     var signature = rsaKeypair.privateKey.createSHA512Signature(message);
  //     var verified =
  //         rsaKeypair.publicKey.verifySHA512Signature(message, signature);
  //     expect(verified, isTrue);
  //   });

  //   test('Encrypt and Decrypt data', () {
  //     var encrypted = rsaKeypair.publicKey.encryptData(message);
  //     var decrypted = rsaKeypair.privateKey.decryptData(encrypted);
  //     expect(decrypted, message);
  //   });

  //   test('Encrypt and Decrypt string', () {
  //     var encrypted = rsaKeypair.publicKey.encrypt(utf8.decode(message));
  //     var decrypted = utf8.encode(rsaKeypair.privateKey.decrypt(encrypted));
  //     expect(decrypted, message);
  //   });

  //   test('Private key PEM-String is formatted', () {
  //     expect(
  //         (rsaKeypair.privateKey
  //                 .toFormattedPEM()
  //                 .split('\n')
  //                 .map((l) => l.length)
  //                 .toList()
  //                   ..sort())
  //             .last,
  //         64);
  //   });

  //   test('Public key PEM-String is formatted', () {
  //     expect(
  //         (rsaKeypair.publicKey
  //                 .toFormattedPEM()
  //                 .split('\n')
  //                 .map((l) => l.length)
  //                 .toList()
  //                   ..sort())
  //             .last,
  //         64);
  //     expect(rsaKeypair.publicKey.toFormattedPEM().length, 450);
  //   });
  // });

}