import 'dart:convert';
import 'dart:typed_data';


import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'RsaKey.dart';

void main() {
  var key = utf8.encode('p@ssw0rd');
  String digest = sha256.convert(key).toString();
  print((digest == 'a075d17f3d453073853f813838c15b8023b8c487038436354fe599c3942e1f95').toString());

  print('');
  RsaKey lol = RsaKey.generate(1024,password: 'idsjojdso');
  print(lol.n());
  print('');
  BigInt mess = BigInt.parse('238984792734283984729837492374894729739847927347927349729');
  print(lol.decrypt(mess));
  print(RsaKey.importKey(lol.exportKey(format:'OpenSSH')).encrypt(lol.decrypt(mess)) == mess);
  print('LOL');
  BigInt min_p = BigInt.parse('9480751908109176726832526455652159260084541744031329863792443335050652303478140824795455728407420733006933090614179782624068317238241310650437075740534632');
  BigInt  e = BigInt.parse('2348732984757349847638174698237628374682364862834421');
  // print(arc.random(exact_bits: 512) == BigInt.parse('8759492523734002772954185296163644346775720732084835037605567350343357087204673198502073297698704315148996660521711422652029717033124036683623812569692389'));
  
  

  String publickey = '''-----BEGIN PUBLIC KEY-----
MIGyMA0GCSqGSIb3DQEBAQUAA4GgADCBnAKBgQDENUCups5Fd+eQu2fMOu9Bz6ej
wpNuwlKZfwjd+dkdAoIO+/Jn7I9nF2CW/3eZiyh9FH9PhFEtbzsXOFZrmls9r6Th
a1kjHgl0R/MxkSxaZnHnhX/MEVUXn0N9PmTX1IBX5vNoDaNXHVmNmxCOoRA8uq4V
ZNM+lXFoyH7lBBWIXwIWBkcRfZa6li6pDDL4XRr+UsMGErCm9Q==
-----END PUBLIC KEY-----''';

  var po = RsaKey.importKey(publickey);





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