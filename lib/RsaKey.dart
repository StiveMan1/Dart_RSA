import 'package:test/test.dart';

import 'src/Primality.dart';

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import "package:pointycastle/export.dart";
import "package:asn1lib/asn1lib.dart";
import 'dart:convert';
import 'package:basic_utils/basic_utils.dart';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';



class RsaKey{
    static BigInt E = BigInt.parse("2348732984757349847638174698237628374682364862834421");
    BigInt _n,_e,_p,_q,_d=null,_u,_dp,_dq;
    RsaKey({String password = null ,BigInt n = null,BigInt e = null,BigInt p = null,BigInt q = null,BigInt d = null,BigInt u = null,}){
      if(n != null && e != null){
        this._n = n;
        this._e = e;
        if(p != null && q != null && d != null && u != null){
          this._q = q;
          this._p = p;
          this._d = d;
          this._u = u;
          this._dp = this._d % (this._p - BigInt.one);  // = (e⁻¹) mod (p-1)
          this._dq = this._d % (this._q - BigInt.one);  // = (e⁻¹) mod (q-1)
        }
      }
    }
    BigInt n(){
      return this._n;
    }
    BigInt e(){
      return this._e;
    }
    BigInt p(){
      if (!has_private()){
        throw("No private exponent available for public keys");
      }
      return this._p;
    }
    BigInt q(){
      if (!has_private()){
        throw("No private exponent available for public keys");
      }
      return this._q;
    }
    BigInt d(){
      if (!has_private()){
        throw("No private exponent available for public keys");
      }
      return this._d;
    }
    BigInt u(){
      if (!has_private()){
        throw("No private exponent available for public keys");
      }
      return this._u;
    }


    int size_in_bits_(){
      // """Size of the RSA modulus in bits"""
      return size_in_bits(_n);
    }
    int size_in_bytes_(){
      // """The minimal amount of bytes that can hold the RSA modulus"""
      return (size_in_bits(_n) - 1) ~/ 8 + 1;
    }

    BigInt _encrypt( plaintext){
        BigInt res = BigInt.zero;
        BigInt plain = BigInt.parse(plaintext.toString());
        while(plain > BigInt.zero){
            res*=_n;
            res+=binpow(plain%_n, _e, _n);
            plain~/=_n;
        }
        return res;
    }
    BigInt _decrypt( plaintext){
        if (!has_private()){
          throw("This is not a private key");
        }
        BigInt res = BigInt.zero;
        BigInt text = BigInt.parse(plaintext.toString());
        while (text > BigInt.zero){
            BigInt ciphertext = text%this._n;
            text~/=this._n;
            res*=this._n;
            // Blinded RSA decryption (to prevent timing attacks):
            // Step 1: Generate random secret blinding factor r,
            // such that 0 < r < n-1
            BigInt r = My_Random('').random_range(min_inclusive:BigInt.one, max_exclusive:this._n);
            // Step 2: Compute c' = c * r**e mod n
            BigInt cp = ciphertext * binpow(r, this._e, this._n) % this._n;
            // Step 3: Compute m' = c'**d mod n       (normal RSA decryption)
            BigInt m1 = binpow(cp, this._dp, this._p);
            BigInt m2 = binpow(cp, this._dq, this._q);
            BigInt h = ((m2 - m1) * this._u) % this._q;
            BigInt mp = h * this._p + m1;
            // Step 4: Compute m = m**(r-1) mod n
            res+= (inverse(r, this._n) * mp) % this._n;
        }
        // Verify no faults occurred
        return res;
    }

    bool has_private(){
        // """Whether this is an RSA private key"""
        return (this._d != null);
    }
    bool can_encrypt(){  // legacy
        return true;
    }
    bool can_sign(){     // legacy
        return true;
    }

    RsaKey publickey(){
      return RsaKey(n:_n, e:_e);
    }

    String exportKey({format='PEM', passphrase=null, pkcs=1, protection=null, randfunc=null}){

        if(randfunc == null){
            randfunc = My_Random('LOLLSKASKL');
        }

        if(format == 'OpenSSH'){
          List<int> str_bytes = str_to_bytes('ssh-rsa');
          List<int> n_bytes = to_bytes(_n);
          List<int> e_bytes = to_bytes(_e);

          if (n_bytes[0] & 0x80 == 0x80){
            n_bytes = [0] + n_bytes;
          }
          if (e_bytes[0] & 0x80 == 0x80){
            e_bytes = [0] + e_bytes;
          }

          str_bytes = pack_len(str_bytes.length) + str_bytes;
          n_bytes = pack_len(n_bytes.length) + n_bytes;
          e_bytes = pack_len(e_bytes.length) + e_bytes;
          return 'ssh-rsa ' + base64.encode(str_bytes + n_bytes + e_bytes);
        }
        if(format == 'Sakaar'){
          List<int> n_bytes = to_bytes(_n);

          if (n_bytes[0] & 0x80 == 0x80){
            n_bytes = [0] + n_bytes;
          }
          n_bytes = pack_len(n_bytes.length) + n_bytes;
          return base64.encode(n_bytes);
        }
        String key_type = '';
        if(has_private()){
          return RSAPKCSParser.encodePrivateKeyToPem(this);
        }else{
          return RSAPKCSParser.encodePublicKeyToPem(this);
        }

        throw("Unknown key format '" + format.toString() + "'. Cannot export the RSA key.");
    }


    // Backward compatibility

    // Methods defined in PyCryptoCore that we don't support anymore
    sign( M, K){
        throw("Use module CryptoCore.Signature.pkcs1_15 instead");
    }
    verify( M, signature){
        throw("Use module CryptoCore.Signature.pkcs1_15 instead");
    }

    BigInt encrypt( message){
        // Step 3b (RSAEP)
        BigInt mint = this._encrypt(message);
        // Step 3c (I2OSP)
        return mint;
    }
    BigInt decrypt( message){
        BigInt mint = this._decrypt(message);
        // Complete step 2c (I2OSP)
        return mint;
    }

    blind(M, B){
        throw 'NotImplementedError';
    }
    unblind(M, B){
        throw 'NotImplementedError';
    }
    size(M, B){
        throw 'NotImplementedError';
    }
  static RsaKey importKey(String extern_key, {passphrase=null}){

    // from CryptoCore.IO import PEM;

    // extern_key = tobytes(extern_key);
    // if(passphrase !=  null){
    //     passphrase = tobytes(passphrase);
    // }

    if (extern_key.startsWith('-----BEGIN OPENSSH PRIVATE KEY')){
        // String text_encoded = extern_key.toString();
        // openssh_encoded, marker, enc_flag = PEM.decode(text_encoded, passphrase);
        // result = _import_openssh_private_rsa(openssh_encoded, passphrase);
        // return result;
    }

    if (extern_key.startsWith('-----')){
        return RSAPKCSParser().parsePEM(extern_key);
    }

    if(extern_key.startsWith('ssh-rsa ')){
        String lol = extern_key.split(' ')[1];
        List<int> list = base64.decode(lol);

        
        var len = unpack_len(list.sublist(0,4));
        list = list.sublist(len+4);

        // Get n
        len = unpack_len(list.sublist(0,4));
        BigInt n = from_bytes(list.sublist(4,len+4));
        list = list.sublist(len+4);

        // Get e
        len = unpack_len(list.sublist(0,4));
        BigInt e = from_bytes(list.sublist(4,len+4));
        list = list.sublist(len+4);

        return RsaKey(n: n , e: e);
    }
    if(extern_key.startsWith('Sakaar: ')){
        String lol = extern_key.split(' ')[1];
        List<int> list = base64.decode(lol);
        var len = unpack_len(list.sublist(0,4));
        BigInt n = from_bytes(list.sublist(4,len+4));
        list = list.sublist(len+4);

        return RsaKey(n: n , e: RsaKey.E);
    }

    throw("RSA key format is not supported");

  }
  // Genaratink private key from random function or password
  static generate(bits, {My_Random randfunc = null, String password = null}){
    if(password == null && randfunc == null){
      throw("randfunc and password can not be both None");
    }
    if(password != null){
      randfunc = My_Random(password);
    }
    BigInt e = BigInt.parse('2348732984757349847638174698237628374682364862834421');
    BigInt d = BigInt.from(1);
    BigInt n = d;
    BigInt p;
    BigInt q;
    BigInt lcm;
    int size_q;
    int size_p;
    BigInt min_q;
    BigInt min_p;
    BigInt min_distance;
    while(size_in_bits(n) != bits && d < (BigInt.one << (bits ~/ 2))){
        size_q = bits ~/ 2;
        size_p = bits - size_q;

        min_q = sqrt(BigInt.from(1) << (2 * size_q - 1));
        min_p = min_q;
        if (size_q != size_p){
            min_p = sqrt(BigInt.from(1) << (2 * size_p - 1));
        }

        p = generate_probable_prime(exact_bits:size_p,  randfunc:randfunc, prime_filter : (BigInt candidate){
            return candidate > min_p && (candidate - BigInt.one).gcd(e) == BigInt.one;
        });
        min_distance = BigInt.one << (bits ~/ 2 - 100);

        q = generate_probable_prime(exact_bits:size_q,
                                    randfunc:randfunc,prime_filter:(BigInt candidate){
          return (candidate > min_q && (candidate - BigInt.one).gcd(e) == BigInt.one && abs(candidate - p) > min_distance);
        });

        n = p * q;
        lcm = LCM(p - BigInt.one, q - BigInt.one);
        d = inverse(e, lcm);
    }
    if (p > q){
      BigInt x = q;
      q = p;
      p = x;
    }

    var u = inverse(p, q);
    // throw("LOL");

    return RsaKey(n:n, e:e, d:d, p:p, q:q, u:u);
  }
}



/// Parser From Pem format of rsa keys
class RSAPKCSParser {
  
  static const String pkcsHeader = '-----';
  static const String pkcs1PublicHeader = '-----BEGIN RSA PUBLIC KEY-----';
  static const String pkcs8PublicHeader = '-----BEGIN PUBLIC KEY-----';
  static const String pkcs1PublicFooter = '-----END RSA PUBLIC KEY-----';
  static const String pkcs8PublicFooter = '-----END PUBLIC KEY-----';

  static const String pkcs1PrivateHeader = '-----BEGIN RSA PRIVATE KEY-----';
  static const String pkcs8PrivateHeader = '-----BEGIN PRIVATE KEY-----';
  static const String pkcs1PrivateFooter = '-----END RSA PRIVATE KEY-----';
  static const String pkcs8PrivateFooter = '-----END PRIVATE KEY-----';

  static const String pkcs8PrivateEncHeader =
      '-----BEGIN ENCRYPTED PRIVATE KEY-----';
  static const String pkcs8PrivateEncFooter =
      '-----END ENCRYPTED PRIVATE KEY-----';

  static const String certHeader = '-----BEGIN CERTIFICATE-----';
  static const String certFooter = '-----END CERTIFICATE-----';

  /// Parse PEM
  RsaKey parsePEM(String pem, {String password}) {
    final List<String> lines = pem
        .split('\n')
        .map((String line) => line.trim())
        .where((String line) => line.isNotEmpty)
        // .skipWhile((String line) => !line.startsWith(pkcsHeader))
        .toList();
    if (lines.isEmpty) {
      _error('format error');
    }
    RsaKey publicKey = _publicKey(lines);
    RsaKey privateKey = _privateKey(lines);
    if(privateKey != null){
      return privateKey;
    }else if(publicKey != null){
      return publicKey;
    }
  }

  RsaKey _privateKey(List<String> lines, {String password}) {
    int header;
    int footer;

    if (lines.contains(pkcs1PrivateHeader)) {
      header = lines.indexOf(pkcs1PrivateHeader);
      footer = lines.indexOf(pkcs1PrivateFooter);
    } else if (lines.contains(pkcs8PrivateHeader)) {
      header = lines.indexOf(pkcs8PrivateHeader);
      footer = lines.indexOf(pkcs8PrivateFooter);
    } else if (lines.contains(pkcs8PrivateEncHeader)) {
      header = lines.indexOf(pkcs8PrivateEncHeader);
      footer = lines.indexOf(pkcs8PrivateEncFooter);
    } else {
      return null;
    }
    if (footer < 0) {
      _error('format error : cannot find footer');
    }
    final String key = lines.sublist(header + 1, footer).join('');
    final Uint8List keyBytes = Uint8List.fromList(base64.decode(key));
    final ASN1Parser p = ASN1Parser(keyBytes);

    final ASN1Sequence seq = p.nextObject();

    if (lines[header] == pkcs1PrivateHeader) {
      return _pkcs1PrivateKey(seq);
    } else if (lines[header] == pkcs8PrivateHeader) {
      return _pkcs8PrivateKey(seq);
    } else {
      return _pkcs8PrivateEncKey(seq, password);
    }
  }

  RsaKey _pkcs8CertificatePrivateKey(ASN1Sequence seq) {
    if (seq.elements.length != 3) _error('Bad certificate format');
    var certificate = seq.elements[0] as ASN1Sequence;

    var subjectPublicKeyInfo = certificate.elements[6] as ASN1Sequence;

    return _pkcs8PublicKey(subjectPublicKeyInfo);
  }

  RsaKey _pkcs8PrivateEncKey(ASN1Sequence seq, String password) {
    throw UnimplementedError();
  }

  RsaKey _pkcs1PrivateKey(ASN1Sequence seq) {
    final List<ASN1Integer> asn1Ints = seq.elements.cast<ASN1Integer>();
    final RsaKey key = RsaKey(
      n: asn1Ints[1].valueAsBigInteger,
      d: asn1Ints[3].valueAsBigInteger,
      p: asn1Ints[4].valueAsBigInteger,
      q: asn1Ints[5].valueAsBigInteger,
      e: asn1Ints[2].valueAsBigInteger,
      u: inverse(asn1Ints[4].valueAsBigInteger, asn1Ints[5].valueAsBigInteger)
    );
    // for(int i=0;i<9;i++){
    //   print(i);
    //   print(asn1Ints[i].valueAsBigInteger);
    // }
    return key;
  }

  RsaKey _pkcs8PrivateKey(ASN1Sequence seq) {
    final ASN1OctetString os = seq.elements[2];
    final ASN1Parser p = ASN1Parser(os.valueBytes());
    return _pkcs1PrivateKey(p.nextObject());
  }

  RsaKey _publicKey(List<String> lines) {
    int header;
    int footer;
    if (lines.contains(pkcs1PublicHeader)) {
      header = lines.indexOf(pkcs1PublicHeader);
      footer = lines.indexOf(pkcs1PublicFooter);
    } else if (lines.contains(pkcs8PublicHeader)) {
      header = lines.indexOf(pkcs8PublicHeader);
      footer = lines.indexOf(pkcs8PublicFooter);
    } else if (lines.contains(certHeader)) {
      header = lines.indexOf(certHeader);
      footer = lines.indexOf(certFooter);
    } else {
      return null;
    }
    if (footer < 0) {
      _error('format error : cannot find footer');
    }
    final String key = lines.sublist(header + 1, footer).join('');
    final Uint8List keyBytes = Uint8List.fromList(base64.decode(key));
    final ASN1Parser p = ASN1Parser(keyBytes);

    final ASN1Sequence seq = p.nextObject();

    if (lines[header] == pkcs1PublicHeader) {
      return _pkcs1PublicKey(seq);
    }
    if (lines[header] == pkcs1PublicHeader) {
      return _pkcs1PublicKey(seq);
    } else if (lines[header] == certHeader) {
      return _pkcs8CertificatePrivateKey(seq);
    } else {
      return _pkcs8PublicKey(seq);
    }
  }

  RsaKey _pkcs1PublicKey(ASN1Sequence seq) {
    final List<ASN1Integer> asn1Ints = seq.elements.cast<ASN1Integer>();
    RsaKey key = RsaKey(n: asn1Ints[0].valueAsBigInteger, e: asn1Ints[1].valueAsBigInteger);
    return key;
  }

  RsaKey _pkcs8PublicKey(ASN1Sequence seq) {
    final ASN1BitString os = seq.elements[1]; //ASN1OctetString or ASN1BitString
    final Uint8List bytes = os.valueBytes().sublist(1);
    final ASN1Parser p = ASN1Parser(bytes);
    return _pkcs1PublicKey(p.nextObject());
  }

  void _error(String msg) {
    throw FormatException(msg);
  }
  static String encodePublicKeyToPem(RsaKey publicKey) {
      var algorithmSeq = new ASN1Sequence();
      var algorithmAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList([0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
      var paramsAsn1Obj = new ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
      algorithmSeq.add(algorithmAsn1Obj);
      algorithmSeq.add(paramsAsn1Obj);

      var publicKeySeq = new ASN1Sequence();
      publicKeySeq.add(ASN1Integer(publicKey.n()));
      publicKeySeq.add(ASN1Integer(publicKey.e()));
      var publicKeySeqBitString = new ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

      var topLevelSeq = new ASN1Sequence();
      topLevelSeq.add(algorithmSeq);
      topLevelSeq.add(publicKeySeqBitString);
      var dataBase64 = base64.encode(topLevelSeq.encodedBytes);
      String res = '';
      for(int i=0;i<dataBase64.length;i++){
        if(i%64 == 0){
          res+='\n';
        }
        res += dataBase64[i];
      }
      return """-----BEGIN PUBLIC KEY-----\r$res\r\n-----END PUBLIC KEY-----""";
  }

  static String encodePrivateKeyToPem(RsaKey privateKey) {
      var version = ASN1Integer(BigInt.from(0));

      ASN1Sequence privateKeySeq = new ASN1Sequence();

      privateKeySeq.add(version);
      privateKeySeq.add(ASN1Integer(privateKey._n));
      privateKeySeq.add(ASN1Integer(privateKey._e));
      privateKeySeq.add(ASN1Integer(privateKey._d));
      privateKeySeq.add(ASN1Integer(privateKey._p));
      privateKeySeq.add(ASN1Integer(privateKey._q));
      privateKeySeq.add(ASN1Integer(privateKey._d % (privateKey._p - BigInt.from(1))));
      privateKeySeq.add(ASN1Integer(privateKey._d % (privateKey._q - BigInt.from(1))));
      privateKeySeq.add(ASN1Integer(inverse(privateKey._q, privateKey._p)));
      
      var dataBase64 = base64.encode(privateKeySeq.encodedBytes);
      var chunks =( StringUtils.chunk(dataBase64, 64)).join('\n');
      return """-----BEGIN RSA PRIVATE KEY-----\n$chunks\n-----END RSA PRIVATE KEY-----""";
  }
}



// import 'dart:convert';
// import 'dart:math';
// import 'dart:typed_data';
// import 'package:encrypt/encrypt.dart';
// import "package:pointycastle/export.dart";
// import "package:asn1lib/asn1lib.dart";

// import 'fixed_secure_random.dart';

List<int> decodePEM(String pem) {
    var startsWith = [
        "-----BEGIN PUBLIC KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n",
    ];
    var endsWith = [
        "-----END PUBLIC KEY-----",
        "-----END PRIVATE KEY-----",
        "-----END PGP PUBLIC KEY BLOCK-----",
        "-----END PGP PRIVATE KEY BLOCK-----",
    ];
    bool isOpenPgp = pem.indexOf('BEGIN PGP') != -1;

    for (var s in startsWith) {
        if (pem.startsWith(s)) {
            pem = pem.substring(s.length);
        }
    }

    for (var s in endsWith) {
        if (pem.endsWith(s)) {
            pem = pem.substring(0, pem.length - s.length);
        }
    }

    if (isOpenPgp) {
        var index = pem.indexOf('\r\n');
        pem = pem.substring(0, index);
    }

    pem = pem.replaceAll('\n', '');
    pem = pem.replaceAll('\r', '');

    return base64.decode(pem);
}