import 'Primality.dart';

import 'dart:convert';
import 'dart:typed_data';
import "package:asn1lib/asn1lib.dart";
// import 'dart:convert';
import 'package:basic_utils/basic_utils.dart';
// import 'dart:typed_data';
// import 'package:asn1lib/asn1lib.dart';



class RsaKey{
    static BigInt E = BigInt.parse("2348732984757349847638174698237628374682364862834421");
    BigInt? _n,_e,_p,_q,_d,_u,_dp,_dq;
    RsaKey({String? password,BigInt? n,BigInt? e,BigInt? p,BigInt? q,BigInt? d,BigInt? u,}){
      if(n != null && e != null){
        this._n = n;
        this._e = e;
        if(p != null && q != null && d != null && u != null){
          this._q = q;
          this._p = p;
          this._d = d;
          this._u = u;
          this._dp = this._d! % (this._p! - BigInt.one);  // = (e⁻¹) mod (p-1)
          this._dq = this._d! % (this._q! - BigInt.one);  // = (e⁻¹) mod (q-1)
        }
      }
    }
    BigInt? n(){
      return this._n;
    }
    BigInt? e(){
      return this._e;
    }
    BigInt? p(){
      if (!hasPrivate()){
        throw("No private exponent available for public keys");
      }
      return this._p;
    }
    BigInt? q(){
      if (!hasPrivate()){
        throw("No private exponent available for public keys");
      }
      return this._q;
    }
    BigInt? d(){
      if (!hasPrivate()){
        throw("No private exponent available for public keys");
      }
      return this._d;
    }
    BigInt? u(){
      if (!hasPrivate()){
        throw("No private exponent available for public keys");
      }
      return this._u;
    }

    BigInt _encrypt( plaintext){
        BigInt res = BigInt.zero;
        BigInt plain = BigInt.parse(plaintext.toString());
        while(plain > BigInt.zero){
            res*=_n!;
            res+=binpow(plain%_n!, _e!, _n!);
            plain~/=_n!;
        }
        return res;
    }
    BigInt _decrypt( plaintext){
        if (!hasPrivate()){
          throw("This is not a private key");
        }
        BigInt res = BigInt.zero;
        BigInt text = BigInt.parse(plaintext.toString());
        while (text > BigInt.zero){
            BigInt ciphertext = text%this._n!;
            text~/=this._n!;
            res*=this._n!;
            // Blinded RSA decryption (to prevent timing attacks):
            // Step 1: Generate random secret blinding factor r,
            // such that 0 < r < n-1
            BigInt r = MyRandom('').randomRange(minInclusive:BigInt.one, maxExclusive:this._n);
            // Step 2: Compute c' = c * r**e mod n
            BigInt cp = ciphertext * binpow(r, this._e!, this._n!) % this._n!;
            // Step 3: Compute m' = c'**d mod n       (normal RSA decryption)
            BigInt m1 = binpow(cp, this._dp!, this._p!);
            BigInt m2 = binpow(cp, this._dq!, this._q!);
            BigInt h = ((m2 - m1) * this._u!) % this._q!;
            BigInt mp = h * this._p! + m1;
            // Step 4: Compute m = m**(r-1) mod n
            res+= (inverse(r, this._n!) * mp) % this._n!;
        }
        // Verify no faults occurred
        return res;
    }

    bool hasPrivate(){
        // """Whether this is an RSA private key"""
        return (this._d != null);
    }
    bool canEncrypt(){  // legacy
        return true;
    }
    bool canSign(){     // legacy
        return true;
    }

    RsaKey publickey(){
      return RsaKey(n:_n, e:_e);
    }

    String exportKey({format='PEM', passphrase, pkcs=1, protection, randfunc}){

        if(randfunc == null){
            randfunc = MyRandom('LOLLSKASKL');
        }

        if(format == 'OpenSSH'){
          List<int> strBytes = str2Bytes('ssh-rsa');
          List<int> nBytes = toBytes(_n!);
          List<int> eBytes = toBytes(_e!);

          if (nBytes[0] & 0x80 == 0x80){
            nBytes = [0] + nBytes;
          }
          if (eBytes[0] & 0x80 == 0x80){
            eBytes = [0] + eBytes;
          }

          strBytes = packLength(strBytes.length) + strBytes;
          nBytes = packLength(nBytes.length) + nBytes;
          eBytes = packLength(eBytes.length) + eBytes;
          return 'ssh-rsa ' + base64.encode(strBytes + nBytes + eBytes);
        }
        if(format == 'Sakaar'){
          List<int> nBytes = toBytes(_n!);

          if (nBytes[0] & 0x80 == 0x80){
            nBytes = [0] + nBytes;
          }
          nBytes = packLength(nBytes.length) + nBytes;
          return base64.encode(nBytes);
        }
        if(hasPrivate()){
          return RSAPKCSParser.encodePrivateKeyToPem(this);
        }else{
          return RSAPKCSParser.encodePublicKeyToPem(this);
        }
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
  static RsaKey importKey(String externKey, {passphrase}){

    // from CryptoCore.IO import PEM;

    // extern_key = tobytes(extern_key);
    // if(passphrase !=  null){
    //     passphrase = tobytes(passphrase);
    // }

    if (externKey.startsWith('-----BEGIN OPENSSH PRIVATE KEY')){
        // String text_encoded = extern_key.toString();
        // openssh_encoded, marker, enc_flag = PEM.decode(text_encoded, passphrase);
        // result = _import_openssh_private_rsa(openssh_encoded, passphrase);
        // return result;
    }

    if (externKey.startsWith('-----')){
        return RSAPKCSParser().parsePem(externKey)!;
    }

    if(externKey.startsWith('ssh-rsa ')){
        String lol = externKey.split(' ')[1];
        List<int> list = base64.decode(lol);

        
        var len = unpackLength(list.sublist(0,4));
        list = list.sublist(len+4);

        // Get n
        len = unpackLength(list.sublist(0,4));
        BigInt n = fromBytes(list.sublist(4,len+4));
        list = list.sublist(len+4);

        // Get e
        len = unpackLength(list.sublist(0,4));
        BigInt e = fromBytes(list.sublist(4,len+4));
        list = list.sublist(len+4);

        return RsaKey(n: n , e: e);
    }
    if(externKey.startsWith('Sakaar: ')){
        String lol = externKey.split(' ')[1];
        List<int> list = base64.decode(lol);
        var len = unpackLength(list.sublist(0,4));
        BigInt n = fromBytes(list.sublist(4,len+4));
        list = list.sublist(len+4);

        return RsaKey(n: n , e: RsaKey.E);
    }

    throw("RSA key format is not supported");

  }
  // Genaratink private key from random function or password
  static generate(bits, {MyRandom? randfunc, String? password}){
    if(password == null && randfunc == null){
      throw("randfunc and password can not be both None");
    }
    if(password != null){
      randfunc = MyRandom(password);
    }
    BigInt e = BigInt.parse('2348732984757349847638174698237628374682364862834421');
    BigInt d = BigInt.from(1);
    BigInt n = d;
    BigInt? p;
    BigInt? q;
    int? sizeQ;
    int? sizeP;
    BigInt? minQ;
    BigInt? minP;
    BigInt? minDistance;
    while(sizeInBits(n) != bits && d < (BigInt.one << (bits ~/ 2))){
        sizeQ = bits ~/ 2;
        sizeP = bits - sizeQ;

        minQ = sqrt(BigInt.from(1) << (2 * sizeQ! - 1));
        minP = minQ;
        if (sizeQ != sizeP){
            minP = sqrt(BigInt.from(1) << (2 * sizeP! - 1));
        }

        p = generateProbablePrime(exactBits:sizeP,  randfunc:randfunc, primeFilter : (BigInt candidate){
            return candidate > minP! && (candidate - BigInt.one).gcd(e) == BigInt.one;
        });
        minDistance = BigInt.one << (bits ~/ 2 - 100);

        q = generateProbablePrime(exactBits:sizeQ,
                                    randfunc:randfunc,primeFilter:(BigInt candidate){
          return (candidate > minQ! && (candidate - BigInt.one).gcd(e) == BigInt.one && abs(candidate - p!) > minDistance!);
        });

        n = p * q;
        d = inverse(e, lcm(p - BigInt.one, q - BigInt.one));
    }
    if (p! > q!){
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
  RsaKey? parsePem(String pem, {String? password}) {
    final List<String> lines = pem
        .split('\n')
        .map((String line) => line.trim())
        .where((String line) => line.isNotEmpty)
        // .skipWhile((String line) => !line.startsWith(pkcsHeader))
        .toList();
    if (lines.isEmpty) {
      _error('format error');
    }
    RsaKey? publicKey = _publicKey(lines);
    RsaKey? privateKey = _privateKey(lines);
    if(privateKey != null){
      return privateKey;
    }else if(publicKey != null){
      return publicKey;
    }
    return null;
  }

  RsaKey? _privateKey(List<String> lines, {String? password}) {
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

    final ASN1Sequence seq = p.nextObject() as ASN1Sequence;

    if (lines[header] == pkcs1PrivateHeader) {
      return _pkcs1PrivateKey(seq);
    } else if (lines[header] == pkcs8PrivateHeader) {
      return _pkcs8PrivateKey(seq);
    } else {
      return _pkcs8PrivateEncKey(seq, password!);
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
      u: inverse(asn1Ints[4].valueAsBigInteger as BigInt, asn1Ints[5].valueAsBigInteger as BigInt)
    );
    // for(int i=0;i<9;i++){
    //   print(i);
    //   print(asn1Ints[i].valueAsBigInteger);
    // }
    return key;
  }

  RsaKey _pkcs8PrivateKey(ASN1Sequence seq) {
    final ASN1OctetString os = seq.elements[2] as ASN1OctetString;
    final ASN1Parser p = ASN1Parser(os.valueBytes());
    return _pkcs1PrivateKey(p.nextObject() as ASN1Sequence);
  }

  RsaKey? _publicKey(List<String> lines) {
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

    final ASN1Sequence seq = p.nextObject() as ASN1Sequence;

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
    final ASN1BitString os = seq.elements[1] as ASN1BitString; //ASN1OctetString or ASN1BitString
    final Uint8List bytes = os.valueBytes().sublist(1);
    final ASN1Parser p = ASN1Parser(bytes);
    return _pkcs1PublicKey(p.nextObject() as ASN1Sequence);
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
      publicKeySeq.add(ASN1Integer(publicKey.n()!));
      publicKeySeq.add(ASN1Integer(publicKey.e()!));
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
      return """-----BEGIN PUBLIC KEY-----$res\n-----END PUBLIC KEY-----""";
  }

  static String encodePrivateKeyToPem(RsaKey privateKey) {
      var version = ASN1Integer(BigInt.from(0));

      ASN1Sequence privateKeySeq = new ASN1Sequence();

      privateKeySeq.add(version);
      privateKeySeq.add(ASN1Integer(privateKey._n!));
      privateKeySeq.add(ASN1Integer(privateKey._e!));
      privateKeySeq.add(ASN1Integer(privateKey._d!));
      privateKeySeq.add(ASN1Integer(privateKey._p!));
      privateKeySeq.add(ASN1Integer(privateKey._q!));
      privateKeySeq.add(ASN1Integer(privateKey._d! % (privateKey._p! - BigInt.from(1))));
      privateKeySeq.add(ASN1Integer(privateKey._d! % (privateKey._q! - BigInt.from(1))));
      privateKeySeq.add(ASN1Integer(inverse(privateKey._q!, privateKey._p!)));
      
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
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: React-Native-OpenPGP.js 0.1\nComment: http://openpgpjs.org\n\n",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: React-Native-OpenPGP.js 0.1\nComment: http://openpgpjs.org\n\n",
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
        var index = pem.indexOf('\n');
        pem = pem.substring(0, index);
    }

    pem = pem.replaceAll('\n', '');
    pem = pem.replaceAll('', '');

    return base64.decode(pem);
}