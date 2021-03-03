import 'package:test/test.dart';

import 'src/Primality.dart';

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import "package:pointycastle/export.dart";
import "package:asn1lib/asn1lib.dart";
import 'src/rsa_pkcs.dart';



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

    exportKey({format='PEM', passphrase=null, pkcs=1, protection=null, randfunc=null}){

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
        var po = RSAPKCSParser().parsePEM(extern_key);
        if(po.private != null){
          BigInt p = po.private.prime1;
          BigInt q = po.private.prime2;
          BigInt n = po.private.modulus;
          BigInt e = RsaKey.E;
          BigInt d = po.private.privateExponent;
          BigInt u = inverse(p, q);
          return RsaKey(n: n,e: e, q: q,p: p,d: d,u: u);
        }else{
          BigInt n = po.public.modulus;
          BigInt e = RsaKey.E;
          return RsaKey(n: n,e: e);
        }
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
