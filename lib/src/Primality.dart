import 'dart:convert';
import 'package:crypto/crypto.dart';



String sha256_16(message) {
  var key = utf8.encode(message);
  return sha256.convert(key).toString();
}
int size_in_bits(BigInt lol){
  int res = 0;
  while(lol > BigInt.zero){
    res ++;
    lol>>=1;
  }
  return res;
}
BigInt abs(BigInt x){
  if(x < BigInt.zero){
    return -x;
  }
  return x;
}
BigInt sqrt(BigInt value){
  BigInt x = value;
  BigInt y = (x + BigInt.one) ~/ BigInt.two;
  while(y < x){
    x = y;
    y = (x + value ~/ x) ~/ BigInt.two;
  }
  return x;
}
class My_Random{
  int counter = 0;
  String master_key = '';

  My_Random(String password){
    String salt = sha256_16(password);
    this.master_key = sha256_16(password + salt);
  }

  List<int> get(int n){
    counter ++;
    List<int> x = [];
    String y = '';
    String code_string = '0123456789abcdef';
    while(x.length < n){
      String lol_pop = '';
      if(y.length == 64){
        lol_pop = y.substring(y.length-32,y.length);
      }
      y = sha256_16(lol_pop + master_key + counter.toString());
      int j = 0;
      while (j < y.length && x.length < n){
        int k = code_string.indexOf(y[j]) * 16 + code_string.indexOf(y[j+1]);
        if(k!=0){
          x.add( k);
        }
        j += 2;
      }
    }
    return x.sublist(0,n);
  }
  BigInt random({exact_bits = null, max_bits = null,My_Random randfunc = null}){

    if (exact_bits == null && max_bits == null){
      throw("Either 'exact_bits' or 'max_bits' must be specified");
    }
    
    if (exact_bits != null && max_bits != null){
      throw("'exact_bits' and 'max_bits' are mutually exclusive");
    }
    int bits = null;
    String code_string = '0123456789abcdef';
    if(exact_bits != null){
      bits = exact_bits;
    }
    if(max_bits != null){
      bits = max_bits;
    }
    int bytes_needed = ((bits - 1) ~/ 8) + 1;
    int significant_bits_msb = 8 - (bytes_needed * 8 - bits);
    int msb = (get(1))[0];
    if (exact_bits != null){
      msb = msb | (1 << (significant_bits_msb - 1));
    }
    msb &= (1 << significant_bits_msb) - 1;
    List<int> list = [msb] + get(bytes_needed - 1);

    BigInt res = BigInt.zero;
    if(list.length % 4 != 0){
      for(int i=4 - (list.length % 4);i>0;i--){
        list = [0]+ list;
      }
    }
    for(int i=0;i<list.length;i+=4){
      res <<= 32;
      res += BigInt.from(((list[i]*256 + list[i+1])*256 + list[i+2])*256 + list[i+3]);
    }
    return res;
  }
  BigInt random_range({BigInt min_inclusive = null,BigInt max_inclusive = null,BigInt max_exclusive = null}){
    if(max_exclusive == null && max_inclusive == null){
      throw("max_inclusive and max_exclusive cannot be both  specified");
    }
    if(max_exclusive != null){
      max_inclusive = max_exclusive - BigInt.one;
    }
    if(min_inclusive == null && max_inclusive == null){
      throw("Missing keyword to identify the interval");
    }

    BigInt norm_maximum = max_inclusive - min_inclusive;
    BigInt lol = norm_maximum;
    int bits_needed = 0;
    while(lol > BigInt.zero){
      lol >>= 1;
      bits_needed += 1;
    }

    BigInt norm_candidate = -BigInt.one;
    while (!(BigInt.zero <= norm_candidate && norm_candidate <= norm_maximum)){
        norm_candidate = random(max_bits : bits_needed);
    }
    return norm_candidate + min_inclusive;
  }
}
int COMPOSITE = 0;
int PROBABLY_PRIME = 1;

BigInt generate_probable_prime({int exact_bits = null, My_Random randfunc = null, prime_filter = null}){

  if(exact_bits == null){
    throw("Missing exact_bits parameter");
  }
  if(exact_bits < 160){
    throw("Prime number is !big enough.");
  }

  var result = COMPOSITE;
  BigInt candidate;
  while (result == COMPOSITE){
    
    candidate = randfunc.random(exact_bits: exact_bits) | BigInt.one;
    if (prime_filter != null && !prime_filter(candidate)){
      continue;
    }
    result = test_probable_prime(candidate,exact_bits , randfunc: randfunc);
  }
  return candidate;
}
List<int> _sieve_base = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541];
int test_probable_prime(BigInt candidate,int exact_bits,{My_Random randfunc = null}){

    if( randfunc == null){
      throw("NO Random");
    }
    
    

    if (candidate < BigInt.from(541) && (_sieve_base).contains(candidate.toInt())){
      return PROBABLY_PRIME;
    }
    for(int arc in _sieve_base){
      if(candidate % BigInt.from(arc) == BigInt.zero){
        return COMPOSITE;
      }
    }
    var mr_ranges = [[220, 30], [280, 20], [390, 15], [512, 10],
                 [620, 7], [740, 6], [890, 5], [1200, 4],
                 [1700, 3], [3700, 2]];

    int bit_size = size_in_bits(candidate);
    int mr_iterations = 1;
    for(var arc in mr_ranges){
      if(arc[0] > bit_size){
        mr_iterations = arc[1];
        break;
      }
    }
    if(miller_rabin_test(candidate, mr_iterations, randfunc: randfunc) == COMPOSITE){
      return COMPOSITE;
    }
    if(lucas_test(candidate) == COMPOSITE){
      return COMPOSITE;
    }
    return PROBABLY_PRIME;
}
BigInt binpow(BigInt a, BigInt b, BigInt mod){
  BigInt res = BigInt.one;
  while(b > BigInt.zero){
    if(b.isOdd){
      res = (res * a) % mod;
    }
    b >>= 1;
    a = (a*a)%mod;
  }
  return res;
}
int lucas_test(BigInt candidate){
  // Step 1

  BigInt x = sqrt(candidate);
  if(candidate == x * x || candidate.isEven){
    return COMPOSITE;
  }

  // Step 2

  BigInt d = BigInt.from(5);
  while (true){
      if([d, -d].contains(candidate)){
          continue;
      }
      BigInt js = jacobi_symbol(d, candidate);
      if (js == BigInt.zero){
          return COMPOSITE;
      }
      if( js == -BigInt.one){
          break;
      }
      
      if (d > BigInt.zero){
          d += BigInt.two;
      }else{
          d -= BigInt.two;
      }
      d = -d;
  }
  
  // Step 3
  // This is \delta(n) = n - jacobi(D/n)
  BigInt K = candidate + BigInt.one;
  // Step 4
  int r = -1;
  var tmp = K;
  while(tmp > BigInt.zero){
    tmp >>= 1;
    r += 1;
  }
  // Step 5
  // U_1=1 and V_1=P
  BigInt U_i = BigInt.one;
  BigInt V_i = BigInt.one;
  BigInt U_temp = BigInt.zero;
  BigInt V_temp = BigInt.zero;
  // Step 6
  for(int i = r-1; i > -1;i--){
    // Square
    // U_temp = U_i * V_i % candidate
    U_temp = (U_i * V_i) % candidate;
    // V_temp = (((V_i ** 2 + (U_i ** 2 * D)) * K) >> 1) % candidate
    V_temp = U_i *  U_i * d + V_i * V_i;
    if (V_temp%BigInt.two == BigInt.one){
        V_temp += candidate;
    }
    V_temp >>= 1;
    V_temp = V_temp % candidate;
    // Multiply
    if ((K >> i) & BigInt.one == BigInt.one){
      // U_i = (((U_temp + V_temp) * K) >> 1) % candidate
      U_i = U_temp;
      U_i += V_temp;
      if(U_i%BigInt.two == BigInt.one){
          U_i += candidate;
      }
      U_i >>= 1;
      U_i %= candidate;
      // V_i = (((V_temp + U_temp * D) * K) >> 1) % candidate
      V_i = (V_temp);
      V_i += (U_temp * d);

      if(V_i%BigInt.two == BigInt.one){
        V_i += candidate;
      }
      V_i >>= 1;
      V_i %= candidate;
    }
    else{
      U_i = (U_temp);
      V_i = (V_temp);
    }
  }
  // Step 7
  if( U_i == BigInt.zero){
      return PROBABLY_PRIME;
  }
  return COMPOSITE;
}
BigInt jacobi_symbol(BigInt a, BigInt n){
  // Step 1
  a = a % n;
  // Step 2
  if( a == BigInt.one || n == BigInt.one){
      return BigInt.one;
  }
  // Step 3
  if (a == BigInt.zero){
      return BigInt.zero;
  }
  // Step 4
  BigInt e = BigInt.zero;
  BigInt a1 = a;
  while ((a1 & BigInt.one) == BigInt.zero){
      a1 >>= 1;
      e += BigInt.one;
  }
  // Step 5
  BigInt s;
  if( (e & BigInt.one) == BigInt.zero || [BigInt.one, BigInt.from(7)].contains(n % BigInt.from(8))){
      s = BigInt.one;
  }else{
      s = -BigInt.one;
  }
  // Step 6
  if (n % BigInt.from(4) == BigInt.from(3) && a1 % BigInt.from(4) == BigInt.from(3)){
      s = -s;
  }
  // Step 7
  BigInt n1 = n % a1;
  // Step 8
  return s * jacobi_symbol(n1, a1);
}
int miller_rabin_test(BigInt candidate,int iterations, {My_Random randfunc=null}){

  if([1, 2, 3, 5].contains(candidate.toInt())){
    return PROBABLY_PRIME;
  }

  if(candidate.isEven){
    return COMPOSITE;
  }

  BigInt one = BigInt.one;
  BigInt minus_one = candidate - BigInt.one;

  if(randfunc == null){
    print("NO Random");
  }

  // Step 1 and 2
  BigInt m = minus_one;
  var a = 0;
  while(m % BigInt.two == BigInt.zero){
    m >>= 1;
    a += 1;
  }

  // Skip step 3

  // Step 4
  if(iterations != 7){
      print('lol '+ iterations.toString());
      throw(iterations != 7);
  }
  for (int i = 0;i <= iterations; i++){
    // Step 4.1-2
    BigInt base = BigInt.one;
    while([minus_one, one].contains(base)){
      base = randfunc.random_range(min_inclusive:BigInt.two, max_inclusive:candidate - BigInt.two);
    }

    // Step 4.3-4.4
    BigInt z = binpow(base, m, candidate);
    if ([minus_one, one].contains(z)){
      continue;
    }

    // Step 4.5
    bool tor = true;
    for(int j = 1;j < a; j++){
      z = (z*z)%candidate;
      if (z == minus_one){
        tor = false;
        break;
      }
      if (z == one){
        return COMPOSITE;
      }
    }
    if(tor){
      return COMPOSITE;
    }
  }

  // Step 5
  return PROBABLY_PRIME;
}
BigInt inverse(BigInt a,BigInt modulus){
  if (modulus == BigInt.zero){
    throw("Modulus cannot be zero");
  }
  if (modulus < BigInt.zero){
    throw("Modulus cannot be negative");
  }
  BigInt r_p = a;
  BigInt r_n = modulus;
  BigInt s_p = BigInt.one;
  BigInt s_n = BigInt.zero;
  BigInt q;
  while (r_n > BigInt.zero){
    q = r_p ~/ r_n;
    BigInt x = r_n;
    r_n =  r_p - q * r_n;
    r_p = x;

    x = s_n;
    s_n =  s_p - q * s_n;
    s_p = x;
  }
  if (r_p != BigInt.one){
      throw("No inverse value can be computed" + r_p.toString());
  }
  while (s_p < BigInt.zero){
      s_p += modulus;
  }
  return s_p;
}
BigInt LCM(BigInt a, BigInt term){
    if( a == BigInt.zero || term == BigInt.zero){
        return BigInt.zero;
    }
    return abs((a * term) ~/ a.gcd(term));

}
List<int> to_bytes(BigInt arc){
  List<int> res = [];
  while(arc > BigInt.zero){
    res.add((arc%BigInt.from(256)).toInt());
    arc ~/= BigInt.from(256);
  }
  return res.reversed.toList();
}
List<int> pack_len(int len){
  List<int> res = [0,0,0,0];
  for(int i=3;i>=0;i--){
    res[i] = ((len%256).toInt());
    len ~/= 256;
  }
  if(len > 0){
    throw('argument out of range');
  }
  return res;
}
int unpack_len(List<int> len){
  int res = 0;
  for(int i=0;i<len.length;i++){
    res *= 256;
    res += len[i];
  }
  return res;
}
BigInt from_bytes(List<int> list){
  BigInt res = BigInt.zero;
  for(int arc in list){
    res*=BigInt.from(256);
    res+=BigInt.from(arc);
  }
  return res;
}

List<int> str_to_bytes(String line){
  List<int> res = [];
  String systems = '';
  if(systems == ''){
    for(var i = 0;i<256;i++){
      systems+=String.fromCharCode(i);
    }
  }
  for(int i=0;i<line.length;i++){
    res.add(systems.indexOf(line[i]));
  }
  return res.reversed.toList();
}