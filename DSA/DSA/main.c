//
//  main.c
//  DSA
//  KeyGen and Sign
//
//  Created by Matthew Russo on 7/11/17.
//  Copyright © 2017 Matthew Russo. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "dsa_verify.h"
#include "sha256.h"

int main(int argc, const char * argv[]) {
    
    // call keygen with e = 17, p = 11, q = 19
    // TODO: to be entered by the user? or chosen at random
    int p = 11;
    int q = 19;
    int n = p*q;
    int e = 17;

    KeyGen(e, p, q);
    
    return 0;
    
    
}

// ---------------------- KEY GEN ---------------------- //
// Generates RSA Public Key and RSA Secret Key
// where n is the RSA Modulus a positive integer
// where e is the public exponent a positive integer

/*
 Rules for modulus:
 ------------------------------------------------
 RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u >= 2 
 
 RSA public exponent e is an integer between 3 and n - 1 satisfying
 
 GCD(e, \lambda(n)) = 1, 
 
 where \lambda(n) = LCM(r_1 - 1, ..., r_u - 1).
 
 By convention, the first two primes r_1 and r_2 may also be denoted p
 and q respectively.
 
 In a valid RSA private key with the first representation, the RSA
 modulus n is the same as in the corresponding RSA public key and is
 the product of u distinct odd primes r_i, i = 1, 2, ..., u, where u
 >= 2.  The RSA private exponent d is a positive integer less than n
 satisfying
 
 e * d == 1 (mod \lambda(n)),
 
 -----------------------------------------------
 
 Define modulus, public exponent, and private exponent
 
 r_1 = p = 5
 r_2 = q = 7
 
 n = p * q = 5 * 7 = 35
 e = between 3 and n-1 = between 3 and 34 = 13
 
 \lambda(n) = LCM(p-1, q-1) = LCM(4, 6) = 12
 GCD(e, \lambda(n)) = GCD(13, 12) = 1
 
 n and e are valid
 
 
 ----------------------------------------------------
/* STRUCTS */
// Public and Private Keys


// Define struct of public key
typedef struct RSAPublicKey {
    // modulus
    int n;
    // publicExponent
    int e;
} RSAPublicKey;

// Define struct of private key
typedef struct RSAPrivateKey {
    // modulus
    int n;
    // privateExponent
    int d;
    // prime one
    int p;
    // prime 2
    int q;
} RSAPrivateKey;


// where e is the public exponent and p and q are
// the distinct primes that multiply to make the modulus
int KeyGen(int e, int p, int q) {
    int n = p*q;// set modulus with p and q

    // verify nand e are valid
    if(3 < n < e - 1 && GCD(e, LCM(p-1,q-1)) == 1) {
        printf("n and e are valid, n=%d, e=%d",n,e);
    }
    
    int u, v;
    int a = e, b = LCM(p-1,q-1); // set a to public exponent
                                 // set b to LCM of p and q for modulus

    EEA(a, b, &u, &v); // call EEA to get d, the private exponent
    
    int d = u; // set d
    
    // create public key
    RSAPublicKey pk;
    pk.n = n; // modulus
    pk.e = e; // public exponent

    // create public key
    RSAPrivateKey sk;
    sk.d = d; // the private exponent
    sk.n = p*q; // modulus
    sk.p = p; // distinct prime
    sk.q = q; // distinct prime
    
    return 0;
}


// ----------------------------------------------------
/* HELPER FUNCTIONS */

// loop over result until finds the greatest common divisor
int GCD(int x, int y)
{
    if (x == y)
        return x;
    if (x > y)
        return GCD(x-y, y);
    return GCD(x, y-x);
}

// return the lowest common multiple
int LCM(int x, int y)
{
    return (x*y)/GCD(x, y);
}

// XOR
char strXOR(char str1[], char str2[]) {
    int len = strlen(str1) + strlen(str2);
    char result[len];

    for (int i=0; i<strlen(str1); i++)
    {
        char value = str1[i] ^ str2[i];
        result[i] = value;
    }
    return result;
}

// C function for extended Euclidean Algorithm
int EEA(int a, int b, int *u, int *v)
{
    // breaks the loop when a = 0
    if (a == 0)
    {
        *u = 0;
        *v = 1;
        return b;
    }
    
    int u1, v1; // keeps values as we "move through" EEA table
    int eea = EEA(b%a, a, &u1, &v1); // call EEA again to step through table again
    
    // update u and v
    *u = v1 - (b/a) * u1;
    *v = u1;
    
    return eea;
}

// encoding method, takes message to be encoded and bit octet bit length
char EMSA_PSS_ENCODE(char M,int emBits) {

    /*
     Options:
     Hash     hash function (hLen denotes the length in octets of the hash
     function output)
     MGF      mask generation function
     sLen     intended length in octets of the salt
     
     Input:
     M        message to be encoded, an octet string
     emBits   maximal bit length of the integer OS2IP (EM) (see Section
     4.2), at least 8hLen + 8sLen + 9
     
     Output:
     EM       encoded message, an octet string of length emLen = \ceil
     (emBits/8)
     
     Errors:  "encoding error"; "message too long"
     */
    
    
    // check if message is too long for input limit of the hash function
    //TODO: set maxHashInputLen to maximum input length for the hash function
    int maxHashInputLen = 512;
    
    if(strlen(&M)*8 > maxHashInputLen) {
        // if it is end
        return "message too long";
    }
    
    // let mHash equal Hash(M)
    char mHash = sha256(M);
    
    // octet length of hash function output
    int hLen = strlen(&mHash);

    int emLen = ceil(emBits/8);

    // intended length in octets of the salt
    int sLen = 8;
    
    // salt is a random string of sLen length is sLen is 0 it is an empty string
    // TODO: Use sha256 to generate the random string to use as the salt

    int sha256_test()
    {
    	BYTE hash1[SHA256_BLOCK_SIZE] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    	                                 0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};

    	BYTE buf[SHA256_BLOCK_SIZE];
    	SHA256_CTX ctx;
    	int idx;
    	printf("SHA-256: ");
    	    	for(idx=0; idx < 32; idx++)
    	    		printf("%02x",hash[idx]);
    	    	printf("\n");
    	int pass = 1;
    	pass = pass && !memcmp(hash1, buf, SHA256_BLOCK_SIZE);

    	return(pass);
    }

    char sha256(char hash)
    {
    	unsigned char text1[32];
    	unsigned char hash[32];

    	int idx;
    	Sha256Context ctx;

    	scanf ("%s", &text1);

        // Hash one
        sha256_init_hash(&ctx);
        sha256_update(&ctx,text1,strlen(text1));
        sha256_final_hash(&ctx,hash);
        print_hash(hash);

    	//getchar();
    	return(hash);
    }
    char salt = sha256(hash1);
    
    // Mprime is an octet string of length 8 + hLen + sLen with eight
    // initial zero octets.
    char mHash = sha256(hash2);
    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    // TODO: generate with sha?
    char emptyM = "0000000000000000";
    int strLen = strlen(&emptyM) + strlen(&mHash);
    char * Mprime = strncat(&emptyM, &mHash, strLen);
    strLen = strLen + sLen;
    Mprime = strncat(Mprime, &salt, strLen);
    
    // hash M' to an octet of string length hLen
    // TODO: use sha to hash Mprime to an octet string of length hLen aka the length of hash function output
    char H = sha256(Mprime);
    
    // generate an octet string PS consisting of emLen - sLen - hLen - 2
    // zero octets.  The length of PS may be 0.
    // TODO: generate octet string for PS, using sha_256, to the length of PSlength
    int PSLength = emLen - sLen - hLen - 2;
    char PS = sha256(hash3);
    
    // Let DB = PS || 0x01 || salt; DB is an octet string of length
    // emLen - hLen - 1.
    char x = "0x01";
    int dbLen = strlen(&PS) + strlen(&x);
    char * DB = strncat(&PS, &x, dbLen);
    dbLen = dbLen + sLen;
    DB = strncat(DB, &salt, dbLen);
    
    // MGF = Mask Generation Function, deterministic, outputs octet of variable length

    int mgfLen = emLen - hLen - 1;
    char* Htrunc = H + (hLen-mgfLen);
    char* Hhash = sha256(Htrunc);
    
    // dbmask xor db
    char maskedDB = strXOR(&Hhash, DB);
    
    // Let EM = maskedDB || H || 0xbc
    char xbc = "0xbc";
    int newLen = strlen(&maskedDB) + strlen(&H);
    // concat new strings with new length
    char * EM = strncat(&PS, &x, newLen);
    newLen = newLen + sizeof(xbc);
    // update final length and concat E< with xbc
    EM = strncat(EM, &xbc, newLen);
    
    return *EM;
}

// converts an octet string to corresponding nonnegative integer
int OS2IP(char X[]) {
    // length of input string
    int xLen = strlen(X);
    // int of length of input string
    int x[xLen];
    
    // converts X[i] into its integer values and
    // store in x
    for (int i=0; i<xLen; i++)
    {
        int value = X[i];
        x[i] = value;
    }

    // initialize the sum
    int sumX = 0;
    // sum up integer values to return
    for (int i = xLen-1; i>=0; i = i-1)
    {
        // check if index is 0, if not do math,
        // if so add x[0] to the sum
        if (i > 0) {
            int value = x[i] * 256^i;
            sumX = sumX + value;
        } else {
            sumX = sumX + x[i];
        }
    }
    
    // return sum
    return sumX;
}

// where K is the private key (n, d)
// assuming K is valid
int RSASP1(RSAPrivateKey K, char m) {
    int s;
    s = m^K.d % K.n;
    
    return s;
}


// where x is the nonnegative integer to be converted
// and xLen is the desired length of the output
char I2OSP(int x[], int xLen) {
    // octet string of length xLen
    char * X = '\0';

    for (int i=0; i<xLen; i++)
    {
        // check for error
        if (x > (256^xLen)) {
            return "integer too large";
        }
        // TODO: fix this part? Hash x[i]?
        char * xHash = sha(x[i]);
        
        int newLen = strlen(X) + strlen(xHash);
        X = strncat(X, xHash, newLen);
        /*
        1. If x >= 256^xLen, output "integer too large" and stop.
        
        2. Write the integer x in its unique xLen-digit representation in
        base 256:
        
        x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) + ...
        + x_1 256 + x_0,
        
        where 0 <= x_i < 256 (note that one or more leading digits will be
                              zero if x is less than 256^(xLen-1)).
        
        3. Let the octet X_i have the integer value x_(xLen-i) for 1 <= i <=
            xLen.  Output the octet string
         */
        
    }

    return *X;
}

// where K is the signers secret key and M is the message to be signed
char Sign(RSAPrivateKey K, char M) {
    
    // length of modulus n in bits
    // TODO: convert modulus length into bits, for now i multiplied it by 8 but im pretty sure that isnt right?
    int modBits = sizeof(K.n);
    // k is the length in octets of the RSA modulus n
    // TODO: is this right?
    int k = sizeof(K.n) - 1;
    
    // Encrypt the message M and pass in the length of the modulus in bits - 1
    char EM = EMSA_PSS_ENCODE(M, modBits - 1);
    
    // check for error in encypting, the message was too long
    char * err = "message too long";
    if (&EM == err) {
        return * "encoding error";
    }
    
    // convert encrypted message to integer representation of message m
    int m = OS2IP(&EM);
    // apply PSA primitive to the message and return signature representative s
    int s = RSASP1(K, m);
    // convert signature representative to signature S of k length in octets
    char S = I2OSP(&s, k);

    return S;
}
