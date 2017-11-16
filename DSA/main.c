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
#include "sha1.h"

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


// ----------------------------------------------------
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


// ---------------------- KEY GEN ---------------------- //
// Generates RSA Public Key and RSA Secret Key
// where n is the RSA Modulus a positive integer
// where e is the public exponent a positive integer


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
    
    
    // check if message is too long for input limit of the hash function
    int maxHashInputLen = 512;
    
    if(strlen(&M) > maxHashInputLen) {
        // if it is end
        return "message too long";
    }
    
    // let mHash equal Hash(M)
    char mHash = sha256(M);
    
    // octet length of hash function output
    int hLen = strlen(&mHash);

    // define emlen
    int emLen = ceil(emBits/8);

    // intended length in octets of the salt
    int sLen = 8;
    
    // salt is a random string of sLen length is sLen is 0 it is an empty string
    char salt = sha256();
    
    // Mprime is an octet string of length 8 + hLen + sLen with eight
    // initial zero octets.
    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    char emptyM = "0000000000000000";
    int strLen = strlen(&emptyM) + strlen(&mHash);
    char * Mprime = strncat(&emptyM, &mHash, strLen);
    strLen = strLen + sLen;
    Mprime = strncat(Mprime, &salt, strLen);
    
    // hash M' to an octet of string length hLen
    char H = sha256(Mprime);
    
    // generate an octet string PS consisting of emLen - sLen - hLen - 2
    // zero octets.  The length of PS may be 0.
    // TODO: generate octet string for PS, using sha_256, to the length of PSlength
    int PSLength = emLen - sLen - hLen - 2;
    char PS = sha256();
    
    // Let DB = PS || 0x01 || salt; DB is an octet string of length
    // emLen - hLen - 1.
    char x = "0x01";
    int dbLen = strlen(&PS) + strlen(&x);
    char * DB = strncat(&PS, &x, dbLen);
    dbLen = dbLen + sLen;
    DB = strncat(DB, &salt, dbLen);
    
    // MGF = Mask Generation Function, deterministic, outputs octet of variable length
    int mgfLen = emLen - hLen - 1;
    char dbMask = sha256(H, mgfLen);
    
    // XOR dbmask and db
    char maskedDB = strXOR(&dbMask, DB);
    
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
            return * "integer too large";
        }
        // to base 256 value
        char * xHash = sha(x[i]);
        // new string length
        int newLen = strlen(X) + strlen(xHash);
        // concatenate new value with previous X
        X = strncat(X, xHash, newLen);
        
    }

    return *X;
}

// where K is the signers secret key and M is the message to be signed
char Sign(RSAPrivateKey K, char M) {
    
    // length of modulus n in bits
    int modBits = sizeof(K.n);
    // k is the length in octets of the RSA modulus n
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

    // return the signature
    return S;
}
