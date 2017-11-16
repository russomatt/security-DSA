

#ifndef _DSA_VERIFY_H_
#define _DSA_VERIFY_H_

// sigR and sigS should be hex-encoded strings, key points at binary data
int dsa_verify_sign(const char *data, int dataLen, const unsigned char *key, const char* sigR, const char* sigS);

#endif

