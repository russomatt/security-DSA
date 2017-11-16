 /**
    2  * @file sha256.h
    3  * @brief SHA-256 (Secure Hash Algorithm 256)
    4  *
    5  * @section License
    6  *
    7  * Copyright (C) 2010-2017 Oryx Embedded SARL. All rights reserved.
    8  *
    9  * This file is part of CycloneCrypto Open.
   10  *
   11  * This program is free software; you can redistribute it and/or
   12  * modify it under the terms of the GNU General Public License
   13  * as published by the Free Software Foundation; either version 2
   14  * of the License, or (at your option) any later version.
   15  *
   16  * This program is distributed in the hope that it will be useful,
   17  * but WITHOUT ANY WARRANTY; without even the implied warranty of
   18  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   19  * GNU General Public License for more details.
   20  *
   21  * You should have received a copy of the GNU General Public License
   22  * along with this program; if not, write to the Free Software Foundation,
   23  * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
   24  *
   25  * @author Oryx Embedded SARL (www.oryx-embedded.com)
   26  * @version 1.7.8
   27  **/

    #ifndef _SHA256_H
   #define _SHA256_H

    //Dependencies
    //#include "crypto.h"

    //SHA-256 block size
    #define SHA256_BLOCK_SIZE 64
    //SHA-256 digest size
    #define SHA256_DIGEST_SIZE 32
    //Common interface for hash algorithms
   #define SHA256_HASH_ALGO (&sha256HashAlgo)


    /**
     * @brief SHA-256 algorithm context
     **/

    typedef struct
    {
       union
      {
         uint32_t h[8];
         uint8_t digest[32];
      };
      union
      {
          uint32_t w[16];
          uint8_t buffer[64];
       };
       size_t size;
       uint64_t totalSize;
    } Sha256Context;


    //SHA-256 related constants
   extern const HashAlgo sha256HashAlgo;

    //SHA-256 related functions
    error_t sha256Compute(const void *data, size_t length, uint8_t *digest);
    void sha256_init_hash(Sha256Context *context);
    void sha256Update(Sha256Context *context, const void *data, size_t length);
    void sha256_final_hash(Sha256Context *context, uint8_t *digest);
    void sha256ProcessBlock(Sha256Context *context);

    #endif
