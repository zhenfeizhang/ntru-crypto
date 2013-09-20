/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  
 * THIS SOFTWARE IS PROVIDED BY SECURITY INNOVATION INC. AND ITS CONTRIBUTORS 
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO,THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL SECURITY INNOVATION INC. OR ITS
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program and the accompanying materials are made available under the
 * terms of the GPL version 3 license for non-commercial use and the Security
 * Innovation Commercial License for commercial applications, both of which
 * accompany this distribution and are also available at:
 *
 *       http://www.gnu.org/licenses/gpl-3.0.html   
 *                      and 
 *       http://www.securityinnovation.com/NTRUlicense.doc 
 *
 *****************************************************************************/
 
/******************************************************************************
 *
 * File: ntru_crypto_sha256.c
 *
 * Contents: Routines implementing the SHA-256 hash calculations.
 *
 *****************************************************************************/


#include <stdlib.h>
#include "ntru_crypto_sha256.h"


/* ntru_crypto_sha256_init
 *
 * This routine performs standard initialization of the SHA-256 state.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 */

uint32_t
ntru_crypto_sha256_init(
    NTRU_CRYPTO_SHA2_CTX *c)        /* in/out - pointer to SHA-2 context */
{
    return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, c, NULL, NULL, 0,
                            SHA_INIT, NULL);
}


/* ntru_crypto_sha256_update
 *
 * This routine processes input data and updates the SHA-256 hash calculation.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha256_update(
    NTRU_CRYPTO_SHA2_CTX *c,         /* in/out - pointer to SHA-2 context */
    uint8_t const        *data,      /*     in - pointer to input data */
    uint32_t              data_len)  /*     in - no. of bytes of input data */
{
    return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, c, NULL, data,
                            data_len, SHA_DATA_ONLY, NULL);
}


/* ntru_crypto_sha256_final
 *
 * This routine completes the SHA-256 hash calculation and returns the
 * message digest.
 * 
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha256_final(
    NTRU_CRYPTO_SHA2_CTX *c,        /* in/out - pointer to SHA-2 context */
    uint8_t              *md)       /*    out - address for message digest */
{
    return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, c, NULL, NULL, 0,
                            SHA_FINISH, md);
}


/* ntru_crypto_sha256_final_zero_pad
 *
 * This routine completes the SHA-256 hash calculation using zero padding
 * and returns the message digest.
 * 
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha256_final_zero_pad(
    NTRU_CRYPTO_SHA2_CTX *c,        /* in/out - pointer to SHA-2 context */
    uint8_t              *md)       /*    out - address for message digest */
{
    return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, c, NULL, NULL, 0,
                            SHA_FINISH | SHA_ZERO_PAD, md);
}


/* ntru_crypto_sha256_digest
 *
 * This routine computes a SHA-256 message digest.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha256_digest(
    uint8_t const  *data,           //  in - pointer to input data
    uint32_t        data_len,       //  in - number of bytes of input data
    uint8_t        *md)             // out - address for message digest
{
    NTRU_CRYPTO_SHA2_CTX c;

    return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, &c, NULL, data,
                            data_len, SHA_INIT | SHA_FINISH, md);
}

