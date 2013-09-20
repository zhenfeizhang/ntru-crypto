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
 * File: ntru_crypto_hmac.h
 *
 * Contents: Definitions and declarations for the HMAC implementation.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_HMAC_H
#define NTRU_CRYPTO_HMAC_H


#include "ntru_crypto_platform.h"
#include "ntru_crypto_hash.h"


/***************
 * error codes *
 ***************/

#define NTRU_CRYPTO_HMAC_OK              ((uint32_t)NTRU_CRYPTO_HASH_OK)
#define NTRU_CRYPTO_HMAC_BAD_PARAMETER   ((uint32_t)NTRU_CRYPTO_HASH_BAD_PARAMETER)
#define NTRU_CRYPTO_HMAC_BAD_ALG         ((uint32_t)NTRU_CRYPTO_HASH_BAD_ALG)
#define NTRU_CRYPTO_HMAC_OUT_OF_MEMORY   ((uint32_t)NTRU_CRYPTO_HASH_OUT_OF_MEMORY)

#define HMAC_RESULT(e)  ((uint32_t)((e) ? HMAC_ERROR_BASE + (e) : (e)))
#define HMAC_RET(e)     return HMAC_RESULT(e)


/*************************
 * structure definitions *
 *************************/

/* HMAC context structure */

struct _NTRU_CRYPTO_HMAC_CTX;            /* opaque forward reference */
typedef struct _NTRU_CRYPTO_HMAC_CTX NTRU_CRYPTO_HMAC_CTX;


/*************************
 * function declarations *
 *************************/

/* ntru_crypto_hmac_create_ctx
 *
 * This routine creates an HMAC context, setting the hash algorithm and
 * the key to be used.
 *
 * Returns NTRU_CRYPTO_HASH_OK if successful.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_OUT_OF_MEMORY if memory cannot be allocated.
 */

extern uint32_t
ntru_crypto_hmac_create_ctx(
    NTRU_CRYPTO_HASH_ALGID   algid,   /*  in - the hash algorithm to be used */
    uint8_t const           *key,     /*  in - pointer to the HMAC key */
    uint32_t                 key_len, /*  in - number of bytes in HMAC key */
    NTRU_CRYPTO_HMAC_CTX   **c);      /* out - address for pointer to HMAC
                                               context */


/* ntru_crypto_hmac_destroy_ctx
 *
 * Destroys an HMAC context.
 *
 * Returns NTRU_CRYPTO_HASH_OK if successful.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

extern uint32_t
ntru_crypto_hmac_destroy_ctx(
    NTRU_CRYPTO_HMAC_CTX *c);       /* in/out - pointer to HMAC context */


/* ntru_crypto_hmac_get_md_len
 *
 * This routine gets the digest length of the HMAC.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

extern uint32_t
ntru_crypto_hmac_get_md_len(
    NTRU_CRYPTO_HMAC_CTX const *c,       /*  in - pointer to HMAC context */
    uint16_t                   *md_len); /* out - address for digest length */


/* ntru_crypto_hmac_set_key
 *
 * This routine sets a digest-length key into the HMAC context.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

extern uint32_t
ntru_crypto_hmac_set_key(
    NTRU_CRYPTO_HMAC_CTX *c,        /*  in - pointer to HMAC context */
    uint8_t const        *key);     /*  in - pointer to new HMAC key */


/* ntru_crypto_hmac_init
 *
 * This routine performs standard initialization of the HMAC state.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HMAC_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

extern uint32_t
ntru_crypto_hmac_init(
    NTRU_CRYPTO_HMAC_CTX *c);       /* in/out - pointer to HMAC context */


/* ntru_crypto_hmac_update
 *
 * This routine processes input data and updates the HMAC hash calculation.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HMAC_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HMAC_OVERFLOW if more than bytes are hashed than the underlying
 *         hash algorithm can handle.
 */

extern uint32_t
ntru_crypto_hmac_update(
    NTRU_CRYPTO_HMAC_CTX *c,         /* in/out - pointer to HMAC context */
    uint8_t const        *data,      /*     in - pointer to input data */
    uint32_t              data_len); /*     in - no. of bytes of input data */


/* ntru_crypto_hmac_final
 *
 * This routine completes the HMAC hash calculation and returns the
 * message digest.
 *
 * Returns NTRU_CRYPTO_HMAC_OK on success.
 * Returns NTRU_CRYPTO_HMAC_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HMAC_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 */

extern uint32_t
ntru_crypto_hmac_final(
    NTRU_CRYPTO_HMAC_CTX  *c,       /* in/out - pointer to HMAC context */
    uint8_t              *md);      /*    out - address for message digest */


#endif /* NTRU_CRYPTO_HMAC_H */
