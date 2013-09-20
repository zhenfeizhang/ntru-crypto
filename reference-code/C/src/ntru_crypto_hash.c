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
 * File: ntru_crypto_hash.c
 *
 * Contents: Routines implementing the hash object abstraction.
 *
 *****************************************************************************/


#include <stdlib.h>
#include "ntru_crypto_hash.h"


typedef uint32_t (*NTRU_CRYPTO_HASH_INIT_FN)(
    void        *c);
typedef uint32_t (*NTRU_CRYPTO_HASH_UPDATE_FN)(
    void        *c,
    void const  *data,
    uint32_t     len);
typedef uint32_t (*NTRU_CRYPTO_HASH_FINAL_FN)(
    void        *c,
    void        *md);
typedef uint32_t (*NTRU_CRYPTO_HASH_DIGEST_FN)(
    void const  *data,
    uint32_t     len,
    void        *md);

typedef struct _NTRU_CRYPTO_HASH_ALG_PARAMS {
    uint8_t                     algid;
    uint16_t                    block_length;
    uint16_t                    digest_length;
    NTRU_CRYPTO_HASH_INIT_FN    init;
    NTRU_CRYPTO_HASH_UPDATE_FN  update;
    NTRU_CRYPTO_HASH_FINAL_FN   final;
    NTRU_CRYPTO_HASH_FINAL_FN   final_zero_pad;
    NTRU_CRYPTO_HASH_DIGEST_FN  digest;
} NTRU_CRYPTO_HASH_ALG_PARAMS;

static NTRU_CRYPTO_HASH_ALG_PARAMS const algs_params[] = {
    {
        NTRU_CRYPTO_HASH_ALGID_SHA1,
        SHA_1_BLK_LEN,
        SHA_1_MD_LEN,
        (NTRU_CRYPTO_HASH_INIT_FN) SHA_1_INIT_FN,
        (NTRU_CRYPTO_HASH_UPDATE_FN) SHA_1_UPDATE_FN,
        (NTRU_CRYPTO_HASH_FINAL_FN) SHA_1_FINAL_FN,
        (NTRU_CRYPTO_HASH_FINAL_FN) SHA_1_FINAL_ZERO_PAD_FN,
        (NTRU_CRYPTO_HASH_DIGEST_FN) SHA_1_DIGEST_FN,
    },
    {
        NTRU_CRYPTO_HASH_ALGID_SHA256,
        SHA_256_BLK_LEN,
        SHA_256_MD_LEN,
        (NTRU_CRYPTO_HASH_INIT_FN) SHA_256_INIT_FN,
        (NTRU_CRYPTO_HASH_UPDATE_FN) SHA_256_UPDATE_FN,
        (NTRU_CRYPTO_HASH_FINAL_FN) SHA_256_FINAL_FN,
        (NTRU_CRYPTO_HASH_FINAL_FN) SHA_256_FINAL_ZERO_PAD_FN,
        (NTRU_CRYPTO_HASH_DIGEST_FN) SHA_256_DIGEST_FN,
    },
};

static int const numalgs = (sizeof(algs_params)/sizeof(algs_params[0]));


/* get_alg_params
 *
 * Return a pointer to the hash algorithm parameters for the hash algorithm
 * specified, by looking for algid in the global algs_params table.
 * If not found, return NULL.
 */
static NTRU_CRYPTO_HASH_ALG_PARAMS const *
get_alg_params(
    NTRU_CRYPTO_HASH_ALGID algid)        //  in - the hash algorithm to find
{
    int i;

    for (i = 0; i < numalgs; i++)
        if (algs_params[i].algid == algid)
            return &algs_params[i];

    return NULL;
}


/* ntru_crypto_hash_set_alg
 *
 * Sets the hash algorithm for the hash context.  This must be called before
 * any calls to ntru_crypto_hash_block_length(),
 * ntru_crypto_hash_digest_length(), or ntru_crypto_hash_init() are made.
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the specified algorithm is not supported.
 */

uint32_t
ntru_crypto_hash_set_alg(
    NTRU_CRYPTO_HASH_ALGID  algid,  //      in - hash algoirithm to be used
    NTRU_CRYPTO_HASH_CTX   *c)      //  in/out - pointer to the hash context
{
    if (!c)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_PARAMETER);

    c->alg_params = get_alg_params(algid);
    if (!c->alg_params) {
        HASH_RET(NTRU_CRYPTO_HASH_BAD_ALG);
    }

    HASH_RET(NTRU_CRYPTO_HASH_OK);
}


/* ntru_crypto_hash_block_length
 *
 * Gets the number of bytes in an input block for the hash algorithm
 * specified in the hash context.  The hash algorithm must have been set
 * in the hash context with a call to ntru_crypto_hash_set_alg() prior to
 * calling this function.
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the algorithm has not been set.
 */

uint32_t
ntru_crypto_hash_block_length(
   NTRU_CRYPTO_HASH_CTX *c,         //  in - pointer to the hash context
   uint16_t             *blk_len)   // out - address for block length in bytes
{
    if (!c || !blk_len)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_PARAMETER);

    if (!c->alg_params)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_ALG);

    *blk_len = c->alg_params->block_length;
    HASH_RET(NTRU_CRYPTO_HASH_OK);
}


/* ntru_crypto_hash_digest_length
 *
 * Gets the number of bytes needed to hold the message digest for the
 * hash algorithm specified in the hash context.  The algorithm must have
 * been set in the hash context with a call to ntru_crypto_hash_set_alg() prior
 * to calling this function.
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the algorithm has not been set.
 */

uint32_t
ntru_crypto_hash_digest_length(
   NTRU_CRYPTO_HASH_CTX const *c,      //  in - pointer to the hash context
   uint16_t                   *md_len) // out - addr for digest length in bytes
{
    if (!c || !md_len)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_PARAMETER);

    if (!c->alg_params)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_ALG);

    *md_len = c->alg_params->digest_length;
    HASH_RET(NTRU_CRYPTO_HASH_OK);
}


/* ntru_crypto_hash_init
 *
 * This routine performs standard initialization of the hash state.
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the algorithm has not been set.
 */

uint32_t
ntru_crypto_hash_init(
   NTRU_CRYPTO_HASH_CTX *c)         // in/out - pointer to hash context
{
    if (!c)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_PARAMETER);

    if (!c->alg_params)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_ALG);

    return c->alg_params->init(&c->alg_ctx);
}


/* ntru_crypto_hash_update
 *
 * This routine processes input data and updates the hash calculation.
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_OVERFLOW if too much text has been fed to the
 *         hash algorithm. The size limit is dependent on the hash algorithm,
 *         and not all algorithms have this limit.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the algorithm has not been set.
 */

uint32_t
ntru_crypto_hash_update(
   NTRU_CRYPTO_HASH_CTX *c,         // in/out - pointer to hash context
   uint8_t const        *data,      //     in - pointer to input data
   uint32_t              data_len)  //     in - number of bytes of input data
{
    if (!c || (data_len && !data))
        HASH_RET(NTRU_CRYPTO_HASH_BAD_PARAMETER);

    if (!c->alg_params)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_ALG);

    return c->alg_params->update(&c->alg_ctx, data, data_len);
}


/* ntru_crypto_hash_final
 *
 * This routine completes the hash calculation and returns the message digest.
 * 
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the algorithm has not been set.
 */

uint32_t
ntru_crypto_hash_final(
   NTRU_CRYPTO_HASH_CTX *c,         // in/out - pointer to hash context
   uint8_t              *md)        //   out  - address for message digest
{
    if (!c || !md)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_PARAMETER);

    if (!c->alg_params)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_ALG);

    return c->alg_params->final(&c->alg_ctx, md);
}


/* ntru_crypto_hash_final_zero_pad
 *
 * This routine completes the hash calculation using zero padding and
 * returns the message digest.
 * 
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the algorithm has not been set.
 */

uint32_t
ntru_crypto_hash_final_zero_pad(
   NTRU_CRYPTO_HASH_CTX *c,         // in/out - pointer to hash context
   uint8_t              *md)        //   out  - address for message digest
{
    if (!c || !md)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_PARAMETER);

    if (!c->alg_params)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_ALG);

    return c->alg_params->final_zero_pad(&c->alg_ctx, md);
}


/* ntru_crypto_hash_digest
 *
 * This routine computes a message digest. It is assumed that the
 * output buffer md is large enough to hold the output (see
 * ntru_crypto_hash_digest_length)
 *
 * Returns NTRU_CRYPTO_HASH_OK on success.
 * Returns NTRU_CRYPTO_HASH_FAIL with corrupted context.
 * Returns NTRU_CRYPTO_HASH_BAD_PARAMETER if inappropriate NULL pointers are
 * passed.
 * Returns NTRU_CRYPTO_HASH_OVERFLOW if too much text has been fed to the
 *         hash algorithm. The size limit is dependent on the hash algorithm,
 *         and not all algorithms have this limit.
 * Returns NTRU_CRYPTO_HASH_BAD_ALG if the specified algorithm is not supported.
 */

uint32_t
ntru_crypto_hash_digest(
   NTRU_CRYPTO_HASH_ALGID  algid,    //  in - the hash algorithm to use
   uint8_t const          *data,     //  in - pointer to input data
   uint32_t                data_len, //  in - number of bytes of input data
   uint8_t                *md)       // out - address for message digest
{
    NTRU_CRYPTO_HASH_ALG_PARAMS const *alg_params = get_alg_params(algid);

    if (!alg_params)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_ALG);

    if ((data_len && !data) || !md)
        HASH_RET(NTRU_CRYPTO_HASH_BAD_PARAMETER);

    return alg_params->digest(data, data_len, md);
}

