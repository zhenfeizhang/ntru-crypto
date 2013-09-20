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
 * File:  ntru_crypto_ntru_mgf1.h
 *
 * Contents: Public header file for MGF-1 in the NTRU algorithm.
 *
 *****************************************************************************/


#ifndef NTRU_CRYPTO_NTRU_MGF1_H
#define NTRU_CRYPTO_NTRU_MGF1_H


#include "ntru_crypto.h"
#include "ntru_crypto_hash.h"


/* function declarations */

/* ntru_mgf1
 *
 * Implements a basic mask-generation function, generating an arbitrary
 * number of octets based on hashing a digest-length string concatenated
 * with a 4-octet counter.
 *
 * The state (string and counter) is initialized when a seed is present.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_CRYPTO_HASH_ errors if they occur.
 *
 */

extern uint32_t
ntru_mgf1(
    uint8_t                *state,      /* in/out - pointer to the state */
    NTRU_CRYPTO_HASH_ALGID  algid,      /*     in - hash algorithm ID */
    uint8_t                 md_len,     /*     in - no. of octets in digest */
    uint8_t                 num_calls,  /*     in - no. of hash calls */
    uint16_t                seed_len,   /*     in - no. of octets in seed */
    uint8_t const          *seed,       /*     in - pointer to seed */
    uint8_t                *out);       /*    out - address for output */


/* ntru_mgftp1
 *
 * Implements a mask-generation function for trinary polynomials,
 * MGF-TP-1, generating an arbitrary number of octets based on hashing
 * a digest-length string concatenated with a 4-octet counter.  From
 * these octets, N trits are derived.
 *
 * The state (string and counter) is initialized when a seed is present.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_CRYPTO_HASH_ errors if they occur.
 *
 */

extern uint32_t
ntru_mgftp1(
    NTRU_CRYPTO_HASH_ALGID  hash_algid,       /*  in - hash alg ID for
                                                       MGF-TP-1 */
    uint8_t                 md_len,           /*  in - no. of octets in
                                                       digest */
    uint8_t                 min_calls,        /*  in - minimum no. of hash
                                                       calls */
    uint16_t                seed_len,         /*  in - no. of octets in seed */
    uint8_t                *seed,             /*  in - pointer to seed */
    uint8_t                *buf,              /*  in - pointer to working
                                                       buffer */
    uint16_t                num_trits_needed, /*  in - no. of trits in mask */
    uint8_t                *mask);            /* out - address for mask trits */


#endif /* NTRU_CRYPTO_NTRU_MGF1_H */
