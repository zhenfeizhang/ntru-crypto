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
 * File: ntru_crypto_ntru_encrypt_param_sets.h
 *
 * Contents: Definitions and declarations for the NTRUEncrypt parameter sets.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_NTRU_ENCRYPT_PARAM_SETS_H
#define NTRU_CRYPTO_NTRU_ENCRYPT_PARAM_SETS_H

#include "ntru_crypto.h"
#include "ntru_crypto_hash_basics.h"


/* structures */

typedef struct _NTRU_ENCRYPT_PARAM_SET {
    NTRU_ENCRYPT_PARAM_SET_ID id;                 /* parameter-set ID */
    uint8_t const             OID[3];             /* pointer to OID */
    uint8_t                   der_id;             /* parameter-set DER id */
    uint8_t                   N_bits;             /* no. of bits in N (i.e. in
                                                     an index */
    uint16_t                  N;                  /* ring dimension */
    uint16_t                  sec_strength_len;   /* no. of octets of
                                                     security strength */
    uint16_t                  q;                  /* big modulus */
    uint8_t                   q_bits;             /* no. of bits in q (i.e. in
                                                     a coefficient */
    bool                      is_product_form;    /* if product form used */
    uint32_t                  dF_r;               /* no. of 1 or -1 coefficients
                                                     in ring elements F, r */
    uint16_t                  dg;                 /* no. - 1 of 1 coefficients
                                                     or no. of -1 coefficients
                                                     in ring element g */
    uint16_t                  m_len_max;          /* max no. of plaintext
                                                     octets */
    uint16_t                  min_msg_rep_wt;     /* min. message
                                                     representative weight */
    uint16_t                  no_bias_limit;      /* limit for no bias in
                                                     IGF-2 */
    uint8_t                   c_bits;             /* no. bits in candidate for
                                                     deriving an index in
                                                     IGF-2 */
    uint8_t                   m_len_len;          /* no. of octets to hold
                                                     mLenOctets */
    uint8_t                   min_IGF_hash_calls; /* min. no. of hash calls for
                                                     IGF-2 */
    uint8_t                   min_MGF_hash_calls; /* min. no. of hash calls for
                                                     MGF-TP-1 */
} NTRU_ENCRYPT_PARAM_SET;



/* function declarations */

/* ntru_encrypt_get_params_with_id
 *
 * Looks up a set of NTRU Encrypt parameters based on the id of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

extern NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_id(
    NTRU_ENCRYPT_PARAM_SET_ID id);  /*  in - parameter-set id */


/* ntru_encrypt_get_params_with_OID
 *
 * Looks up a set of NTRU Encrypt parameters based on the OID of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

extern NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_OID(
    uint8_t const *oid);            /*  in - pointer to parameter-set OID */


/* ntru_encrypt_get_params_with_DER_id
 *
 * Looks up a set of NTRUEncrypt parameters based on the DER id of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

extern NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_DER_id(
    uint8_t der_id);                /*  in - parameter-set DER id */


#endif /* NTRU_CRYPTO_NTRU_ENCRYPT_PARAM_SETS_H */

