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
 * File:  ntru_crypto_ntru_encrypt_key.h
 *
 * Contents: Public header file for exporting and importing public and
 *           private keys for NTRUEncrypt.
 *
 *****************************************************************************/


#ifndef NTRU_CRYPTO_NTRU_ENCRYPT_KEY_H
#define NTRU_CRYPTO_NTRU_ENCRYPT_KEY_H

#include "ntru_crypto_ntru_convert.h"
#include "ntru_crypto_ntru_encrypt_param_sets.h"


/* key-blob definitions */

#define NTRU_ENCRYPT_PUBKEY_TAG           0x01
#define NTRU_ENCRYPT_PRIVKEY_DEFAULT_TAG  0x02
#define NTRU_ENCRYPT_PRIVKEY_TRITS_TAG    0xfe
#define NTRU_ENCRYPT_PRIVKEY_INDICES_TAG  0xff

/* packing types */

#define NTRU_ENCRYPT_KEY_PACKED_COEFFICIENTS    0x01
#define NTRU_ENCRYPT_KEY_PACKED_INDICES         0x02
#define NTRU_ENCRYPT_KEY_PACKED_TRITS           0x03

/* function declarations */


/* ntru_crypto_ntru_encrypt_key_parse
 *
 * Parses an NTRUEncrypt key blob.
 * If the blob is not corrupt, returns packing types for public and private
 * keys, a pointer to the parameter set, a pointer to the public key, and
 * a pointer to the private key if it exists.
 *
 * Returns TRUE if successful.
 * Returns FALSE if the blob is invalid.
 */

extern bool
ntru_crypto_ntru_encrypt_key_parse(
    bool                     pubkey_parse,      /*  in - if parsing pubkey
                                                         blob */
    uint16_t                 key_blob_len,      /*  in - no. octets in key
                                                         blob */
    uint8_t const           *key_blob,          /*  in - pointer to key blob */
    uint8_t                 *pubkey_pack_type,  /* out - addr for pubkey
                                                         packing type */
    uint8_t                 *privkey_pack_type, /* out - addr for privkey
                                                         packing type */
    NTRU_ENCRYPT_PARAM_SET **params,            /* out - addr for ptr to
                                                         parameter set */
    uint8_t const          **pubkey,            /* out - addr for ptr to
                                                         packed pubkey */
    uint8_t const          **privkey);          /* out - addr for ptr to
                                                         packed privkey */


/* ntru_crypto_ntru_encrypt_key_get_blob_params
 *
 * Returns public and private key packing types and blob lengths given
 * a packing format.  For now, only a default packing format exists.
 *
 * Only public-key params may be returned by setting privkey_pack_type
 * and privkey_blob_len to NULL.
 */

extern void
ntru_crypto_ntru_encrypt_key_get_blob_params(
    NTRU_ENCRYPT_PARAM_SET const *params,             /*  in - pointer to
                                                               param set
                                                               parameters */
    uint8_t                      *pubkey_pack_type,   /* out - addr for pubkey
                                                               packing type */
    uint16_t                     *pubkey_blob_len,    /* out - addr for no. of
                                                               bytes in
                                                               pubkey blob */
    uint8_t                      *privkey_pack_type,  /* out - addr for privkey
                                                               packing type */
    uint16_t                     *privkey_blob_len);  /* out - addr for no. of
                                                               bytes in
                                                               privkey blob */


/* ntru_crypto_ntru_encrypt_key_create_pubkey_blob
 *
 * Returns a public key blob, packed according to the packing type provided.
 */

extern void
ntru_crypto_ntru_encrypt_key_create_pubkey_blob(
    NTRU_ENCRYPT_PARAM_SET const *params,             /*  in - pointer to
                                                               param set
                                                               parameters */
    uint16_t const               *pubkey,             /*  in - pointer to the
                                                               coefficients
                                                               of the pubkey */
    uint8_t                       pubkey_pack_type,   /* out - addr for pubkey
                                                               packing type */
    uint8_t                      *pubkey_blob);       /* out - addr for the
                                                               pubkey blob */


/* ntru_crypto_ntru_encrypt_key_recreate_pubkey_blob
 *
 * Returns a public key blob, recreated from an already-packed public key.
 */

extern void
ntru_crypto_ntru_encrypt_key_recreate_pubkey_blob(
    NTRU_ENCRYPT_PARAM_SET const *params,             /*  in - pointer to
                                                               param set
                                                               parameters */
    uint16_t                      packed_pubkey_len,  /*  in - no. octets in
                                                               packed pubkey */
    uint8_t const                *packed_pubkey,      /*  in - pointer to the
                                                               packed pubkey */
    uint8_t                       pubkey_pack_type,   /* out - pubkey packing
                                                               type */
    uint8_t                      *pubkey_blob);       /* out - addr for the
                                                               pubkey blob */


/* ntru_crypto_ntru_encrypt_key_create_privkey_blob
 *
 * Returns a privlic key blob, packed according to the packing type provided.
 */

extern void
ntru_crypto_ntru_encrypt_key_create_privkey_blob(
    NTRU_ENCRYPT_PARAM_SET const *params,             /*  in - pointer to
                                                               param set
                                                               parameters */
    uint16_t const               *pubkey,             /*  in - pointer to the
                                                               coefficients
                                                               of the pubkey */
    uint16_t const               *privkey,            /*  in - pointer to the
                                                               indices of the
                                                               privkey */
    uint8_t                       privkey_pack_type,  /*  in - privkey packing
                                                               type */
    uint8_t                      *buf,                /*  in - temp, N bytes */
    uint8_t                      *privkey_blob);      /* out - addr for the
                                                               privkey blob */


#endif /* NTRU_CRYPTO_NTRU_ENCRYPT_KEY_H */
