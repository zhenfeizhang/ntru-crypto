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
 * File: ntru_crypto_hash_basics.h
 *
 * Contents: Common definitions for all hash algorithms.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_HASH_BASICS_H
#define NTRU_CRYPTO_HASH_BASICS_H

#include "ntru_crypto_platform.h"


/**************
 * algorithms *
 **************/

typedef enum {
    NTRU_CRYPTO_HASH_ALGID_NONE = 0,
    NTRU_CRYPTO_HASH_ALGID_SHA1,
    NTRU_CRYPTO_HASH_ALGID_SHA256,
} NTRU_CRYPTO_HASH_ALGID;


/***************
 * error codes *
 ***************/

#define NTRU_CRYPTO_HASH_OK              ((uint32_t)0x00)
#define NTRU_CRYPTO_HASH_FAIL            ((uint32_t)0x01)
#define NTRU_CRYPTO_HASH_BAD_PARAMETER   ((uint32_t)0x02)
#define NTRU_CRYPTO_HASH_OVERFLOW        ((uint32_t)0x03)
#define NTRU_CRYPTO_HASH_BAD_ALG         ((uint32_t)0x20)
#define NTRU_CRYPTO_HASH_OUT_OF_MEMORY   ((uint32_t)0x21)

// For backward-compatibility
typedef uint32_t NTRU_CRYPTO_HASH_ERROR;


/*********
 * flags *
 *********/

#define HASH_DATA_ONLY      0
#define HASH_INIT           (1 << 0)
#define HASH_FINISH         (1 << 1)
#define HASH_ZERO_PAD       (1 << 2)


#endif /* NTRU_CRYPTO_HASH_BASICS_H */
