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
 * File:  ntru_crypto_error.h
 *
 * Contents: Contains base values for crypto error codes.
 *
 *****************************************************************************/


#ifndef NTRU_CRYPTO_ERROR_H
#define NTRU_CRYPTO_ERROR_H

/* define base values for crypto error codes */

#define HASH_ERROR_BASE     ((uint32_t)0x00000100)
#define HMAC_ERROR_BASE     ((uint32_t)0x00000200)
#define SHA_ERROR_BASE      ((uint32_t)0x00000400)
#define DRBG_ERROR_BASE     ((uint32_t)0x00000a00)
#define NTRU_ERROR_BASE     ((uint32_t)0x00003000)
#define MGF1_ERROR_BASE     ((uint32_t)0x00004100)

#endif /* NTRU_CRYPTO_ERROR_H */
