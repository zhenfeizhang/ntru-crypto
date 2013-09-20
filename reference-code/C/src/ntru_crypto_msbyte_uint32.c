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
 * File: ntru_crypto_msbyte_uint32.c
 *
 * Contents: Routines to convert between an array of bytes in network byte
 *           order (most-significant byte first) and an array of uint32 words.
 *
 *****************************************************************************/


#include <stdlib.h>
#include "ntru_crypto_msbyte_uint32.h"


/* ntru_crypto_msbyte_2_uint32()
 *
 * This routine converts an array of bytes in network byte order to an array
 * of uint32_t, placing the first byte in the most significant byte of the
 * first uint32_t word.
 *
 * The number of bytes in the input stream MUST be at least 4 times the
 * number of words expected in the output array.
 */

void
ntru_crypto_msbyte_2_uint32(
    uint32_t       *words,      // out - pointer to the output uint32_t array
    uint8_t const  *bytes,      //  in - pointer to the input byte array
    uint32_t        n)          //  in - number of words in the output array
{
    uint32_t    i;

    for (i = 0; i < n; i++) {
        words[i]  = ((uint32_t) (*bytes++)) << 24;
        words[i] |= ((uint32_t) (*bytes++)) << 16;
        words[i] |= ((uint32_t) (*bytes++)) <<  8;
        words[i] |=  (uint32_t) (*bytes++);
    }
}


/* ntru_crypto_uint32_2_msbyte()
 *
 * This routine converts an array of uint32_t to an array of bytes in
 * network byte order, placing the most significant byte of the first uint32_t
 * word as the first byte of the output array.
 *
 * The number of bytes in the output stream will be 4 times the number of words
 * specified in the input array.
 */

void
ntru_crypto_uint32_2_msbyte(
    uint8_t        *bytes,      // out - pointer to the output byte array
    uint32_t const *words,      //  in - pointer to the input uint32_t array
    uint32_t        n)          //  in - number of words in the input array
{
    uint32_t i;

    for (i = 0; i < n; i++) {
        *bytes++ = (uint8_t) (words[i] >> 24);
        *bytes++ = (uint8_t) (words[i] >> 16);
        *bytes++ = (uint8_t) (words[i] >>  8);
        *bytes++ = (uint8_t) (words[i]      );
    }
}


