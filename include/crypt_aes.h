/*
 *************************************************************************
 * Ralink Tech Inc.
 * 5F., No.36, Taiyuan St., Jhubei City,
 * Hsinchu County 302,
 * Taiwan, R.O.C.
 *
 * (c) Copyright 2002-2010, Ralink Technology, Inc.
 *
 * This program is free software; you can redistribute it and/or modify  *
 * it under the terms of the GNU General Public License as published by  *
 * the Free Software Foundation; either version 2 of the License, or     *
 * (at your option) any later version.                                   *
 *                                                                       *
 * This program is distributed in the hope that it will be useful,       *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 * GNU General Public License for more details.                          *
 *                                                                       *
 * You should have received a copy of the GNU General Public License     *
 * along with this program; if not, write to the                         *
 * Free Software Foundation, Inc.,                                       *
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 *                                                                       *
 *************************************************************************/


#ifndef __CRYPT_AES_H__
#define __CRYPT_AES_H__

#include "rt_config.h"


/* AES definition & structure */
#define AES_STATE_ROWS 4     /* Block size: 4*4*8 = 128 bits */
#define AES_STATE_COLUMNS 4
#define AES_BLOCK_SIZES AES_STATE_ROWS*AES_STATE_COLUMNS
#define AES_KEY_ROWS 4
#define AES_KEY_COLUMNS 8    /*Key length: 4*{4,6,8}*8 = 128, 192, 256 bits */
#define AES_KEY128_LENGTH 16
#define AES_KEY192_LENGTH 24
#define AES_KEY256_LENGTH 32
#define AES_CBC_IV_LENGTH 16

typedef struct {
    u8 State[AES_STATE_ROWS][AES_STATE_COLUMNS];
    u8 KeyWordExpansion[AES_KEY_ROWS][AES_KEY_ROWS*((AES_KEY256_LENGTH >> 2) + 6 + 1)];
} AES_CTX_STRUC, *PAES_CTX_STRUC;


/* AES operations */
void RT_AES_KeyExpansion (
    u8 Key[],
    UINT KeyLength,
    AES_CTX_STRUC *paes_ctx);

void RT_AES_Encrypt (
    u8 PlainBlock[],
    UINT PlainBlockSize,
    u8 Key[],
    UINT KeyLength,
    u8 CipherBlock[],
    UINT *CipherBlockSize);

void RT_AES_Decrypt (
    u8 CipherBlock[],
    UINT CipherBlockSize,
    u8 Key[],
    UINT KeyLength,
    u8 PlainBlock[],
    UINT *PlainBlockSize);

/* AES Counter with CBC-MAC operations */
void AES_CCM_MAC (
    u8 Payload[],
    UINT  PayloadLength,
    u8 Key[],
    UINT  KeyLength,
    u8 Nonce[],
    UINT  NonceLength,
    u8 AAD[],
    UINT  AADLength,
    UINT  MACLength,
    u8 MACText[]);

INT AES_CCM_Encrypt (
    u8 PlainText[],
    UINT  PlainTextLength,
    u8 Key[],
    UINT  KeyLength,
    u8 Nonce[],
    UINT  NonceLength,
    u8 AAD[],
    UINT  AADLength,
    UINT  MACLength,
    u8 CipherText[],
    UINT *CipherTextLength);

INT AES_CCM_Decrypt (
    u8 CipherText[],
    UINT  CipherTextLength,
    u8 Key[],
    UINT  KeyLength,
    u8 Nonce[],
    UINT  NonceLength,
    u8 AAD[],
    UINT  AADLength,
    UINT  MACLength,
    u8 PlainText[],
    UINT *PlainTextLength);

/* AES-CMAC operations */
void AES_CMAC_GenerateSubKey (
    u8 Key[],
    UINT KeyLength,
    u8 SubKey1[],
    u8 SubKey2[]);

void AES_CMAC (
    u8 PlainText[],
    UINT PlainTextLength,
    u8 Key[],
    UINT KeyLength,
    u8 MACText[],
    UINT *MACTextLength);



/* AES-CBC operations */
void AES_CBC_Encrypt (
    u8 PlainText[],
    UINT PlainTextLength,
    u8 Key[],
    UINT KeyLength,
    u8 IV[],
    UINT IVLength,
    u8 CipherText[],
    UINT *CipherTextLength);

void AES_CBC_Decrypt (
    u8 CipherText[],
    UINT CipherTextLength,
    u8 Key[],
    UINT KeyLength,
    u8 IV[],
    UINT IVLength,
    u8 PlainText[],
    UINT *PlainTextLength);

/* AES key wrap operations */
INT AES_Key_Wrap (
    u8 PlainText[],
    UINT  PlainTextLength,
    u8 Key[],
    UINT  KeyLength,
    u8 CipherText[],
    UINT *CipherTextLength);

INT AES_Key_Unwrap (
    u8 CipherText[],
    UINT  CipherTextLength,
    u8 Key[],
    UINT  KeyLength,
    u8 PlainText [],
    UINT *PlainTextLength);


#endif /* __CRYPT_AES_H__ */

