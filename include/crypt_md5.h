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


#ifndef __CRYPT_MD5_H__
#define __CRYPT_MD5_H__


/* Algorithm options */
#define MD5_SUPPORT

#ifdef MD5_SUPPORT
#define MD5_BLOCK_SIZE    64	/* 512 bits = 64 bytes */
#define MD5_DIGEST_SIZE   16	/* 128 bits = 16 bytes */
typedef struct {
	u32 HashValue[4];
	uint64_t MessageLen;
	u8 Block[MD5_BLOCK_SIZE];
	UINT BlockLen;
} MD5_CTX_STRUC, *PMD5_CTX_STRUC;

void RT_MD5_Init(
	MD5_CTX_STRUC * pMD5_CTX);
void RT_MD5_Hash(
	MD5_CTX_STRUC * pMD5_CTX);
void RT_MD5_Append(
	MD5_CTX_STRUC * pMD5_CTX,
	const u8 Message[],
	UINT MessageLen);
void RT_MD5_End(
	MD5_CTX_STRUC * pMD5_CTX,
	u8 DigestMessage[]);
void RT_MD5(
	const u8 Message[],
	UINT MessageLen,
	u8 DigestMessage[]);
#endif /* MD5_SUPPORT */


#endif /* __CRYPT_MD5_H__ */
