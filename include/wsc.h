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


#ifndef	__WSC_H__
#define	__WSC_H__

/* WSC OUI SMI */
#define WSC_OUI				0x0050f204
#define	WSC_SMI				0x00372A
#define	WSC_VENDOR_TYPE		0x00000001

/* EAP code */
#define	EAP_CODE_REQ		0x01
#define	EAP_CODE_RSP		0x02
#define	EAP_CODE_FAIL		0x04
#define EAP_TYPE_ID			0x01
#define EAP_TYPE_NOTIFY		0x02
#define	EAP_TYPE_WSC		0xfe


/* structure to store Simple Config Attributes Info */
typedef struct __attribute__ ((packed)) _WSC_LV_INFO {
    unsigned short  ValueLen;
    u8   Value[512];
} WSC_LV_INFO;

typedef struct __attribute__ ((packed)) _WSC_IE_HEADER {
	u8 elemId;
	u8 length;
	u8 oui[4];
} WSC_IE_HEADER;

/* WSC IE structure */
typedef	struct __attribute__ ((packed)) _WSC_IE
{
	unsigned short	Type;
	unsigned short	Length;
	u8 Data[1];	/* variable length data */
}	WSC_IE, *PWSC_IE;

/* WSC fixed information within EAP */
typedef	struct __attribute__ ((packed)) _WSC_FRAME
{
	u8 SMI[3];
	unsigned int	VendorType;
	u8 OpCode;
	u8 Flags;
}	WSC_FRAME, *PWSC_FRAME;

/* EAP frame format */
typedef	struct __attribute__ ((packed)) _EAP_FRAME	{
	u8 Code;						/* 1 = Request, 2 = Response */
	u8 Id;
	unsigned short	Length;
	u8 Type;						/* 1 = Identity, 0xfe = reserved, used by WSC */
}	EAP_FRAME, *PEAP_FRAME;

static inline bool WscCheckWSCHeader(
    u8 *             pData)
{
    PWSC_FRAME			pWsc;

	pWsc = (PWSC_FRAME) pData;

    /* Verify SMI first */
	if (((pWsc->SMI[0] * 256 + pWsc->SMI[1]) * 256 + pWsc->SMI[2]) != WSC_SMI)
	{
		/* Wrong WSC SMI Vendor ID, Update WSC status */
		return  false;
	}

    /* Verify Vendor Type */
	if (cpu2be32(get_unaligned32(&pWsc->VendorType)) != WSC_VENDOR_TYPE)
	{
		/* Wrong WSC Vendor Type, Update WSC status */
		return  false;
	}
    return true;
}

#endif	/* __WSC_H__ */

