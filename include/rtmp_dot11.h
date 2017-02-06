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


#ifndef __DOT11_BASE_H__
#define __DOT11_BASE_H__

#include "rtmp_type.h"

#ifdef DOT11_VHT_AC
#include "dot11ac_vht.h"
#endif /* DOT11_VHT_AC */

/* 4-byte HTC field.  maybe included in any frame except non-QOS data frame.  The Order bit must set 1. */
typedef struct __attribute__ ((packed)) _HT_CONTROL{
#ifdef RT_BIG_ENDIAN
	u32 RDG:1;
	u32 ACConstraint:1;
	u32 rsv2:5;
	u32 NDPAnnounce:1;
	u32 CSISTEERING:2;
	u32 rsv1:2;
	u32 CalSeq:2;
	u32 CalPos:2;
	u32 MFBorASC:7;
	u32 MFSI:3;
	u32 MSI:3;
	u32 MRQ:1;
	u32 TRQ:1;
	u32 vht:1;
#else
	u32 vht:1;		/* indicate for VHT variant or HT variant */
	u32 TRQ:1;		/*sounding request */
	u32 MRQ:1;		/*MCS feedback. Request for a MCS feedback */
	u32 MSI:3;		/*MCS Request, MRQ Sequence identifier */
	u32 MFSI:3;		/*SET to the received value of MRS. 0x111 for unsolicited MFB. */
	u32 MFBorASC:7;	/*Link adaptation feedback containing recommended MCS. 0x7f for no feedback or not available */
	u32 CalPos:2;	/* calibration position */
	u32 CalSeq:2;	/*calibration sequence */
	u32 rsv1:2;		/* Reserved */
	u32 CSISTEERING:2;	/*CSI/ STEERING */
	u32 NDPAnnounce:1;	/* ZLF announcement */
	u32 rsv2:5;		/*calibration sequence */
	u32 ACConstraint:1;	/*feedback request */
	u32 RDG:1;		/*RDG / More PPDU */
#endif				/* !RT_BIG_ENDIAN */
} HT_CONTROL, *PHT_CONTROL;

/* 2-byte QOS CONTROL field */
typedef struct __attribute__ ((packed)) _QOS_CONTROL{
#ifdef RT_BIG_ENDIAN
	unsigned short Txop_QueueSize:8;
	unsigned short AMsduPresent:1;
	unsigned short AckPolicy:2;	/*0: normal ACK 1:No ACK 2:scheduled under MTBA/PSMP  3: BA */
	unsigned short EOSP:1;
	unsigned short TID:4;
#else
	unsigned short TID:4;
	unsigned short EOSP:1;
	unsigned short AckPolicy:2;	/*0: normal ACK 1:No ACK 2:scheduled under MTBA/PSMP  3: BA */
	unsigned short AMsduPresent:1;
	unsigned short Txop_QueueSize:8;
#endif				/* !RT_BIG_ENDIAN */
} QOS_CONTROL, *PQOS_CONTROL;


typedef struct __attribute__ ((packed)) _AC_PARAM_RECORD{
	u8 aci_aifsn;
	u8 ecw_max:4;
	u8 ecw_min: 4;
	uint16_t txop_limit;
}AC_PARAM_RECORD;


typedef struct __attribute__ ((packed)) _PSPOLL_FRAME {
	FRAME_CONTROL FC;
	unsigned short Aid;
	u8 Bssid[ETH_ALEN];
	u8 Ta[ETH_ALEN];
} PSPOLL_FRAME, *PPSPOLL_FRAME;


typedef struct __attribute__ ((packed)) _RTS_FRAME {
	FRAME_CONTROL FC;
	unsigned short Duration;
	u8 Addr1[ETH_ALEN];
	u8 Addr2[ETH_ALEN];
} RTS_FRAME, *PRTS_FRAME;

#endif /* __DOT11_BASE_H__ */
