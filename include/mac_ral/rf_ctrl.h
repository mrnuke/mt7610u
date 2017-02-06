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


#ifndef __RF_CTRL_H__
#define __RF_CTRL_H__

/* ================================================================================= */
/* Register format  for RFCTRL                                                                                                                                               */
/* ================================================================================= */

#define	RF_CSR_CFG	0x500

#ifdef RLT_RF

#define RF_BANK0	0
#define RF_BANK1	1
#define RF_BANK2	2
#define RF_BANK3	3
#define RF_BANK4	4
#define RF_BANK5	5
#define RF_BANK6	6
#define RF_BANK7	7
#define RF_BANK8	8
#define RF_BANK9	9
#define RF_BANK10	10
#define RF_BANK11	11
#define RF_BANK12	12
#define RF_BANK13	13
#define RF_BANK14	14
#define RF_BANK15	15

/* @!Release
	RF_CSR_KICK:1
			Write - kick RF register read/write
				0: do nothing
				1: kick read/write process
			Read - Polling RF register read/write
				0: idle
				1: busy
	RF_CSR_RW:1
			0: read  1: write
	rsv:12
	RF_CSR_REG_ID:10
			RF register ID, 0 for R0, 1 for R1 and so on
				Bits [17:15] 3 bits, indicates the bank number
				Bits [14:08] 7 bits, indicates the register number

	RF_CSR_DATA:8
			DATA written to/read from RF
*/
typedef	union _RLT_RF_CSR_CFG {
#ifdef RT_BIG_ENDIAN
	struct {
		unsigned int RF_CSR_KICK:1;
		unsigned int RF_CSR_WR:1;
		unsigned int rsv:12;
		unsigned int RF_CSR_REG_BANK:3;
		unsigned int RF_CSR_REG_ID:7;
		unsigned int RF_CSR_DATA:8;
	} field;
#else
	struct {
		unsigned int RF_CSR_DATA:8;
		unsigned int RF_CSR_REG_ID:7;
		unsigned int RF_CSR_REG_BANK:3;
		unsigned int rsv:12;
		unsigned int RF_CSR_WR:1;
		unsigned int RF_CSR_KICK:1;
	} field;
#endif /* RT_BIG_ENDIAN */
	unsigned int word;
}RLT_RF_CSR_CFG;
#endif /* RLT_RF */


typedef	union _RF_CSR_CFG_STRUC {
#ifdef RT_BIG_ENDIAN
	struct {
		u32	Rsvd1:14;				/* Reserved */
		u32	RF_CSR_KICK:1;			/* kick RF register read/write */
		u32	RF_CSR_WR:1;			/* 0: read  1: write */
		u32	TESTCSR_RFACC_REGNUM:8;	/* RF register ID */
		u32	RF_CSR_DATA:8;			/* DATA */
	} field;
#else
	struct {
		u32	RF_CSR_DATA:8;
		u32	TESTCSR_RFACC_REGNUM:8;
		u32	RF_CSR_WR:1;
		u32	RF_CSR_KICK:1;
		u32	Rsvd1:14;
	} field;
#endif /* RT_BIG_ENDIAN */
	u32 word;
}RF_CSR_CFG_STRUC;

#define RF_BYPASS_0		0x0504

#define RF_SETTING_0	0x050C

#endif /* __RF_CTRL_H__ */

