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


#ifndef __RAL_NMAC_PCI_H__
#define __RAL_NMAC_PCI_H__



/* INT_SOURCE_CSR: Interrupt source register. Write one to clear corresponding bit */
#define INT_SOURCE_CSR		0x200


#define INT_R0_DONE		(1<<0)
#define INT_R1_DONE		(1<<1)
#define INT_T0_DONE		(1<<4)
#define INT_T1_DONE		(1<<5)
#define INT_T2_DONE		(1<<6)
#define INT_T3_DONE		(1<<7)
#define INT_T4_DONE		(1<<8)
#define INT_T5_DONE		(1<<9)
#define INT_T6_DONE		(1<<10)
#define INT_T7_DONE		(1<<11)
#define INT_T8_DONE		(1<<12)
#define INT_T9_DONE		(1<<13)
#define INT_RESVD		((1<<14) | (1<<15))
#define INT_RX_COHE		(1<<16)
#define INT_TX_COHE		(1<<17)
#define INT_ANY_COH		(1<<18)
#define INT_MCU_CMD	(1<<19)
#define INT_TBTT_ISR	(1<<20)
#define INT_PRE_TBTT	(1<<21)
#define INT_TX_STAT		(1<<22)
#define INT_AUTO_WAKE	(1<<23)
#define INT_GP_TIMER	(1<<24)
#define INT_RESVD_2		(1<<25)
#define INT_RX_DLY		(1<<26)
#define INT_TX_DLY		(1<<27)

 /* Delayed Rx or indivi rx */
#define RxINT			(INT_R0_DONE | INT_R1_DONE /* | INT_RX_DLY */)
/* Delayed Tx or indivi tx */
#define TxDataInt		(INT_T0_DONE | INT_T1_DONE | INT_T2_DONE | INT_T3_DONE /*| INT_TX_DLY*/)

#ifdef RT8592
#define TxMgmtInt		(INT_T5_DONE /*| INT_TX_DLY*/)
#else
#define TxMgmtInt		(INT_T9_DONE /*| INT_TX_DLY*/)
#endif /* RT8592 */

#define RxCoherent		INT_RX_COHE
#define TxCoherent		INT_TX_COHE
#define TxRxCoherent		INT_ANY_COH

/* mcu */
#define McuCommand		INT_MCU_CMD
#define PreTBTTInt		INT_PRE_TBTT
#define TBTTInt			INT_TBTT_ISR

/*  fifo statistics full interrupt */
#define FifoStaFullInt		INT_TX_STAT

/* AutoWakeupInt interrupt */
#define AutoWakeupInt	INT_AUTO_WAKE

/* GPtimeout interrupt */
#define GPTimeOutInt	INT_GP_TIMER

#define INT_RX			(INT_R0_DONE | INT_R1_DONE)

#define INT_AC0_DLY		(INT_T0_DONE)
#define INT_AC1_DLY		(INT_T1_DONE)
#define INT_AC2_DLY		(INT_T2_DONE)
#define INT_AC3_DLY		(INT_T3_DONE)
#ifdef RT8592
#define INT_HCCA_DLY	(INT_T4_DONE)
#define INT_MGMT_DLY	(INT_T5_DONE)
#else
#define INT_HCCA_DLY	(INT_T8_DONE)
#define INT_MGMT_DLY	(INT_T9_DONE)
#endif /* RT8592 */

#ifdef RT_BIG_ENDIAN
typedef union _INT_SOURCE_CSR_STRUC {
	struct {
		uint32_t rsv1:4;
		uint32_t TxDelayINT:1;
		uint32_t RxDelayINT:1;
		uint32_t rsv2:1;
		uint32_t GPTimer:1;
		uint32_t AutoWakeup:1;
		uint32_t TXFifoStatusInt:1;
		uint32_t PreTBTT:1;
		uint32_t tbttInt:1;
		uint32_t MCUCommandINT:1;
		uint32_t trCoherent:1;
		uint32_t txCoherent:1;
		uint32_t rxCoherent:1;
		uint32_t rsv3:2;
		uint32_t TxDone9:1;
		uint32_t TxDone8:1;
		uint32_t TxDone7:1;
		uint32_t TxDone6:1;
		uint32_t MgmtDmaDone:1;
		uint32_t HccaDmaDone:1;
		uint32_t Ac3DmaDone:1;
		uint32_t Ac2DmaDone:1;
		uint32_t Ac1DmaDone:1;
		uint32_t Ac0DmaDone:1;
		uint32_t rsv4:2;
		uint32_t RxDone1:1;
		uint32_t RxDone:1;
	}field;
	uint32_t word;
}INT_SOURCE_CSR_STRUC;
#else
typedef union _INT_SOURCE_CSR_STRUC {
	struct {
		uint32_t RxDone:1;
		uint32_t RxDone1:1;
		uint32_t rsv4:2;
		uint32_t Ac0DmaDone:1;
		uint32_t Ac1DmaDone:1;
		uint32_t Ac2DmaDone:1;
		uint32_t Ac3DmaDone:1;
		uint32_t HccaDmaDone:1;
		uint32_t MgmtDmaDone:1;
		uint32_t TxDone6:1;
		uint32_t TxDone7:1;
		uint32_t TxDone8:1;
		uint32_t TxDone9:1;
		uint32_t rsv3:2;
		uint32_t rxCoherent:1;
		uint32_t txCoherent:1;
		uint32_t trCoherent:1;
		uint32_t MCUCommandINT:1;
		uint32_t tbttInt:1;
		uint32_t PreTBTT:1;
		uint32_t TXFifoStatusInt:1;
		uint32_t AutoWakeup:1;
		uint32_t GPTimer:1;
		uint32_t rsv2:1;
		uint32_t RxDelayINT:1;
		uint32_t TxDelayINT:1;
		uint32_t rsv1:4;
	}field;
	uint32_t word;
}INT_SOURCE_CSR_STRUC;
#endif /* RT_BIG_ENDIAN */


/* INT_MASK_CSR:   Interrupt MASK register.   1: the interrupt is mask OFF */
#define INT_MASK_CSR        0x204
#ifdef RT_BIG_ENDIAN
typedef union _PDMA_INT_MASK{
	struct {
		uint32_t rsv1:4;
		uint32_t TxDelayINT:1;
		uint32_t RxDelayINT:1;
		uint32_t rsv2:1;
		uint32_t GPTimer:1;
		uint32_t AutoWakeup:1;
		uint32_t TXFifoStatusInt:1;
		uint32_t PreTBTT:1;
		uint32_t tbttInt:1;
		uint32_t MCUCommandINT:1;
		uint32_t trCoherent:1;
		uint32_t txCoherent:1;
		uint32_t rxCoherent:1;
		uint32_t rsv3:2;
		uint32_t TxDone9:1;
		uint32_t TxDone8:1;
		uint32_t TxDone7:1;
		uint32_t TxDone6:1;
		uint32_t MgmtDmaDone:1;
		uint32_t HccaDmaDone:1;
		uint32_t Ac3DmaDone:1;
		uint32_t Ac2DmaDone:1;
		uint32_t Ac1DmaDone:1;
		uint32_t Ac0DmaDone:1;
		uint32_t rsv4:2;
		uint32_t RxDone1:1;
		uint32_t RxDone:1;
	}field;
	uint32_t word;
}PMDA_INT_MASK;
#else
typedef union _PDMA_INT_MASK{
	struct {
		uint32_t RxDone:1;
		uint32_t RxDone1:1;
		uint32_t rsv4:2;
		uint32_t Ac0DmaDone:1;
		uint32_t Ac1DmaDone:1;
		uint32_t Ac2DmaDone:1;
		uint32_t Ac3DmaDone:1;
		uint32_t HccaDmaDone:1;
		uint32_t MgmtDmaDone:1;
		uint32_t TxDone6:1;
		uint32_t TxDone7:1;
		uint32_t TxDone8:1;
		uint32_t TxDone9:1;
		uint32_t rsv3:2;
		uint32_t rxCoherent:1;
		uint32_t txCoherent:1;
		uint32_t trCoherent:1;
		uint32_t MCUCommandINT:1;
		uint32_t tbttInt:1;
		uint32_t PreTBTT:1;
		uint32_t TXFifoStatusInt:1;
		uint32_t AutoWakeup:1;
		uint32_t GPTimer:1;
		uint32_t rsv2:1;
		uint32_t RxDelayINT:1;
		uint32_t TxDelayINT:1;
		uint32_t rsv1:4;
	}field;
	uint32_t word;
}PMDA_INT_MASK;
#endif /* RT_BIG_ENDIAN */


/*
	Tx Ring Layout and assignments

	Totally we have 10 Tx Rings and assigned as following usage:
	1. RT85592
		TxRing 0~3: for TxQ Channel 1 with AC_BK/BE/VI/VO
		TxRing 4    : for TxQ CTRL
		TxRing 5    : for TxQ MGMT
		TxRing 6~9: for TxQ Channel 2 with AC_BK/BE/VI/VO

	2. MT7650
		TxRing 0~3: for TxQ Channel 1 with AC_BK/BE/VI/VO
		TxRing 4~7: for TxQ Channel 2 with AC_BK/BE/VI/VO
		TxRing 8    : for TxQ CTRL
		TxRing 9    : for TxQ MGMT

	For each TxRing, we have four register to control it
		TX_RINGn_CTRL0 (0x0): base address of this ring(4-DWORD aligned address)
		TX_RINGn_CTRL1 (0x4): maximum number of TxD count in this ring
		TX_RINGn_CTRL2 (0x8): Point to the next TxD CPU wants to use
		TX_RINGn_CTRL3 (0xc): Point to the next TxD DMA wants to use

*/
#define RINGREG_DIFF	0x10
#define TX_RING_BASE	0x0300
#define TX_RING_NUM		10
#define TX_RING_PTR		0x0300
#define TX_RING_CNT		0x0304
#define TX_RING_CIDX	0x0308
#define TX_RING_DIDX	0x030c

#ifdef RT8592
#define TX_MGMT_BASE	(TX_RING_BASE  + RINGREG_DIFF * 5)
#else
/* Mgmt Tx Ring registers */
#define TX_MGMT_BASE	(TX_RING_BASE  + RINGREG_DIFF * 9)
#endif /* RT8592 */
#define TX_MGMT_CNT	(TX_MGMT_BASE + 0x04)
#define TX_MGMT_CIDX	(TX_MGMT_BASE + 0x08)
#define TX_MGMT_DIDX	(TX_MGMT_BASE + 0x0c)

#ifdef RT8592
#define TX_CTRL_BASE	(TX_RING_BASE  + RINGREG_DIFF * 4)
#else
/* Mgmt Tx Ring registers */
#define TX_CTRL_BASE	(TX_RING_BASE  + RINGREG_DIFF * 8)
#endif /* RT8592 */
#define TX_CTRL_CNT		(TX_CTRL_BASE + 0x04)
#define TX_CTRL_CIDX	(TX_CTRL_BASE + 0x08)
#define TX_CTRL_DIDX	(TX_CTRL_BASE + 0x0c)


#define TX_CHAN_BASE_1		(TX_RING_BASE + RINGREG_DIFF * 0)
#define TX_CHAN_BASE_2		(TX_RING_BASE + RINGREG_DIFF * 6)

/* following address is base on TX_CHAN_BASE_X */
#define TX_RING_BK_BASE	0x0
#define TX_RING_BK_CNT		(TX_RING_BK_BASE + 0x04)
#define TX_RING_BK_CIDX		(TX_RING_BK_BASE + 0x08)
#define TX_RING_BK_DIDX	(TX_RING_BK_BASE + 0x0c)

#define TX_RING_BE_BASE	(TX_RING_BK_BASE + RINGREG_DIFF)
#define TX_RING_BE_CNT		(TX_RING_BE_BASE + 0x04)
#define TX_RING_BE_CIDX		(TX_RING_BE_BASE + 0x08)
#define TX_RING_BE_DIDX	(TX_RING_BE_BASE + 0x0c)

#define TX_RING_VI_BASE		(TX_RING_BE_BASE + RINGREG_DIFF)
#define TX_RING_VI_CNT		(TX_RING_VI_BASE + 0x04)
#define TX_RING_VI_CIDX		(TX_RING_VI_BASE + 0x08)
#define TX_RING_VI_DIDX		(TX_RING_VI_BASE + 0x0c)

#define TX_RING_VO_BASE	(TX_RING_VI_BASE + RINGREG_DIFF)
#define TX_RING_VO_CNT		(TX_RING_VO_BASE + 0x04)
#define TX_RING_VO_CIDX	(TX_RING_VO_BASE + 0x08)
#define TX_RING_VO_DIDX	(TX_RING_VO_BASE + 0x0c)


/*
	Rx Ring Layput and assignments

	Totally we have 2 Rx Rings and assigned as following usage:
		RxRing 0: for all received data packets
		RxRing 1: for internal ctrl/info packets generated by on-chip CPU.

	For each TxRing, we have four register to control it
		RX_RING_CTRL0 (0x0): base address of this ring(4-DWORD aligned address)
		RX_RING_CTRL1 (0x4): maximum number of RxD count in this ring
		RX_RING_CTRL2 (0x8): Point to the next RxD CPU wants to use
		RX_RING_CTRL3 (0xc): Point to the next RxD DMA wants to use
*/
#define RX_RING_BASE	0x03c0
#define RX_RING_NUM	2
#define RX_RING_PTR		RX_RING_BASE
#define RX_RING_CNT		(RX_RING_BASE + 0x04)
#define RX_RING_CIDX	(RX_RING_BASE + 0x08)
#define RX_RING_DIDX	(RX_RING_BASE + 0x0c)

#endif /*__RAL_NMAC_PCI_H__ */

