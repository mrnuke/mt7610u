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


#include "rt_config.h"


u8 SNAP_802_1H[] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00};
u8 SNAP_BRIDGE_TUNNEL[] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8};
u8 EAPOL[] = {0x88, 0x8e};
u8   TPID[] = {0x81, 0x00}; /* VLAN related */

u8 IPX[] = {0x81, 0x37};
u8 APPLE_TALK[] = {0x80, 0xf3};


u8 MapUserPriorityToAccessCategory[8] = {QID_AC_BE, QID_AC_BK, QID_AC_BK, QID_AC_BE, QID_AC_VI, QID_AC_VI, QID_AC_VO, QID_AC_VO};



void dump_rxinfo(struct rtmp_adapter*pAd, struct rtmp_rxinfo *pRxInfo)
{
	DBGPRINT(RT_DEBUG_OFF, ("RxInfo Fields:\n"));

	DBGPRINT(RT_DEBUG_OFF, ("\tBA=%d\n", pRxInfo->BA));
	DBGPRINT(RT_DEBUG_OFF, ("\tDATA=%d\n", pRxInfo->DATA));
	DBGPRINT(RT_DEBUG_OFF, ("\tNULLDATA=%d\n", pRxInfo->NULLDATA));
	DBGPRINT(RT_DEBUG_OFF, ("\tFRAG=%d\n", pRxInfo->FRAG));
	DBGPRINT(RT_DEBUG_OFF, ("\tU2M=%d\n", pRxInfo->U2M));
	DBGPRINT(RT_DEBUG_OFF, ("\tMcast=%d\n", pRxInfo->Mcast));
	DBGPRINT(RT_DEBUG_OFF, ("\tBcast=%d\n", pRxInfo->Bcast));
	DBGPRINT(RT_DEBUG_OFF, ("\tMyBss=%d\n", pRxInfo->MyBss));
	DBGPRINT(RT_DEBUG_OFF, ("\tCrc=%d\n", pRxInfo->Crc));
	DBGPRINT(RT_DEBUG_OFF, ("\tCipherErr=%d\n", pRxInfo->CipherErr));
	DBGPRINT(RT_DEBUG_OFF, ("\tAMSDU=%d\n", pRxInfo->AMSDU));
	DBGPRINT(RT_DEBUG_OFF, ("\tHTC=%d\n", pRxInfo->HTC));
	DBGPRINT(RT_DEBUG_OFF, ("\tRSSI=%d\n", pRxInfo->RSSI));
	DBGPRINT(RT_DEBUG_OFF, ("\tL2PAD=%d\n", pRxInfo->L2PAD));
	DBGPRINT(RT_DEBUG_OFF, ("\tAMPDU=%d\n", pRxInfo->AMPDU));
	DBGPRINT(RT_DEBUG_OFF, ("\tDecrypted=%d\n", pRxInfo->Decrypted));
	DBGPRINT(RT_DEBUG_OFF, ("\tBssIdx3=%d\n", pRxInfo->BssIdx3));
	DBGPRINT(RT_DEBUG_OFF, ("\twapi_kidx=%d\n", pRxInfo->wapi_kidx));
	DBGPRINT(RT_DEBUG_OFF, ("\tpn_len=%d\n", pRxInfo->pn_len));
	DBGPRINT(RT_DEBUG_OFF, ("\tsw_fc_type0=%d\n", pRxInfo->action_wanted));
	DBGPRINT(RT_DEBUG_OFF, ("\tsw_fc_type1=%d\n", pRxInfo->sw_fc_type1));
	DBGPRINT(RT_DEBUG_OFF, ("\tprobe_rsp=%d\n", pRxInfo->probe_rsp));
	DBGPRINT(RT_DEBUG_OFF, ("\tbeacon=%d\n", pRxInfo->beacon));
	DBGPRINT(RT_DEBUG_OFF, ("\tdisasso=%d\n", pRxInfo->disasso));
	DBGPRINT(RT_DEBUG_OFF, ("\tdeauth=%d\n", pRxInfo->deauth));
	DBGPRINT(RT_DEBUG_OFF, ("\taction_wanted=%d\n", pRxInfo->action_wanted));
	DBGPRINT(RT_DEBUG_OFF, ("\trsv=%d\n", pRxInfo->rsv));

}


void dumpRxFCEInfo(struct rtmp_adapter*pAd, RXFCE_INFO *pRxFceInfo)
{
	DBGPRINT(RT_DEBUG_OFF, ("RxFCEInfo Fields:\n"));

	DBGPRINT(RT_DEBUG_OFF, ("\tinfo_type=%d\n", pRxFceInfo->info_type));
	DBGPRINT(RT_DEBUG_OFF, ("\ts_port=%d\n", pRxFceInfo->s_port));
	DBGPRINT(RT_DEBUG_OFF, ("\tqsel=%d\n", pRxFceInfo->qsel));
	DBGPRINT(RT_DEBUG_OFF, ("\tpcie_intr=%d\n", pRxFceInfo->pcie_intr));
	DBGPRINT(RT_DEBUG_OFF, ("\tmac_len=%d\n", pRxFceInfo->mac_len));
	DBGPRINT(RT_DEBUG_OFF, ("\tl3l4_done=%d\n", pRxFceInfo->l3l4_done));
	DBGPRINT(RT_DEBUG_OFF, ("\tpkt_80211=%d\n", pRxFceInfo->pkt_80211));
	DBGPRINT(RT_DEBUG_OFF, ("\tip_err=%d\n", pRxFceInfo->ip_err));
	DBGPRINT(RT_DEBUG_OFF, ("\ttcp_err=%d\n", pRxFceInfo->tcp_err));
	DBGPRINT(RT_DEBUG_OFF, ("\tudp_err=%d\n", pRxFceInfo->udp_err));
	DBGPRINT(RT_DEBUG_OFF, ("\tpkt_len=%d\n", pRxFceInfo->pkt_len));
}


static u8 *txwi_txop_str[]={"HT_TXOP", "PIFS", "SIFS", "BACKOFF", "Invalid"};
#define TXWI_TXOP_STR(_x)	((_x) <= 3 ? txwi_txop_str[(_x)]: txwi_txop_str[4])

void dumpTxWI(struct rtmp_adapter*pAd, struct txwi_nmac *pTxWI)
{
	DBGPRINT(RT_DEBUG_OFF, ("TxWI Fields:\n"));
	DBGPRINT(RT_DEBUG_OFF, ("\tPHYMODE=%d(%s)\n", pTxWI->TxWIPHYMODE,  get_phymode_str(pTxWI->TxWIPHYMODE)));
	DBGPRINT(RT_DEBUG_OFF, ("\tSTBC=%d\n", pTxWI->TxWISTBC));
	DBGPRINT(RT_DEBUG_OFF, ("\tShortGI=%d\n", pTxWI->TxWIShortGI));
	DBGPRINT(RT_DEBUG_OFF, ("\tBW=%d(%sMHz)\n", pTxWI->TxWIBW, get_bw_str(pTxWI->TxWIBW)));
	DBGPRINT(RT_DEBUG_OFF, ("\tLDPC=%d\n",pTxWI->TxWILDPC));
	DBGPRINT(RT_DEBUG_OFF, ("\tMCS=%d\n", pTxWI->TxWIMCS));
	DBGPRINT(RT_DEBUG_OFF, ("\tTxOP=%d(%s)\n", pTxWI->TxWITXOP, TXWI_TXOP_STR(pTxWI->TxWITXOP)));
	DBGPRINT(RT_DEBUG_OFF, ("\tMpduDensity=%d\n", pTxWI->TxWIMpduDensity));
	DBGPRINT(RT_DEBUG_OFF, ("\tAMPDU=%d\n", pTxWI->TxWIAMPDU));
	DBGPRINT(RT_DEBUG_OFF, ("\tTS=%d\n", pTxWI->TxWITS));
	DBGPRINT(RT_DEBUG_OFF, ("\tCF-ACK=%d\n", pTxWI->TxWICFACK));
	DBGPRINT(RT_DEBUG_OFF, ("\tMIMO-PS=%d\n", pTxWI->TxWIMIMOps));
	DBGPRINT(RT_DEBUG_OFF, ("\tNSEQ=%d\n", pTxWI->TxWINSEQ));
	DBGPRINT(RT_DEBUG_OFF, ("\tACK=%d\n", pTxWI->TxWIACK));
	DBGPRINT(RT_DEBUG_OFF, ("\tFRAG=%d\n", pTxWI->TxWIFRAG));
	DBGPRINT(RT_DEBUG_OFF, ("\tWCID=%d\n", pTxWI->TxWIWirelessCliID));
	DBGPRINT(RT_DEBUG_OFF, ("\tBAWinSize=%d\n", pTxWI->TxWIBAWinSize));
	DBGPRINT(RT_DEBUG_OFF, ("\tMPDUtotalByteCnt=%d\n", pTxWI->TxWIMPDUByteCnt));
	DBGPRINT(RT_DEBUG_OFF, ("\tTXBF_PT_SCA=%d\n", pTxWI->TxWITxBfPTSca));
	DBGPRINT(RT_DEBUG_OFF, ("\tTIM=%d\n", pTxWI->TxWITIM));
	DBGPRINT(RT_DEBUG_OFF, ("\tPID=%d\n", pTxWI->TxWIPacketId));
}


void dump_rxwi(struct rtmp_adapter*pAd, struct rxwi_nmac *pRxWI)
{
	DBGPRINT(RT_DEBUG_OFF, ("RxWI Fields:\n"));
	DBGPRINT(RT_DEBUG_OFF, ("\tWCID=%d\n", pRxWI->RxWIWirelessCliID));
	DBGPRINT(RT_DEBUG_OFF, ("\tPhyMode=%d(%s)\n", pRxWI->RxWIPhyMode, get_phymode_str(pRxWI->RxWIPhyMode)));
#ifdef RT65xx
	if (IS_RT65XX(pAd) && (pRxWI->RxWIPhyMode == MODE_VHT))
		DBGPRINT(RT_DEBUG_OFF, ("\tMCS=%d(Nss:%d, MCS:%d)\n", pRxWI->RxWIMCS, (pRxWI->RxWIMCS >> 4), (pRxWI->RxWIMCS & 0xf)));
	else
#endif /* RT65xx */
		DBGPRINT(RT_DEBUG_OFF, ("\tMCS=%d\n", pRxWI->RxWIMCS));
	DBGPRINT(RT_DEBUG_OFF, ("\tLDPC=%d\n", pRxWI->RxWILDPC));
	DBGPRINT(RT_DEBUG_OFF, ("\tBW=%d\n", pRxWI->RxWIBW));
	DBGPRINT(RT_DEBUG_OFF, ("\tSGI=%d\n", pRxWI->RxWISGI));
	DBGPRINT(RT_DEBUG_OFF, ("\tMPDUtotalByteCnt=%d\n", pRxWI->RxWIMPDUByteCnt));
	DBGPRINT(RT_DEBUG_OFF, ("\tTID=%d\n", pRxWI->RxWITID));
	DBGPRINT(RT_DEBUG_OFF, ("\tSTBC=%d\n", pRxWI->RxWISTBC));
	DBGPRINT(RT_DEBUG_OFF, ("\tkey_idx=%d\n", pRxWI->RxWIKeyIndex));
	DBGPRINT(RT_DEBUG_OFF, ("\tBSS_IDX=%d\n", pRxWI->RxWIBSSID));
}


static u8 *txinfo_type_str[]={"PKT", "", "CMD", "RSV", "Invalid"};
static u8 *txinfo_d_port_str[]={"WLAN", "CPU_RX", "CPU_TX", "HOST", "VIRT_RX", "VIRT_TX", "DROP", "Invalid"};
static u8 *txinfo_que_str[]={"MGMT", "HCCA", "EDCA_1", "EDCA_2", "Invalid"};

#define TXINFO_TYPE_STR(_x)  	((_x)<=3 ?  txinfo_type_str[_x] : txinfo_type_str[4])
#define TXINFO_DPORT_STR(_x)	((_x) <= 6 ? txinfo_d_port_str[_x]: txinfo_d_port_str[7])
#define TXINFO_QUE_STR(_x)		((_x) <= 3 ? txinfo_que_str[_x]: txinfo_que_str[4])

void dump_txinfo(struct rtmp_adapter*pAd, struct txinfo_nmac_pkt *pTxInfo)
{
	DBGPRINT(RT_DEBUG_OFF, ("TxInfo Fields:\n"));

	{
		struct txinfo_nmac_pkt *pkt_txinfo = pTxInfo;

		DBGPRINT(RT_DEBUG_OFF, ("\tInfo_Type=%d(%s)\n", pkt_txinfo->info_type, TXINFO_TYPE_STR(pkt_txinfo->info_type)));
		DBGPRINT(RT_DEBUG_OFF, ("\td_port=%d(%s)\n", pkt_txinfo->d_port, TXINFO_DPORT_STR(pkt_txinfo->d_port)));
		DBGPRINT(RT_DEBUG_OFF, ("\tQSEL=%d(%s)\n", pkt_txinfo->QSEL, TXINFO_QUE_STR(pkt_txinfo->QSEL)));
		DBGPRINT(RT_DEBUG_OFF, ("\tWIV=%d\n", pkt_txinfo->wiv));
		DBGPRINT(RT_DEBUG_OFF, ("\t802.11=%d\n", pkt_txinfo->pkt_80211));
		DBGPRINT(RT_DEBUG_OFF, ("\tcso=%d\n", pkt_txinfo->cso));
		DBGPRINT(RT_DEBUG_OFF, ("\ttso=%d\n", pkt_txinfo->tso));
		DBGPRINT(RT_DEBUG_OFF, ("\tpkt_len=0x%x\n", pkt_txinfo->pkt_len));
	}

}


#ifdef DBG_DIAGNOSE
static void dumpTxBlk(TX_BLK *pTxBlk)
{
	NDIS_PACKET *pPacket;
	int i, frameNum;
	PQUEUE_ENTRY	pQEntry;

	DBGPRINT(RT_DEBUG_TRACE,("Dump TX_BLK Structure:\n"));
	DBGPRINT(RT_DEBUG_TRACE,("\tTxFrameType=%d!\n", pTxBlk->TxFrameType));
	DBGPRINT(RT_DEBUG_TRACE,("\tTotalFrameLen=%d\n", pTxBlk->TotalFrameLen));
	DBGPRINT(RT_DEBUG_TRACE,("\tTotalFrameNum=%ld!\n", pTxBlk->TxPacketList.Number));
	DBGPRINT(RT_DEBUG_TRACE,("\tTotalFragNum=%d!\n", pTxBlk->TotalFragNum));
	DBGPRINT(RT_DEBUG_TRACE,("\tpPacketList=\n"));

	frameNum = pTxBlk->TxPacketList.Number;

	for(i=0; i < frameNum; i++)
	{	int j;
		u8 *pBuf;

		pQEntry = RemoveHeadQueue(&pTxBlk->TxPacketList);
		pPacket = QUEUE_ENTRY_TO_PACKET(pQEntry);
		if (pPacket)
		{
			pBuf = pPacket->data;
			DBGPRINT(RT_DEBUG_TRACE,("\t\t[%d]:ptr=0x%x, Len=%d!\n", i, (u32)pPacket->data), pPacket->len));
			DBGPRINT(RT_DEBUG_TRACE,("\t\t"));
			for (j =0 ; j < pPacket->len; j++)
			{
				DBGPRINT(RT_DEBUG_TRACE,("%02x ", (pBuf[j] & 0xff)));
				if (j == 16)
					break;
			}
			InsertTailQueue(&pTxBlk->TxPacketList, PACKET_TO_QUEUE_ENTRY(pPacket));
		}
	}
	DBGPRINT(RT_DEBUG_TRACE,("\tWcid=%d!\n", pTxBlk->Wcid));
	DBGPRINT(RT_DEBUG_TRACE,("\tapidx=%d!\n", pTxBlk->apidx));
	DBGPRINT(RT_DEBUG_TRACE,("----EndOfDump\n"));

}
#endif


/*
	========================================================================

	Routine Description:
		API for MLME to transmit management frame to AP (BSS Mode)
	or station (IBSS Mode)

	Arguments:
		pAd Pointer to our adapter
		pData		Pointer to the outgoing 802.11 frame
		Length		Size of outgoing management frame

	Return Value:
		NDIS_STATUS_FAILURE
		NDIS_STATUS_PENDING
		NDIS_STATUS_SUCCESS

	IRQL = PASSIVE_LEVEL
	IRQL = DISPATCH_LEVEL

	Note:

	========================================================================
*/
int MiniportMMRequest(
	struct rtmp_adapter*pAd,
	u8 QueIdx,
	u8 *pData,
	UINT Length)
{
	struct sk_buff * pPacket;
	int Status = NDIS_STATUS_SUCCESS;
	ULONG FreeNum;
	u8 TXWISize = sizeof(struct txwi_nmac);
	u8 rtmpHwHdr[40];
	bool bUseDataQ = false, FlgDataQForce = false, FlgIsLocked = false;
	int retryCnt = 0, hw_len = TXINFO_SIZE + TXWISize + TSO_SIZE;


	ASSERT(Length <= MGMT_DMA_BUFFER_SIZE);

	if ((QueIdx & MGMT_USE_QUEUE_FLAG) == MGMT_USE_QUEUE_FLAG)
	{
		bUseDataQ = true;
		QueIdx &= (~MGMT_USE_QUEUE_FLAG);
	}

	do
	{
		/* Reset is in progress, stop immediately*/
		if (RTMP_TEST_FLAG(pAd, (fRTMP_ADAPTER_RESET_IN_PROGRESS |
								fRTMP_ADAPTER_HALT_IN_PROGRESS |
								fRTMP_ADAPTER_NIC_NOT_EXIST |
								fRTMP_ADAPTER_RADIO_OFF)) ||
			 !RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_START_UP)
			)
		{
			Status = NDIS_STATUS_FAILURE;
			break;
		}

#ifdef CONFIG_STA_SUPPORT
#ifdef RTMP_MAC_USB
		if(RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_IDLE_RADIO_OFF))
				MT76x0UsbAsicRadioOn(pAd, MLME_RADIO_ON);
#endif /* RTMP_MAC_USB */
#endif /* CONFIG_STA_SUPPORT */

		/* Check Free priority queue*/
		/* Since we use PBF Queue2 for management frame.  Its corresponding DMA ring should be using TxRing.*/
		{
			FreeNum = GET_MGMTRING_FREENO(pAd);
		}

		if ((FreeNum > 0))
		{
			/* We need to reserve space for rtmp hardware header. i.e., TxWI for RT2860 and TxInfo+TxWI for RT2870*/
			memset(&rtmpHwHdr, 0, hw_len);
			Status = RTMPAllocateNdisPacket(pAd, &pPacket, (u8 *)&rtmpHwHdr, hw_len, pData, Length);
			if (Status != NDIS_STATUS_SUCCESS)
			{
				DBGPRINT(RT_DEBUG_WARN, ("MiniportMMRequest (error:: can't allocate NDIS PACKET)\n"));
				break;
			}




			Status = MlmeHardTransmit(pAd, QueIdx, pPacket, FlgDataQForce, FlgIsLocked);
			if (Status == NDIS_STATUS_SUCCESS)
				retryCnt = 0;
			else
				RTMPFreeNdisPacket(pAd, pPacket);
		}
		else
		{
			pAd->RalinkCounters.MgmtRingFullCount++;
			DBGPRINT(RT_DEBUG_ERROR, ("Qidx(%d), not enough space in MgmtRing, MgmtRingFullCount=%ld!\n",
										QueIdx, pAd->RalinkCounters.MgmtRingFullCount));
		}
	} while (retryCnt > 0);



	return Status;
}




/*
	========================================================================

	Routine Description:
		Copy frame from waiting queue into relative ring buffer and set
	appropriate ASIC register to kick hardware transmit function

	Arguments:
		pAd Pointer to our adapter
		pBuffer 	Pointer to	memory of outgoing frame
		Length		Size of outgoing management frame

	Return Value:
		NDIS_STATUS_FAILURE
		NDIS_STATUS_PENDING
		NDIS_STATUS_SUCCESS

	IRQL = PASSIVE_LEVEL
	IRQL = DISPATCH_LEVEL

	Note:

	========================================================================
*/
int MlmeHardTransmit(
	struct rtmp_adapter*pAd,
	u8 QueIdx,
	struct sk_buff * pPacket,
	bool FlgDataQForce,
	bool FlgIsLocked)
{
	PACKET_INFO 	PacketInfo;
	u8 *		pSrcBufVA;
	UINT			SrcBufLen;

	if ((pAd->Dot11_H.RDMode != RD_NORMAL_MODE)
		)
	{
		return NDIS_STATUS_FAILURE;
	}

	RTMP_QueryPacketInfo(pPacket, &PacketInfo, &pSrcBufVA, &SrcBufLen);
	if (pSrcBufVA == NULL)
		return NDIS_STATUS_FAILURE;

    {
    		return MlmeHardTransmitMgmtRing(pAd,QueIdx,pPacket);
    }
}


int MlmeHardTransmitMgmtRing(
	struct rtmp_adapter*pAd,
	u8 QueIdx,
	struct sk_buff * pPacket)
{
	PACKET_INFO PacketInfo;
	u8 *pSrcBufVA;
	UINT SrcBufLen;
	HEADER_802_11 *pHeader_802_11;
	bool bAckRequired, bInsertTimestamp;
	u8 MlmeRate;
	struct txwi_nmac *pFirstTxWI;
	MAC_TABLE_ENTRY *pMacEntry = NULL;
	u8 PID;
	u8 TXWISize = sizeof(struct txwi_nmac);


	RTMP_QueryPacketInfo(pPacket, &PacketInfo, &pSrcBufVA, &SrcBufLen);

	/* Make sure MGMT ring resource won't be used by other threads*/
	RTMP_SEM_LOCK(&pAd->MgmtRingLock);
	if (pSrcBufVA == NULL)
	{
		/* The buffer shouldn't be NULL*/
			RTMP_SEM_UNLOCK(&pAd->MgmtRingLock);
		return NDIS_STATUS_FAILURE;
	}

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		/* outgoing frame always wakeup PHY to prevent frame lost*/
		if (OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_DOZE))
			AsicForceWakeup(pAd, true);
	}
#endif /* CONFIG_STA_SUPPORT */

	pFirstTxWI = (struct txwi_nmac *)(pSrcBufVA +  TXINFO_SIZE);
	pHeader_802_11 = (PHEADER_802_11) (pSrcBufVA + TXINFO_SIZE + TSO_SIZE + TXWISize);

	if (pHeader_802_11->Addr1[0] & 0x01)
	{
		MlmeRate = pAd->CommonCfg.BasicMlmeRate;
	}
	else
	{
		MlmeRate = pAd->CommonCfg.MlmeRate;
	}

	/* Verify Mlme rate for a / g bands.*/
	if ((pAd->LatchRfRegs.Channel > 14) && (MlmeRate < RATE_6)) /* 11A band*/
		MlmeRate = RATE_6;

	if ((pHeader_802_11->FC.Type == BTYPE_DATA) &&
		(pHeader_802_11->FC.SubType == SUBTYPE_QOS_NULL))
	{
		pMacEntry = MacTableLookup(pAd, pHeader_802_11->Addr1);
	}

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		/* Fixed W52 with Activity scan issue in ABG_MIXED and ABGN_MIXED mode.*/
		// TODO: shiang-6590, why we need this condition check here?
		if (WMODE_EQUAL(pAd->CommonCfg.PhyMode, WMODE_A | WMODE_B | WMODE_G)
#ifdef DOT11_N_SUPPORT
			|| WMODE_EQUAL(pAd->CommonCfg.PhyMode, WMODE_A | WMODE_B | WMODE_G | WMODE_AN | WMODE_GN)
#endif /* DOT11_N_SUPPORT */
#ifdef DOT11_VHT_AC
			|| WMODE_CAP(pAd->CommonCfg.PhyMode, WMODE_AC)
#endif /* DOT11_VHT_AC*/
		)
		{
			if (pAd->LatchRfRegs.Channel > 14)
			{
				pAd->CommonCfg.MlmeTransmit.field.MODE = MODE_OFDM;
				pAd->CommonCfg.MlmeTransmit.field.MCS = MCS_RATE_6;
			}
			else
			{
				pAd->CommonCfg.MlmeTransmit.field.MODE = MODE_CCK;
				pAd->CommonCfg.MlmeTransmit.field.MCS = MCS_0;
			}
		}
	}
#endif /* CONFIG_STA_SUPPORT */

	/* Should not be hard code to set PwrMgmt to 0 (PWR_ACTIVE)*/
	/* Snice it's been set to 0 while on MgtMacHeaderInit*/
	/* By the way this will cause frame to be send on PWR_SAVE failed.*/

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS))
		{
			/* We are in scan progress, just let the PwrMgmt bit keep as it orginally should be.*/
		}
		else
#endif /* CONFIG_STA_SUPPORT */
			pHeader_802_11->FC.PwrMgmt = PWR_ACTIVE; /* (pAd->StaCfg.Psm == PWR_SAVE);*/
#ifdef CONFIG_STA_SUPPORT
	}
#endif /* CONFIG_STA_SUPPORT */

#ifdef CONFIG_STA_SUPPORT

	/* In WMM-UAPSD, mlme frame should be set psm as power saving but probe request frame*/
	/* Data-Null packets alse pass through MMRequest in RT2860, however, we hope control the psm bit to pass APSD*/
/*	if ((pHeader_802_11->FC.Type != BTYPE_DATA) && (pHeader_802_11->FC.Type != BTYPE_CNTL))*/
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		if ((pHeader_802_11->FC.SubType == SUBTYPE_ACTION) ||
			((pHeader_802_11->FC.Type == BTYPE_DATA) &&
			((pHeader_802_11->FC.SubType == SUBTYPE_QOS_NULL) ||
			(pHeader_802_11->FC.SubType == SUBTYPE_NULL_FUNC))))
		{
			if (RtmpPktPmBitCheck(pAd) == true)
				pHeader_802_11->FC.PwrMgmt = PWR_SAVE;
			else if (OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED) &&
					INFRA_ON(pAd) &&
					RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS))
			{
				/* We are in scan progress, just let the PwrMgmt bit keep as it orginally should be */
			}
			else
			{
				pHeader_802_11->FC.PwrMgmt = pAd->CommonCfg.bAPSDForcePowerSave;
			}
		}
	}
#endif /* CONFIG_STA_SUPPORT */





	bInsertTimestamp = false;
	if (pHeader_802_11->FC.Type == BTYPE_CNTL) /* must be PS-POLL*/
	{
#ifdef CONFIG_STA_SUPPORT
		/*Set PM bit in ps-poll, to fix WLK 1.2  PowerSaveMode_ext failure issue.*/
		if ((pAd->OpMode == OPMODE_STA) && (pHeader_802_11->FC.SubType == SUBTYPE_PS_POLL))
		{
			pHeader_802_11->FC.PwrMgmt = PWR_SAVE;
		}
#endif /* CONFIG_STA_SUPPORT */
		bAckRequired = false;
	}
	else /* BTYPE_MGMT or BTYPE_DATA(must be NULL frame)*/
	{
		if (pHeader_802_11->Addr1[0] & 0x01) /* MULTICAST, BROADCAST*/
		{
			bAckRequired = false;
			pHeader_802_11->Duration = 0;
		}
		else
		{
			bAckRequired = true;
			pHeader_802_11->Duration = RTMPCalcDuration(pAd, MlmeRate, 14);
			if ((pHeader_802_11->FC.SubType == SUBTYPE_PROBE_RSP) && (pHeader_802_11->FC.Type == BTYPE_MGMT))
			{
				bInsertTimestamp = true;
				bAckRequired = false; /* Disable ACK to prevent retry 0x1f for Probe Response*/
			}
			else if ((pHeader_802_11->FC.SubType == SUBTYPE_PROBE_REQ) && (pHeader_802_11->FC.Type == BTYPE_MGMT))
			{
				bAckRequired = false; /* Disable ACK to prevent retry 0x1f for Probe Request*/
			}
		}
	}

	pHeader_802_11->Sequence = pAd->Sequence++;
	if (pAd->Sequence >0xfff)
		pAd->Sequence = 0;

	/*
		Before radar detection done, mgmt frame can not be sent but probe req
		Because we need to use probe req to trigger driver to send probe req in passive scan
	*/
	if ((pHeader_802_11->FC.SubType != SUBTYPE_PROBE_REQ)
		&& (pAd->CommonCfg.bIEEE80211H == 1)
		&& (pAd->Dot11_H.RDMode != RD_NORMAL_MODE))
	{
		RTMP_SEM_UNLOCK(&pAd->MgmtRingLock);
		return NDIS_STATUS_FAILURE;
	}

#ifdef RT_BIG_ENDIAN
	RTMPFrameEndianChange(pAd, (u8 *)pHeader_802_11, DIR_WRITE, false);
#endif


	/*
		fill scatter-and-gather buffer list into TXD. Internally created NDIS PACKET
		should always has only one physical buffer, and the whole frame size equals
		to the first scatter buffer size
	*/


	/*
		Initialize TX Descriptor
		For inter-frame gap, the number is for this frame and next frame
		For MLME rate, we will fix as 2Mb to match other vendor's implement
	*/
	/*pAd->CommonCfg.MlmeTransmit.field.MODE = 1;*/

	/*
		management frame doesn't need encryption.
		so use RESERVED_WCID no matter u are sending to specific wcid or not
	*/
	PID = PID_MGMT;


	if (pMacEntry == NULL)
	{
		RTMPWriteTxWI(pAd, pFirstTxWI, false, false, bInsertTimestamp, false, bAckRequired, false,
						0, RESERVED_WCID, (SrcBufLen - TXINFO_SIZE - TXWISize - TSO_SIZE), PID, 0,
						(u8)pAd->CommonCfg.MlmeTransmit.field.MCS, IFS_BACKOFF, false,
						&pAd->CommonCfg.MlmeTransmit);
	}
	else
	{
		/* dont use low rate to send QoS Null data frame */
		RTMPWriteTxWI(pAd, pFirstTxWI, false, false,
					bInsertTimestamp, false, bAckRequired, false,
					0, pMacEntry->Aid, (SrcBufLen - TXINFO_SIZE - TXWISize - TSO_SIZE),
					pMacEntry->MaxHTPhyMode.field.MCS, 0,
					(u8)pMacEntry->MaxHTPhyMode.field.MCS,
					IFS_BACKOFF, false, &pMacEntry->MaxHTPhyMode);
	}

#ifdef RT_BIG_ENDIAN
	RTMPWIEndianChange(pFirstTxWI,sizeof(*pFirstTxWI));
#endif

	/* Now do hardware-depened kick out.*/
	HAL_KickOutMgmtTx(pAd, QueIdx, pPacket, pSrcBufVA, SrcBufLen);

	/* Make sure to release MGMT ring resource*/
/*	if (!IrqState)*/
		RTMP_SEM_UNLOCK(&pAd->MgmtRingLock);
	return NDIS_STATUS_SUCCESS;
}


/********************************************************************************

	New DeQueue Procedures.

 ********************************************************************************/
#define DEQUEUE_LOCK(lock, bIntContext, IrqFlags) 				\
			do{													\
				if (bIntContext == false)						\
				RTMP_IRQ_LOCK((lock), IrqFlags);		\
			}while(0)

#define DEQUEUE_UNLOCK(lock, bIntContext, IrqFlags)				\
			do{													\
				if (bIntContext == false)						\
					RTMP_IRQ_UNLOCK((lock), IrqFlags);	\
			}while(0)


/*
	========================================================================
	Tx Path design algorithm:
		Basically, we divide the packets into four types, Broadcast/Multicast, 11N Rate(AMPDU, AMSDU, Normal), B/G Rate(ARALINK, Normal),
		Specific Packet Type. Following show the classification rule and policy for each kinds of packets.
				Classification Rule=>
					Multicast: (*addr1 & 0x01) == 0x01
					Specific : bDHCPFrame, bARPFrame, bEAPOLFrame, etc.
					11N Rate : If peer support HT
								(1).AMPDU  -- If TXBA is negotiated.
								(2).AMSDU  -- If AMSDU is capable for both peer and ourself.
											*). AMSDU can embedded in a AMPDU, but now we didn't support it.
								(3).Normal -- Other packets which send as 11n rate.

					B/G Rate : If peer is b/g only.
								(1).ARALINK-- If both of peer/us supprot Ralink proprietary Aggregation and the TxRate is large than RATE_6
								(2).Normal -- Other packets which send as b/g rate.
					Fragment:
								The packet must be unicast, NOT A-RALINK, NOT A-MSDU, NOT 11n, then can consider about fragment.

				Classified Packet Handle Rule=>
					Multicast:
								No ACK, 		pTxBlk->bAckRequired = false;
								No WMM, 		pTxBlk->bWMM = false;
								No piggyback,   pTxBlk->bPiggyBack = false;
								Force LowRate,  pTxBlk->bForceLowRate = true;
					Specific :	Basically, for specific packet, we should handle it specifically, but now all specific packets are use
									the same policy to handle it.
								Force LowRate,  pTxBlk->bForceLowRate = true;

					11N Rate :
								No piggyback,	pTxBlk->bPiggyBack = false;

								(1).AMSDU
									pTxBlk->bWMM = true;
								(2).AMPDU
									pTxBlk->bWMM = true;
								(3).Normal

					B/G Rate :
								(1).ARALINK

								(2).Normal
	========================================================================
*/
static u8 TxPktClassification(
	struct rtmp_adapter*pAd,
	struct sk_buff *  pPacket)
{
	u8 		TxFrameType = TX_UNKOWN_FRAME;
	u8 		Wcid;
	MAC_TABLE_ENTRY	*pMacEntry = NULL;
#ifdef DOT11_N_SUPPORT
	bool 		bHTRate = false;
#endif /* DOT11_N_SUPPORT */

	Wcid = RTMP_GET_PACKET_WCID(pPacket);
	if (Wcid == MCAST_WCID)
	{	/* Handle for RA is Broadcast/Multicast Address.*/
		return TX_MCAST_FRAME;
	}

	/* Handle for unicast packets*/
	pMacEntry = &pAd->MacTab.Content[Wcid];
	if (RTMP_GET_PACKET_LOWRATE(pPacket))
	{	/* It's a specific packet need to force low rate, i.e., bDHCPFrame, bEAPOLFrame, bWAIFrame*/
		TxFrameType = TX_LEGACY_FRAME;
	}
#ifdef DOT11_N_SUPPORT
	else if (IS_HT_RATE(pMacEntry))
	{	/* it's a 11n capable packet*/

		/* Depends on HTPhyMode to check if the peer support the HTRate transmission.*/
		/* 	Currently didn't support A-MSDU embedded in A-MPDU*/
		bHTRate = true;
		if (RTMP_GET_PACKET_MOREDATA(pPacket) || (pMacEntry->PsMode == PWR_SAVE))
			TxFrameType = TX_LEGACY_FRAME;
#ifdef UAPSD_SUPPORT
		else if (RTMP_GET_PACKET_EOSP(pPacket))
			TxFrameType = TX_LEGACY_FRAME;
#endif /* UAPSD_SUPPORT */
#ifdef WFA_VHT_PF
		else if (pAd->force_amsdu == true)
			return TX_AMSDU_FRAME;
#endif /* WFA_VHT_PF */
		else if ((pMacEntry->TXBAbitmap & (1<<(RTMP_GET_PACKET_UP(pPacket)))) != 0)
			return TX_AMPDU_FRAME;
		else if(CLIENT_STATUS_TEST_FLAG(pMacEntry, fCLIENT_STATUS_AMSDU_INUSED)
		)
			return TX_AMSDU_FRAME;
		else
			TxFrameType = TX_LEGACY_FRAME;
	}
#endif /* DOT11_N_SUPPORT */
	else
	{	/* it's a legacy b/g packet.*/
		if ((CLIENT_STATUS_TEST_FLAG(pMacEntry, fCLIENT_STATUS_AGGREGATION_CAPABLE) && pAd->CommonCfg.bAggregationCapable) &&
			(RTMP_GET_PACKET_TXRATE(pPacket) >= RATE_6) &&
			(!(OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_WMM_INUSED) && CLIENT_STATUS_TEST_FLAG(pMacEntry, fCLIENT_STATUS_WMM_CAPABLE)))
		)
		{	/* if peer support Ralink Aggregation, we use it.*/
			TxFrameType = TX_RALINK_FRAME;
		}
		else
		{
			TxFrameType = TX_LEGACY_FRAME;
		}
	}

	/* Currently, our fragment only support when a unicast packet send as NOT-ARALINK, NOT-AMSDU and NOT-AMPDU.*/
	if ((RTMP_GET_PACKET_FRAGMENTS(pPacket) > 1)
		 && (TxFrameType == TX_LEGACY_FRAME)
#ifdef DOT11_N_SUPPORT
		&& ((pMacEntry->TXBAbitmap & (1<<(RTMP_GET_PACKET_UP(pPacket)))) == 0)
#endif /* DOT11_N_SUPPORT */
		)
		TxFrameType = TX_FRAG_FRAME;

	return TxFrameType;
}


bool RTMP_FillTxBlkInfo(struct rtmp_adapter*pAd, TX_BLK *pTxBlk)
{
	PACKET_INFO PacketInfo;
	struct sk_buff * pPacket;
	MAC_TABLE_ENTRY *pMacEntry = NULL;

	pPacket = pTxBlk->pPacket;
	RTMP_QueryPacketInfo(pPacket, &PacketInfo, &pTxBlk->pSrcBufHeader, &pTxBlk->SrcBufLen);
#ifdef TX_PKT_SG
	memmove( &pTxBlk->pkt_info, &PacketInfo, sizeof(PacketInfo));
#endif /* TX_PKT_SG */
	pTxBlk->Wcid = RTMP_GET_PACKET_WCID(pPacket);
	pTxBlk->apidx = RTMP_GET_PACKET_IF(pPacket);
	pTxBlk->UserPriority = RTMP_GET_PACKET_UP(pPacket);
	pTxBlk->FrameGap = IFS_HTTXOP;

	if (RTMP_GET_PACKET_CLEAR_EAP_FRAME(pTxBlk->pPacket))
		TX_BLK_SET_FLAG(pTxBlk, fTX_bClearEAPFrame);
	else
		TX_BLK_CLEAR_FLAG(pTxBlk, fTX_bClearEAPFrame);

	/* Default to clear this flag*/
	TX_BLK_CLEAR_FLAG(pTxBlk, fTX_bForceNonQoS);


	if (pTxBlk->Wcid == MCAST_WCID)
	{
		pTxBlk->pMacEntry = NULL;
		{
#ifdef MCAST_RATE_SPECIFIC
			u8 *pDA = pPacket->data;
			if (((*pDA & 0x01) == 0x01) && (*pDA != 0xff))
				pTxBlk->pTransmit = &pAd->CommonCfg.MCastPhyMode;
			else
#endif /* MCAST_RATE_SPECIFIC */
				pTxBlk->pTransmit = &pAd->MacTab.Content[MCAST_WCID].HTPhyMode;
		}

		TX_BLK_CLEAR_FLAG(pTxBlk, fTX_bAckRequired);	/* AckRequired = false, when broadcast packet in Adhoc mode.*/
		TX_BLK_CLEAR_FLAG(pTxBlk, fTX_bAllowFrag);
		TX_BLK_CLEAR_FLAG(pTxBlk, fTX_bWMM);
		if (RTMP_GET_PACKET_MOREDATA(pPacket))
		{
			TX_BLK_SET_FLAG(pTxBlk, fTX_bMoreData);
		}
	}
	else
	{
		pTxBlk->pMacEntry = &pAd->MacTab.Content[pTxBlk->Wcid];
		pTxBlk->pTransmit = &pTxBlk->pMacEntry->HTPhyMode;

		pMacEntry = pTxBlk->pMacEntry;

		/* For all unicast packets, need Ack unless the Ack Policy is not set as NORMAL_ACK.*/
		if (pAd->CommonCfg.AckPolicy[pTxBlk->QueIdx] != NORMAL_ACK)
			TX_BLK_CLEAR_FLAG(pTxBlk, fTX_bAckRequired);
		else
			TX_BLK_SET_FLAG(pTxBlk, fTX_bAckRequired);

		{

#ifdef CONFIG_STA_SUPPORT
			IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
			{


				/* If support WMM, enable it.*/
				if (OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_WMM_INUSED) &&
					CLIENT_STATUS_TEST_FLAG(pMacEntry, fCLIENT_STATUS_WMM_CAPABLE))
					TX_BLK_SET_FLAG(pTxBlk, fTX_bWMM);
			}
#endif /* CONFIG_STA_SUPPORT */
		}

		if (pTxBlk->TxFrameType == TX_LEGACY_FRAME)
		{
			if ( (RTMP_GET_PACKET_LOWRATE(pPacket)) ||
				((pAd->OpMode == OPMODE_AP) && (pMacEntry->MaxHTPhyMode.field.MODE == MODE_CCK) && (pMacEntry->MaxHTPhyMode.field.MCS == RATE_1))
			)
			{	/* Specific packet, i.e., bDHCPFrame, bEAPOLFrame, bWAIFrame, need force low rate.*/
				pTxBlk->pTransmit = &pAd->MacTab.Content[MCAST_WCID].HTPhyMode;

#ifdef DOT11_N_SUPPORT
				/* Modify the WMM bit for ICV issue. If we have a packet with EOSP field need to set as 1, how to handle it? */
				if (IS_HT_STA(pTxBlk->pMacEntry) &&
					(CLIENT_STATUS_TEST_FLAG(pMacEntry, fCLIENT_STATUS_RALINK_CHIPSET)) &&
					((pAd->CommonCfg.bRdg == true) && CLIENT_STATUS_TEST_FLAG(pMacEntry, fCLIENT_STATUS_RDG_CAPABLE)))
				{
					TX_BLK_CLEAR_FLAG(pTxBlk, fTX_bWMM);
					TX_BLK_SET_FLAG(pTxBlk, fTX_bForceNonQoS);
				}
#endif /* DOT11_N_SUPPORT */
			}

#ifdef DOT11_N_SUPPORT
			if ( (IS_HT_RATE(pMacEntry) == false) &&
				(CLIENT_STATUS_TEST_FLAG(pMacEntry, fCLIENT_STATUS_PIGGYBACK_CAPABLE)))
			{	/* Currently piggy-back only support when peer is operate in b/g mode.*/
				TX_BLK_SET_FLAG(pTxBlk, fTX_bPiggyBack);
			}
#endif /* DOT11_N_SUPPORT */

			if (RTMP_GET_PACKET_MOREDATA(pPacket))
			{
				TX_BLK_SET_FLAG(pTxBlk, fTX_bMoreData);
			}
#ifdef UAPSD_SUPPORT
			if (RTMP_GET_PACKET_EOSP(pPacket))
			{
				TX_BLK_SET_FLAG(pTxBlk, fTX_bWMM_UAPSD_EOSP);
			}
#endif /* UAPSD_SUPPORT */
		}
		else if (pTxBlk->TxFrameType == TX_FRAG_FRAME)
		{
			TX_BLK_SET_FLAG(pTxBlk, fTX_bAllowFrag);
		}

		pMacEntry->DebugTxCount++;
	}


	pAd->LastTxRate = (USHORT)pTxBlk->pTransmit->word;

	return true;
}


bool CanDoAggregateTransmit(
	struct rtmp_adapter*pAd,
	struct sk_buff *pPacket,
	TX_BLK		*pTxBlk)
{
	int minLen = LENGTH_802_3;

	/*DBGPRINT(RT_DEBUG_TRACE, ("Check if can do aggregation! TxFrameType=%d!\n", pTxBlk->TxFrameType));*/

	if (RTMP_GET_PACKET_WCID(pPacket) == MCAST_WCID)
		return false;

	if (RTMP_GET_PACKET_DHCP(pPacket) ||
		RTMP_GET_PACKET_EAPOL(pPacket) ||
		RTMP_GET_PACKET_WAI(pPacket)
	)
		return false;

	/* Make sure the first packet has non-zero-length data payload */
	if (RTMP_GET_PACKET_VLAN(pPacket))
		minLen += LENGTH_802_1Q; /* VLAN tag */
	else if (RTMP_GET_PACKET_LLCSNAP(pPacket))
		minLen += 8; /* SNAP hdr Len*/
	if (minLen >= pPacket->len)
		return false;

	if ((pTxBlk->TxFrameType == TX_AMSDU_FRAME) &&
		((pTxBlk->TotalFrameLen + pPacket->len)> (RX_BUFFER_AGGRESIZE - 100)))
	{	/* For AMSDU, allow the packets with total length < max-amsdu size*/
		return false;
	}

	if ((pTxBlk->TxFrameType == TX_RALINK_FRAME) &&
		(pTxBlk->TxPacketList.Number == 2))
	{	/* For RALINK-Aggregation, allow two frames in one batch.*/
		return false;
	}

#ifdef CONFIG_STA_SUPPORT
	if ((INFRA_ON(pAd)) && (pAd->OpMode == OPMODE_STA)) /* must be unicast to AP*/
		return true;
	else
#endif /* CONFIG_STA_SUPPORT */
		return false;

}


/*
	========================================================================

	Routine Description:
		To do the enqueue operation and extract the first item of waiting
		list. If a number of available shared memory segments could meet
		the request of extracted item, the extracted item will be fragmented
		into shared memory segments.

	Arguments:
		pAd Pointer to our adapter
		pQueue		Pointer to Waiting Queue

	Return Value:
		None

	IRQL = DISPATCH_LEVEL

	Note:

	========================================================================
*/
void RTMPDeQueuePacket(
	struct rtmp_adapter*pAd,
	bool bIntContext,
	u8 QIdx,
	INT Max_Tx_Packets)
{
	PQUEUE_ENTRY pEntry = NULL;
	struct sk_buff * pPacket;
	int Status = NDIS_STATUS_SUCCESS;
	u8 Count=0;
	PQUEUE_HEADER   pQueue;
	ULONG FreeNumber[NUM_OF_TX_RING];
	u8 QueIdx, sQIdx, eQIdx;
	unsigned long	IrqFlags = 0;
	bool hasTxDesc = false;
	TX_BLK TxBlk, *pTxBlk;

#ifdef DBG_DIAGNOSE
	bool 		firstRound;
	RtmpDiagStruct	*pDiagStruct = &pAd->DiagStruct;
#endif


	if (QIdx == NUM_OF_TX_RING)
	{
		sQIdx = 0;
		eQIdx = 3;	/* 4 ACs, start from 0.*/
	}
	else
	{
		sQIdx = eQIdx = QIdx;
	}

	for (QueIdx=sQIdx; QueIdx <= eQIdx; QueIdx++)
	{
		Count=0;

		RTMP_START_DEQUEUE(pAd, QueIdx, IrqFlags);

#ifdef DBG_DIAGNOSE
		firstRound = ((QueIdx == 0) ? true : false);
#endif /* DBG_DIAGNOSE */

		while (1)
		{
			if ((RTMP_TEST_FLAG(pAd, (fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS |
										fRTMP_ADAPTER_RADIO_OFF |
										fRTMP_ADAPTER_RESET_IN_PROGRESS |
										fRTMP_ADAPTER_HALT_IN_PROGRESS |
										fRTMP_ADAPTER_NIC_NOT_EXIST)))
				)
			{
				RTMP_STOP_DEQUEUE(pAd, QueIdx, IrqFlags);
				return;
			}

			if (Count >= Max_Tx_Packets)
				break;

			DEQUEUE_LOCK(&pAd->irq_lock, bIntContext, IrqFlags);
			if (&pAd->TxSwQueue[QueIdx] == NULL)
			{
#ifdef DBG_DIAGNOSE
				if (firstRound == true)
					pDiagStruct->TxSWQueCnt[pDiagStruct->ArrayCurIdx][0]++;
#endif /* DBG_DIAGNOSE */
				DEQUEUE_UNLOCK(&pAd->irq_lock, bIntContext, IrqFlags);
				break;
			}


			/* probe the Queue Head*/
			pQueue = &pAd->TxSwQueue[QueIdx];
			if ((pEntry = pQueue->Head) == NULL)
			{
				DEQUEUE_UNLOCK(&pAd->irq_lock, bIntContext, IrqFlags);
				break;
			}

			pTxBlk = &TxBlk;
			memset((u8 *)pTxBlk, 0, sizeof(TX_BLK));

			pTxBlk->QueIdx = QueIdx;

			pTxBlk->HeaderBuf = (u8 *)pTxBlk->HeaderBuffer;

			pPacket = QUEUE_ENTRY_TO_PACKET(pEntry);


			/* Early check to make sure we have enoguh Tx Resource.*/
			hasTxDesc = RTMP_HAS_ENOUGH_FREE_DESC(pAd, pTxBlk, FreeNumber[QueIdx], pPacket);
			if (!hasTxDesc)
			{
				pAd->PrivateInfo.TxRingFullCnt++;

				DEQUEUE_UNLOCK(&pAd->irq_lock, bIntContext, IrqFlags);

				break;
			}

			pTxBlk->TxFrameType = TxPktClassification(pAd, pPacket);
			pEntry = RemoveHeadQueue(pQueue);
			pTxBlk->TotalFrameNum++;
			pTxBlk->TotalFragNum += RTMP_GET_PACKET_FRAGMENTS(pPacket);	/* The real fragment number maybe vary*/
			pTxBlk->TotalFrameLen += pPacket->len;
			pTxBlk->pPacket = pPacket;
			InsertTailQueue(&pTxBlk->TxPacketList, PACKET_TO_QUEUE_ENTRY(pPacket));

			if (pTxBlk->TxFrameType & (TX_RALINK_FRAME | TX_AMSDU_FRAME))
			{
				// Enhance SW Aggregation Mechanism
				if (NEED_QUEUE_BACK_FOR_AGG(pAd, QueIdx, FreeNumber[QueIdx], pTxBlk->TxFrameType))
				{
					InsertHeadQueue(pQueue, PACKET_TO_QUEUE_ENTRY(pPacket));
					DEQUEUE_UNLOCK(&pAd->irq_lock, bIntContext, IrqFlags);
					break;
				}
			}


			if (pTxBlk->TxFrameType == TX_RALINK_FRAME || pTxBlk->TxFrameType == TX_AMSDU_FRAME)
			{
				// Enhance SW Aggregation Mechanism
				if (NEED_QUEUE_BACK_FOR_AGG(pAd, QueIdx, FreeNumber[QueIdx], pTxBlk->TxFrameType))
				{
					InsertHeadQueue(pQueue, PACKET_TO_QUEUE_ENTRY(pPacket));
					DEQUEUE_UNLOCK(&pAd->irq_lock, bIntContext, IrqFlags);
					break;
				}

				do{
					if((pEntry = pQueue->Head) == NULL)
						break;

					/* For TX_AMSDU_FRAME/TX_RALINK_FRAME, Need to check if next pakcet can do aggregation.*/
					pPacket = QUEUE_ENTRY_TO_PACKET(pEntry);
					FreeNumber[QueIdx] = GET_TXRING_FREENO(pAd, QueIdx);
					hasTxDesc = RTMP_HAS_ENOUGH_FREE_DESC(pAd, pTxBlk, FreeNumber[QueIdx], pPacket);
					if ((hasTxDesc == false) || (CanDoAggregateTransmit(pAd, pPacket, pTxBlk) == false))
						break;

					/*Remove the packet from the TxSwQueue and insert into pTxBlk*/
					pEntry = RemoveHeadQueue(pQueue);
					ASSERT(pEntry);
					pPacket = QUEUE_ENTRY_TO_PACKET(pEntry);


					pTxBlk->TotalFrameNum++;
					pTxBlk->TotalFragNum += RTMP_GET_PACKET_FRAGMENTS(pPacket);	/* The real fragment number maybe vary*/
					pTxBlk->TotalFrameLen += pPacket->len;
					InsertTailQueue(&pTxBlk->TxPacketList, PACKET_TO_QUEUE_ENTRY(pPacket));
				}while(1);

				if (pTxBlk->TxPacketList.Number == 1)
					pTxBlk->TxFrameType = TX_LEGACY_FRAME;
			}

#ifdef RTMP_MAC_USB
			DEQUEUE_UNLOCK(&pAd->irq_lock, bIntContext, IrqFlags);
#endif /* RTMP_MAC_USB */

			Count += pTxBlk->TxPacketList.Number;

				/* Do HardTransmit now.*/
#ifdef CONFIG_STA_SUPPORT
			IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
			{
				Status = STAHardTransmit(pAd, pTxBlk, QueIdx);
			}
#endif /* CONFIG_STA_SUPPORT */


		}

		RTMP_STOP_DEQUEUE(pAd, QueIdx, IrqFlags);

#ifdef RTMP_MAC_USB
		if (!hasTxDesc)
			RTUSBKickBulkOut(pAd);
#endif /* RTMP_MAC_USB */

#ifdef BLOCK_NET_IF
		if ((pAd->blockQueueTab[QueIdx].SwTxQueueBlockFlag == true)
			&& (pAd->TxSwQueue[QueIdx].Number < 1))
		{
			releaseNetIf(&pAd->blockQueueTab[QueIdx]);
		}
#endif /* BLOCK_NET_IF */

	}

}


/*
	========================================================================

	Routine Description:
		Calculates the duration which is required to transmit out frames
	with given size and specified rate.

	Arguments:
		pAd 	Pointer to our adapter
		Rate			Transmit rate
		Size			Frame size in units of byte

	Return Value:
		Duration number in units of usec

	IRQL = PASSIVE_LEVEL
	IRQL = DISPATCH_LEVEL

	Note:

	========================================================================
*/
USHORT	RTMPCalcDuration(
	struct rtmp_adapter *pAd,
	u8 		Rate,
	ULONG			Size)
{
	ULONG	Duration = 0;

	if (Rate < RATE_FIRST_OFDM_RATE) /* CCK*/
	{
		if ((Rate > RATE_1) && OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_SHORT_PREAMBLE_INUSED))
			Duration = 96;	/* 72+24 preamble+plcp*/
		else
			Duration = 192; /* 144+48 preamble+plcp*/

		Duration += (USHORT)((Size << 4) / RateIdTo500Kbps[Rate]);
		if ((Size << 4) % RateIdTo500Kbps[Rate])
			Duration ++;
	}
	else if (Rate <= RATE_LAST_OFDM_RATE)/* OFDM rates*/
	{
		Duration = 20 + 6;		/* 16+4 preamble+plcp + Signal Extension*/
		Duration += 4 * (USHORT)((11 + Size * 4) / RateIdTo500Kbps[Rate]);
		if ((11 + Size * 4) % RateIdTo500Kbps[Rate])
			Duration += 4;
	}
	else	/*mimo rate*/
	{
		Duration = 20 + 6;		/* 16+4 preamble+plcp + Signal Extension*/
	}

	return (USHORT)Duration;
}


/*
	========================================================================

	Routine Description:
		Suspend MSDU transmission

	Arguments:
		pAd 	Pointer to our adapter

	Return Value:
		None

	Note:

	========================================================================
*/
void RTMPSuspendMsduTransmission(
	struct rtmp_adapter *pAd)
{
	DBGPRINT(RT_DEBUG_TRACE,("SCANNING, suspend MSDU transmission ...\n"));


	/*
		Before BSS_SCAN_IN_PROGRESS, we need to keep Current R66 value and
		use Lowbound as R66 value on ScanNextChannel(...)
	*/
	rtmp_bbp_get_agc(pAd, &pAd->BbpTuning.R66CurrentValue, RX_CHAIN_0);

	//printk("pAd->CommonCfg.BBPCurrentBW = %d\n", pAd->CommonCfg.BBPCurrentBW);
	pAd->hw_cfg.bbp_bw = pAd->CommonCfg.BBPCurrentBW;

	RTMP_SET_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS);
	/* abort all TX rings */
	/*mt7610u_write32(pAd, TX_CNTL_CSR, 0x000f0000);	*/
}


/*
	========================================================================

	Routine Description:
		Resume MSDU transmission

	Arguments:
		pAd 	Pointer to our adapter

	Return Value:
		None

	IRQL = DISPATCH_LEVEL

	Note:

	========================================================================
*/
void RTMPResumeMsduTransmission(
	struct rtmp_adapter *pAd)
{
	DBGPRINT(RT_DEBUG_TRACE,("SCAN done, resume MSDU transmission ...\n"));


	/*
		After finish BSS_SCAN_IN_PROGRESS, we need to restore Current R66 value
		R66 should not be 0
	*/
	if (pAd->BbpTuning.R66CurrentValue == 0)
	{
		pAd->BbpTuning.R66CurrentValue = 0x38;
		DBGPRINT_ERR(("RTMPResumeMsduTransmission, R66CurrentValue=0...\n"));
	}
	rtmp_bbp_set_agc(pAd, pAd->BbpTuning.R66CurrentValue, RX_CHAIN_ALL);

	pAd->CommonCfg.BBPCurrentBW = pAd->hw_cfg.bbp_bw;

	RTMP_CLEAR_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS);
/* sample, for IRQ LOCK to SEM LOCK */
/*
	IrqState = pAd->irq_disabled;
	if (IrqState)
		RTMPDeQueuePacket(pAd, true, NUM_OF_TX_RING, MAX_TX_PROCESS);
	else
*/
	RTMPDeQueuePacket(pAd, false, NUM_OF_TX_RING, MAX_TX_PROCESS);
}


#ifdef DOT11_N_SUPPORT
UINT deaggregate_AMSDU_announce(
	struct rtmp_adapter *pAd,
	struct sk_buff *		pPacket,
	u8 *		pData,
	ULONG			DataSize,
	u8 		OpMode)
{
	USHORT 			PayloadSize;
	USHORT 			SubFrameSize;
	PHEADER_802_3 	pAMSDUsubheader;
	UINT			nMSDU;
    u8 		Header802_3[14];

	u8 *pPayload, *pDA, *pSA, *pRemovedLLCSNAP;
	struct sk_buff *	pClonePacket;


	nMSDU = 0;

	while (DataSize > LENGTH_802_3)
	{

		nMSDU++;

		pAMSDUsubheader = (PHEADER_802_3)pData;
		/*pData += LENGTH_802_3;*/
		PayloadSize = pAMSDUsubheader->Octet[1] + (pAMSDUsubheader->Octet[0]<<8);
		SubFrameSize = PayloadSize + LENGTH_802_3;


		if ((DataSize < SubFrameSize) || (PayloadSize > 1518 ))
		{
			break;
		}

		/*DBGPRINT(RT_DEBUG_TRACE,("%d subframe: Size = %d\n",  nMSDU, PayloadSize));*/

		pPayload = pData + LENGTH_802_3;
		pDA = pData;
		pSA = pData + ETH_ALEN;

		/* convert to 802.3 header*/
        CONVERT_TO_802_3(Header802_3, pDA, pSA, pPayload, PayloadSize, pRemovedLLCSNAP);

#ifdef CONFIG_STA_SUPPORT
		if ((Header802_3[12] == 0x88) && (Header802_3[13] == 0x8E))
		{
			/* avoid local heap overflow, use dyanamic allocation */
			MLME_QUEUE_ELEM *Elem; /* = (MLME_QUEUE_ELEM *) kmalloc(sizeof(MLME_QUEUE_ELEM), MEM_ALLOC_FLAG);*/

			Elem = kmalloc(sizeof(MLME_QUEUE_ELEM), GFP_ATOMIC);
			if (Elem != NULL) {
				memmove(Elem->Msg+(LENGTH_802_11 + LENGTH_802_1_H), pPayload, PayloadSize);
				Elem->MsgLen = LENGTH_802_11 + LENGTH_802_1_H + PayloadSize;
				/*WpaEAPOLKeyAction(pAd, Elem);*/
				REPORT_MGMT_FRAME_TO_MLME(pAd, BSSID_WCID, Elem->Msg, Elem->MsgLen, 0, 0, 0, 0, OPMODE_STA);
/*				kfree(Elem);*/
				kfree(Elem);
			}
		}
#endif /* CONFIG_STA_SUPPORT */

#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
	        	if (pRemovedLLCSNAP)
	        	{
	    			pPayload -= LENGTH_802_3;
	    			PayloadSize += LENGTH_802_3;
	    			memmove(pPayload, &Header802_3[0], LENGTH_802_3);
	        	}
		}
#endif /* CONFIG_STA_SUPPORT */

		pClonePacket = ClonePacket(pAd, pPacket, pPayload, PayloadSize);
		if (pClonePacket)
		{
#ifdef CONFIG_STA_SUPPORT
			IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
				ANNOUNCE_OR_FORWARD_802_3_PACKET(pAd, pClonePacket, RTMP_GET_PACKET_IF(pPacket));
#endif /* CONFIG_STA_SUPPORT */
		}


		/* A-MSDU has padding to multiple of 4 including subframe header.*/
		/* align SubFrameSize up to multiple of 4*/
		SubFrameSize = (SubFrameSize+3)&(~0x3);


		if (SubFrameSize > 1528 || SubFrameSize < 32)
		{
			break;
		}

		if (DataSize > SubFrameSize)
		{
			pData += SubFrameSize;
			DataSize -= SubFrameSize;
		}
		else
		{
			/* end of A-MSDU*/
			DataSize = 0;
		}
	}

	/* finally release original rx packet*/
	RTMPFreeNdisPacket(pAd, pPacket);

	return nMSDU;
}


UINT BA_Reorder_AMSDU_Annnounce(
	struct rtmp_adapter *pAd,
	struct sk_buff *	pPacket,
	u8 		OpMode)
{
	u8 *		pData;
	USHORT			DataSize;
	UINT			nMSDU = 0;

	pData = pPacket->data;
	DataSize = pPacket->len;

	nMSDU = deaggregate_AMSDU_announce(pAd, pPacket, pData, DataSize, OpMode);

	return nMSDU;
}

void Indicate_AMSDU_Packet(
	struct rtmp_adapter *pAd,
	RX_BLK			*pRxBlk,
	u8 		FromWhichBSSID)
{
	UINT			nMSDU;

	RTMP_UPDATE_OS_PACKET_INFO(pAd, pRxBlk, FromWhichBSSID);
	RTMP_SET_PACKET_IF(pRxBlk->pRxPacket, FromWhichBSSID);
	nMSDU = deaggregate_AMSDU_announce(pAd, pRxBlk->pRxPacket, pRxBlk->pData, pRxBlk->DataSize, pRxBlk->OpMode);
}
#endif /* DOT11_N_SUPPORT */


/*
	==========================================================================
	Description:

	IRQL = DISPATCH_LEVEL

	==========================================================================
*/
void AssocParmFill(
	struct rtmp_adapter *pAd,
	MLME_ASSOC_REQ_STRUCT *AssocReq,
	u8 *                    pAddr,
	USHORT                     CapabilityInfo,
	ULONG                      Timeout,
	USHORT                     ListenIntv)
{
	memcpy(AssocReq->Addr, pAddr, ETH_ALEN);
	/* Add mask to support 802.11b mode only */
	AssocReq->CapabilityInfo = CapabilityInfo & SUPPORTED_CAPABILITY_INFO; /* not cf-pollable, not cf-poll-request*/
	AssocReq->Timeout = Timeout;
	AssocReq->ListenIntv = ListenIntv;
}


/*
	==========================================================================
	Description:

	IRQL = DISPATCH_LEVEL

	==========================================================================
*/
void DisassocParmFill(
	struct rtmp_adapter *pAd,
	MLME_DISASSOC_REQ_STRUCT *DisassocReq,
	u8 *pAddr,
	USHORT Reason)
{
	memcpy(DisassocReq->Addr, pAddr, ETH_ALEN);
	DisassocReq->Reason = Reason;
}


bool RTMPCheckEtherType(
	struct rtmp_adapter *pAd,
	struct sk_buff *	pPacket,
	PMAC_TABLE_ENTRY pMacEntry,
	u8 		OpMode,
	u8 *pUserPriority,
	u8 *pQueIdx)
{
	USHORT	TypeLen;
	u8 Byte0, Byte1;
	u8 *pSrcBuf;
	u32	pktLen;
	uint16_t 	srcPort, dstPort;
	bool bWmmReq;


	/*
		for bc/mc packets, if it has VLAN tag or DSCP field, we also need
		to get UP for IGMP use.
	*/
	bWmmReq = (
				OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_WMM_INUSED))
				&& ((pMacEntry) &&
					((VALID_WCID(pMacEntry->Aid) && CLIENT_STATUS_TEST_FLAG(pMacEntry, fCLIENT_STATUS_WMM_CAPABLE))
						|| (pMacEntry->Aid == MCAST_WCID)));

	pSrcBuf = pPacket->data;;
	pktLen = pPacket->len;

	ASSERT(pSrcBuf);

	RTMP_SET_PACKET_SPECIFIC(pPacket, 0);

	/* get Ethernet protocol field*/
	TypeLen = (pSrcBuf[12] << 8) | pSrcBuf[13];

	pSrcBuf += LENGTH_802_3;	/* Skip the Ethernet Header.*/

	if (TypeLen <= 1500)
	{	/* 802.3, 802.3 LLC*/
		/*
			DestMAC(6) + SrcMAC(6) + Lenght(2) +
			DSAP(1) + SSAP(1) + Control(1) +
			if the DSAP = 0xAA, SSAP=0xAA, Contorl = 0x03, it has a 5-bytes SNAP header.
				=> + SNAP (5, OriginationID(3) + etherType(2))
		*/
		if (pSrcBuf[0] == 0xAA && pSrcBuf[1] == 0xAA && pSrcBuf[2] == 0x03)
		{
			Sniff2BytesFromNdisBuffer((PNDIS_BUFFER)pSrcBuf, 6, &Byte0, &Byte1);
			RTMP_SET_PACKET_LLCSNAP(pPacket, 1);
			TypeLen = (USHORT)((Byte0 << 8) + Byte1);
			pSrcBuf += 8; /* Skip this LLC/SNAP header*/
		}
		else
		{
			/*It just has 3-byte LLC header, maybe a legacy ether type frame. we didn't handle it.*/
		}
	}

	/* If it's a VLAN packet, get the real Type/Length field.*/
	if (TypeLen == 0x8100)
	{

		RTMP_SET_PACKET_VLAN(pPacket, 1);
		Sniff2BytesFromNdisBuffer((PNDIS_BUFFER)pSrcBuf, 2, &Byte0, &Byte1);
		TypeLen = (USHORT)((Byte0 << 8) + Byte1);

		/* only use VLAN tag */
		if (bWmmReq)
		{
			*pUserPriority = (*pSrcBuf & 0xe0) >> 5;
			*pQueIdx = MapUserPriorityToAccessCategory[*pUserPriority];
		}

		pSrcBuf += 4; /* Skip the VLAN Header.*/
	}
	else if (TypeLen == 0x0800)
	{
		if (bWmmReq)
		{
			if ((*pSrcBuf & 0xf0) == 0x40) /* IPv4 */
			{
				/*
					Version - 4-bit Internet Protocol version number.
					Length - 4-bit IP header length.
					Traffic Class - 8-bit TOS field.
				*/
				*pUserPriority = (*(pSrcBuf + 1) & 0xe0) >> 5;
			}

			*pQueIdx = MapUserPriorityToAccessCategory[*pUserPriority];
		}
	}
	else if (TypeLen == 0x86dd)
	{
		if (bWmmReq)
		{
			if ((*pSrcBuf & 0xf0) == 0x60) /* IPv6 */
			{
				/*
					Version - 4-bit Internet Protocol version number.
					Traffic Class - 8-bit traffic class field.
				*/
				*pUserPriority = ((*pSrcBuf) & 0x0e) >> 1;
			}

			*pQueIdx = MapUserPriorityToAccessCategory[*pUserPriority];
		}
	}

	switch (TypeLen)
	{
		case 0x0800:
			{
				/* return AC_BE if packet is not IPv4*/
				if (bWmmReq && (*pSrcBuf & 0xf0) != 0x40)
				{
					*pUserPriority = 0;
					*pQueIdx = QID_AC_BE;
				}
				else
					RTMP_SET_PACKET_IPV4(pPacket, 1);

				ASSERT((pktLen > 34));
				if (*(pSrcBuf + 9) == 0x11)
				{	/* udp packet*/
					ASSERT((pktLen > 34));	/* 14 for ethernet header, 20 for IP header*/

					pSrcBuf += 20;	/* Skip the IP header*/
					srcPort = OS_NTOHS(get_unaligned((uint16_t *)(pSrcBuf)));
					dstPort = OS_NTOHS(get_unaligned((uint16_t *)(pSrcBuf+2)));

					if ((srcPort==0x44 && dstPort==0x43) || (srcPort==0x43 && dstPort==0x44))
					{	/*It's a BOOTP/DHCP packet*/
						RTMP_SET_PACKET_DHCP(pPacket, 1);
					}
				}
			}
			break;
		case 0x86dd:
			{
				/* return AC_BE if packet is not IPv6 */
				if (bWmmReq &&
					((*pSrcBuf & 0xf0) != 0x60))
				{
					*pUserPriority = 0;
					*pQueIdx = QID_AC_BE;
				}
			}
			break;
		case 0x0806:
			{
				/*ARP Packet.*/
				RTMP_SET_PACKET_DHCP(pPacket, 1);
			}
			break;
		case 0x888e:
			{
				/* EAPOL Packet.*/
				RTMP_SET_PACKET_EAPOL(pPacket, 1);
			}
			break;


		default:
			break;
	}

	RTMP_SET_PACKET_PROTOCOL(pPacket, TypeLen);

	/* have to check ACM bit. downgrade UP & QueIdx before passing ACM*/
	/* NOTE: AP doesn't have to negotiate TSPEC. ACM is controlled purely via user setup, not protocol handshaking*/
	/*
		Under WMM ACM control, we dont need to check the bit;
		Or when a TSPEC is built for VO but we will change priority to
		BE here and when we issue a BA session, the BA session will
		be BE session, not VO session.
	*/
	if (pAd->CommonCfg.APEdcaParm.bACM[*pQueIdx])
	{
		*pUserPriority = 0;
		*pQueIdx		 = QID_AC_BE;
	}


	return true;

}


void Update_Rssi_Sample(
	struct rtmp_adapter*pAd,
	RSSI_SAMPLE *pRssi,
	struct rxwi_nmac *pRxWI)
{
	CHAR rssi[3];
	u8 snr[3];
	bool bInitial = false;
	CHAR Phymode = get_pkt_phymode_by_rxwi(pRxWI);


	if (!(pRssi->AvgRssi0 | pRssi->AvgRssi0X8 | pRssi->LastRssi0))
		bInitial = true;

	get_pkt_rssi_by_rxwi(pRxWI, 3, &rssi[0]);
	get_pkt_snr_by_rxwi(pRxWI, 3, &snr[0]);
	if (rssi[0] != 0)
	{
		pRssi->LastRssi0 = ConvertToRssi(pAd, (CHAR)rssi[0], RSSI_0);
		if (bInitial)
		{
			pRssi->AvgRssi0X8 = pRssi->LastRssi0 << 3;
			pRssi->AvgRssi0  = pRssi->LastRssi0;
		}
		else
			pRssi->AvgRssi0X8 = (pRssi->AvgRssi0X8 - pRssi->AvgRssi0) + pRssi->LastRssi0;

		pRssi->AvgRssi0 = pRssi->AvgRssi0X8 >> 3;
	}

	if (snr[0] != 0 && Phymode != MODE_CCK)
	{
		pRssi->LastSnr0 = ConvertToSnr(pAd, (u8)snr[0]);
		if (bInitial)
		{
			pRssi->AvgSnr0X8 = pRssi->LastSnr0 << 3;
			pRssi->AvgSnr0  = pRssi->LastSnr0;
		}
		else
			pRssi->AvgSnr0X8 = (pRssi->AvgSnr0X8 - pRssi->AvgSnr0) + pRssi->LastSnr0;

		pRssi->AvgSnr0 = pRssi->AvgSnr0X8 >> 3;
	}

	if (rssi[1] != 0)
	{
		pRssi->LastRssi1 = ConvertToRssi(pAd, (CHAR)rssi[1], RSSI_1);
		if (bInitial)
		{
			pRssi->AvgRssi1X8 = pRssi->LastRssi1 << 3;
			pRssi->AvgRssi1  = pRssi->LastRssi1;
		}
		else
			pRssi->AvgRssi1X8 = (pRssi->AvgRssi1X8 - pRssi->AvgRssi1) + pRssi->LastRssi1;

		pRssi->AvgRssi1 = pRssi->AvgRssi1X8 >> 3;
	}

	if (snr[1] != 0 && Phymode != MODE_CCK)
	{
		pRssi->LastSnr1 = ConvertToSnr(pAd, (u8)snr[1]);
		if (bInitial)
		{
			pRssi->AvgSnr1X8 = pRssi->LastSnr1 << 3;
			pRssi->AvgSnr1  = pRssi->LastSnr1;
		}
		else
			pRssi->AvgSnr1X8 = (pRssi->AvgSnr1X8 - pRssi->AvgSnr1) + pRssi->LastSnr1;

		pRssi->AvgSnr1 = pRssi->AvgSnr1X8 >> 3;
	}

	if (rssi[2] != 0)
	{
		pRssi->LastRssi2 = ConvertToRssi(pAd, (CHAR)rssi[2], RSSI_2);

		if (bInitial)
		{
			pRssi->AvgRssi2X8 = pRssi->LastRssi2 << 3;
			pRssi->AvgRssi2  = pRssi->LastRssi2;
		}
		else
			pRssi->AvgRssi2X8 = (pRssi->AvgRssi2X8 - pRssi->AvgRssi2) + pRssi->LastRssi2;

		pRssi->AvgRssi2 = pRssi->AvgRssi2X8 >> 3;
	}
}



/* Normal legacy Rx packet indication*/
void Indicate_Legacy_Packet(
	struct rtmp_adapter*pAd,
	RX_BLK *pRxBlk,
	u8 FromWhichBSSID)
{
	struct sk_buff * pRxPacket = pRxBlk->pRxPacket;
	u8 Header802_3[LENGTH_802_3];
	USHORT VLAN_VID = 0, VLAN_Priority = 0;



	/*
		1. get 802.3 Header
		2. remove LLC
			a. pointer pRxBlk->pData to payload
			b. modify pRxBlk->DataSize
	*/
#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		RTMP_802_11_REMOVE_LLC_AND_CONVERT_TO_802_3(pRxBlk, Header802_3);
#endif /* CONFIG_STA_SUPPORT */

	if (pRxBlk->DataSize > MAX_RX_PKT_LEN)
	{

		/* release packet*/
		RTMPFreeNdisPacket(pAd, pRxPacket);
		return;
	}

	STATS_INC_RX_PACKETS(pAd, FromWhichBSSID);

#ifdef RTMP_MAC_USB
#ifdef DOT11_N_SUPPORT
	if (pAd->CommonCfg.bDisableReordering == 0)
	{
		PBA_REC_ENTRY		pBAEntry;
		ULONG				Now32;
		u8 			Wcid = pRxBlk->pRxWI->RxWIWirelessCliID;
		u8 			TID = pRxBlk->pRxWI->RxWITID;
		USHORT				Idx;

#define REORDERING_PACKET_TIMEOUT		((100 * OS_HZ)/1000)	/* system ticks -- 100 ms*/

		if (Wcid < MAX_LEN_OF_MAC_TABLE)
		{
			Idx = pAd->MacTab.Content[Wcid].BARecWcidArray[TID];
			if (Idx != 0)
			{
				pBAEntry = &pAd->BATable.BARecEntry[Idx];
				/* update last rx time*/
				NdisGetSystemUpTime(&Now32);
				if ((pBAEntry->list.qlen > 0) &&
					 RTMP_TIME_AFTER((unsigned long)Now32, (unsigned long)(pBAEntry->LastIndSeqAtTimer+(REORDERING_PACKET_TIMEOUT)))
	   				)
				{
					DBGPRINT(RT_DEBUG_OFF, ("Indicate_Legacy_Packet():flush reordering_timeout_mpdus! RxWI->Flags=%d, pRxWI.TID=%d, RxD->AMPDU=%d!\n",
												pRxBlk->Flags, pRxBlk->pRxWI->RxWITID, pRxBlk->pRxInfo->AMPDU));
					ba_flush_reordering_timeout_mpdus(pAd, pBAEntry, Now32);
				}
			}
		}
	}
#endif /* DOT11_N_SUPPORT */
#endif /* RTMP_MAC_USB */

	RT_80211_TO_8023_PACKET(pAd, VLAN_VID, VLAN_Priority,
							pRxBlk, Header802_3, FromWhichBSSID, TPID);

	/* pass this 802.3 packet to upper layer or forward this packet to WM directly*/

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		ANNOUNCE_OR_FORWARD_802_3_PACKET(pAd, pRxPacket, FromWhichBSSID);
#endif /* CONFIG_STA_SUPPORT */

}


/* Normal, AMPDU or AMSDU*/
void CmmRxnonRalinkFrameIndicate(
	struct rtmp_adapter *pAd,
	RX_BLK			*pRxBlk,
	u8 		FromWhichBSSID)
{
#ifdef DOT11_N_SUPPORT
	if (RX_BLK_TEST_FLAG(pRxBlk, fRX_AMPDU) && (pAd->CommonCfg.bDisableReordering == 0))
	{
		Indicate_AMPDU_Packet(pAd, pRxBlk, FromWhichBSSID);
	}
	else
#endif /* DOT11_N_SUPPORT */
	{
#ifdef DOT11_N_SUPPORT
		if (RX_BLK_TEST_FLAG(pRxBlk, fRX_AMSDU))
		{
			/* handle A-MSDU*/
			Indicate_AMSDU_Packet(pAd, pRxBlk, FromWhichBSSID);
		}
		else
#endif /* DOT11_N_SUPPORT */
		{
			Indicate_Legacy_Packet(pAd, pRxBlk, FromWhichBSSID);
		}
	}
}

void CmmRxRalinkFrameIndicate(
	struct rtmp_adapter *pAd,
	MAC_TABLE_ENTRY	*pEntry,
	RX_BLK			*pRxBlk,
	u8 		FromWhichBSSID)
{
	u8 		Header802_3[LENGTH_802_3];
	uint16_t			Msdu2Size;
	uint16_t 			Payload1Size, Payload2Size;
	u8 *			pData2;
	struct sk_buff *	pPacket2 = NULL;
	USHORT			VLAN_VID = 0, VLAN_Priority = 0;


	Msdu2Size = *(pRxBlk->pData) + (*(pRxBlk->pData+1) << 8);

	if ((Msdu2Size <= 1536) && (Msdu2Size < pRxBlk->DataSize))
	{
		/* skip two byte MSDU2 len */
		pRxBlk->pData += 2;
		pRxBlk->DataSize -= 2;
	}
	else
	{
		/* release packet*/
		RTMPFreeNdisPacket(pAd, pRxBlk->pRxPacket);
		return;
	}

	/* get 802.3 Header and  remove LLC*/
#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		RTMP_802_11_REMOVE_LLC_AND_CONVERT_TO_802_3(pRxBlk, Header802_3);
#endif /* CONFIG_STA_SUPPORT */


	ASSERT(pRxBlk->pRxPacket);

	/* Ralink Aggregation frame*/
	pAd->RalinkCounters.OneSecRxAggregationCount ++;
	Payload1Size = pRxBlk->DataSize - Msdu2Size;
	Payload2Size = Msdu2Size - LENGTH_802_3;

	pData2 = pRxBlk->pData + Payload1Size + LENGTH_802_3;
#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		pPacket2 = duplicate_pkt(get_netdev_from_bssid(pAd, FromWhichBSSID),
								(pData2-LENGTH_802_3), LENGTH_802_3, pData2,
								Payload2Size, FromWhichBSSID);
#endif /* CONFIG_STA_SUPPORT */

	if (!pPacket2)
	{
		/* release packet*/
		RTMPFreeNdisPacket(pAd, pRxBlk->pRxPacket);
		return;
	}

	/* update payload size of 1st packet*/
	pRxBlk->DataSize = Payload1Size;

	RT_80211_TO_8023_PACKET(pAd, VLAN_VID, VLAN_Priority,
							pRxBlk, Header802_3, FromWhichBSSID, TPID);

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		ANNOUNCE_OR_FORWARD_802_3_PACKET(pAd, pRxBlk->pRxPacket, FromWhichBSSID);
#endif /* CONFIG_STA_SUPPORT */

	if (pPacket2)
	{
#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
			ANNOUNCE_OR_FORWARD_802_3_PACKET(pAd, pPacket2, FromWhichBSSID);
#endif /* CONFIG_STA_SUPPORT */
	}
}


#define RESET_FRAGFRAME(_fragFrame) \
	{								\
		_fragFrame.RxSize = 0;		\
		_fragFrame.Sequence = 0;	\
		_fragFrame.LastFrag = 0;	\
		_fragFrame.Flags = 0;		\
	}


struct sk_buff * RTMPDeFragmentDataFrame(
	struct rtmp_adapter*pAd,
	RX_BLK *pRxBlk)
{
	HEADER_802_11 *pHeader = pRxBlk->pHeader;
	struct sk_buff * pRxPacket = pRxBlk->pRxPacket;
	u8 *pData = pRxBlk->pData;
	USHORT DataSize = pRxBlk->DataSize;
	struct sk_buff * pRetPacket = NULL;
	u8 *pFragBuffer = NULL;
	bool bReassDone = false;
	u8 HeaderRoom = 0;


	ASSERT(pHeader);

	HeaderRoom = pData - (u8 *)pHeader;

	/* Re-assemble the fragmented packets*/
	if (pHeader->Frag == 0)		/* Frag. Number is 0 : First frag or only one pkt*/
	{
		/* the first pkt of fragment, record it.*/
		if (pHeader->FC.MoreFrag)
		{
			ASSERT(pAd->FragFrame.pFragPacket);
			pFragBuffer = (pAd->FragFrame.pFragPacket)->data;
			pAd->FragFrame.RxSize   = DataSize + HeaderRoom;
			memmove(pFragBuffer,	 pHeader, pAd->FragFrame.RxSize);
			pAd->FragFrame.Sequence = pHeader->Sequence;
			pAd->FragFrame.LastFrag = pHeader->Frag;	   /* Should be 0*/
			ASSERT(pAd->FragFrame.LastFrag == 0);
			goto done;	/* end of processing this frame*/
		}
	}
	else	/*Middle & End of fragment*/
	{
		if ((pHeader->Sequence != pAd->FragFrame.Sequence) ||
			(pHeader->Frag != (pAd->FragFrame.LastFrag + 1)))
		{
			/* Fragment is not the same sequence or out of fragment number order*/
			/* Reset Fragment control blk*/
			RESET_FRAGFRAME(pAd->FragFrame);
			DBGPRINT(RT_DEBUG_ERROR, ("Fragment is not the same sequence or out of fragment number order.\n"));
			goto done; /* give up this frame*/
		}
		else if ((pAd->FragFrame.RxSize + DataSize) > MAX_FRAME_SIZE)
		{
			/* Fragment frame is too large, it exeeds the maximum frame size.*/
			/* Reset Fragment control blk*/
			RESET_FRAGFRAME(pAd->FragFrame);
			DBGPRINT(RT_DEBUG_ERROR, ("Fragment frame is too large, it exeeds the maximum frame size.\n"));
			goto done; /* give up this frame*/
		}


		/* Broadcom AP(BCM94704AGR) will send out LLC in fragment's packet, LLC only can accpet at first fragment.*/
		/* In this case, we will dropt it.*/

		if (memcmp(pData, SNAP_802_1H, sizeof(SNAP_802_1H)) == 0)
		{
			DBGPRINT(RT_DEBUG_ERROR, ("Find another LLC at Middle or End fragment(SN=%d, Frag=%d)\n", pHeader->Sequence, pHeader->Frag));
			goto done; /* give up this frame*/
		}

		pFragBuffer = (pAd->FragFrame.pFragPacket)->data;

		/* concatenate this fragment into the re-assembly buffer*/
		memmove((pFragBuffer + pAd->FragFrame.RxSize), pData, DataSize);
		pAd->FragFrame.RxSize  += DataSize;
		pAd->FragFrame.LastFrag = pHeader->Frag;	   /* Update fragment number*/

		/* Last fragment*/
		if (pHeader->FC.MoreFrag == false)
		{
			bReassDone = true;
		}
	}

done:
	/* always release rx fragmented packet*/
	RTMPFreeNdisPacket(pAd, pRxPacket);

	/* return defragmented packet if packet is reassembled completely*/
	/* otherwise return NULL*/
	if (bReassDone)
	{
		struct sk_buff * pNewFragPacket;

		/* allocate a new packet buffer for fragment*/
		pNewFragPacket = dev_alloc_skb(RX_BUFFER_NORMSIZE);
		if (pNewFragPacket)
		{
			/* update RxBlk*/
			pRetPacket = pAd->FragFrame.pFragPacket;
			pAd->FragFrame.pFragPacket = pNewFragPacket;
			pRxBlk->pHeader = (PHEADER_802_11) pRetPacket->data;
			pRxBlk->pData = (u8 *)pRxBlk->pHeader + HeaderRoom;
			pRxBlk->DataSize = pAd->FragFrame.RxSize - HeaderRoom;
			pRxBlk->pRxPacket = pRetPacket;
		}
		else
		{
			RESET_FRAGFRAME(pAd->FragFrame);
		}
	}

	return pRetPacket;
}


void Indicate_EAPOL_Packet(
	struct rtmp_adapter*pAd,
	RX_BLK *pRxBlk,
	u8 FromWhichBSSID)
{
	MAC_TABLE_ENTRY *pEntry = NULL;

	if (pRxBlk->pRxWI->RxWIWirelessCliID >= MAX_LEN_OF_MAC_TABLE)
	{
		DBGPRINT(RT_DEBUG_WARN, ("Indicate_EAPOL_Packet: invalid wcid.\n"));
		RTMPFreeNdisPacket(pAd, pRxBlk->pRxPacket);
		return;
	}

	pEntry = &pAd->MacTab.Content[pRxBlk->pRxWI->RxWIWirelessCliID];
	if (pEntry == NULL)
	{
		DBGPRINT(RT_DEBUG_WARN, ("Indicate_EAPOL_Packet: drop and release the invalid packet.\n"));
		RTMPFreeNdisPacket(pAd, pRxBlk->pRxPacket);
		return;
	}


#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		{
			ASSERT((pRxBlk->pRxWI->RxWIWirelessCliID == BSSID_WCID));
			STARxEAPOLFrameIndicate(pAd, pEntry, pRxBlk, FromWhichBSSID);
			return;
	}
	}
#endif /* CONFIG_STA_SUPPORT */

}


#define BCN_TBTT_OFFSET		64	/*defer 64 us*/
void ReSyncBeaconTime(
	struct rtmp_adapter*pAd)
{
	u32  Offset;


	Offset = (pAd->TbttTickCount) % (BCN_TBTT_OFFSET);
	pAd->TbttTickCount++;

	/*
		The updated BeaconInterval Value will affect Beacon Interval after two TBTT
		beacasue the original BeaconInterval had been loaded into next TBTT_TIMER
	*/
	if (Offset == (BCN_TBTT_OFFSET-2))
	{
		BCN_TIME_CFG_STRUC csr;
		csr.word = mt7610u_read32(pAd, BCN_TIME_CFG);
		csr.field.BeaconInterval = (pAd->CommonCfg.BeaconPeriod << 4) - 1 ;	/* ASIC register in units of 1/16 TU = 64us*/
		mt7610u_write32(pAd, BCN_TIME_CFG, csr.word);
	}
	else
	{
		if (Offset == (BCN_TBTT_OFFSET-1))
		{
			BCN_TIME_CFG_STRUC csr;

			csr.word = mt7610u_read32(pAd, BCN_TIME_CFG);
			csr.field.BeaconInterval = (pAd->CommonCfg.BeaconPeriod) << 4; /* ASIC register in units of 1/16 TU*/
			mt7610u_write32(pAd, BCN_TIME_CFG, csr.word);
		}
	}
}

#ifdef SOFT_ENCRYPT
bool RTMPExpandPacketForSwEncrypt(
	struct rtmp_adapter *  pAd,
	PTX_BLK			pTxBlk)
{
	PACKET_INFO		PacketInfo;
	u32	ex_head = 0, ex_tail = 0;
	u8 	NumberOfFrag = RTMP_GET_PACKET_FRAGMENTS(pTxBlk->pPacket);

	if (pTxBlk->CipherAlg == CIPHER_AES)
		ex_tail = LEN_CCMP_MIC;

	ex_tail = (NumberOfFrag * ex_tail);

	pTxBlk->pPacket = ExpandPacket(pAd, pTxBlk->pPacket, ex_head, ex_tail);
	if (pTxBlk->pPacket == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: out of resource.\n", __FUNCTION__));
		return false;
	}
	RTMP_QueryPacketInfo(pTxBlk->pPacket, &PacketInfo, &pTxBlk->pSrcBufHeader, &pTxBlk->SrcBufLen);

	return true;
}

void RTMPUpdateSwCacheCipherInfo(
	struct rtmp_adapter *  pAd,
	PTX_BLK			pTxBlk,
	u8 *		pHdr)
{
	PHEADER_802_11 		pHeader_802_11;
	PMAC_TABLE_ENTRY	pMacEntry;

	pHeader_802_11 = (HEADER_802_11 *) pHdr;
	pMacEntry = pTxBlk->pMacEntry;

	if (pMacEntry && pHeader_802_11->FC.Wep &&
		CLIENT_STATUS_TEST_FLAG(pMacEntry, fCLIENT_STATUS_SOFTWARE_ENCRYPT))
	{
		PCIPHER_KEY pKey = &pMacEntry->PairwiseKey;

		TX_BLK_SET_FLAG(pTxBlk, fTX_bSwEncrypt);

		pTxBlk->CipherAlg = pKey->CipherAlg;
		pTxBlk->pKey = pKey;
		if ((pKey->CipherAlg == CIPHER_WEP64) || (pKey->CipherAlg == CIPHER_WEP128))
			inc_iv_byte(pKey->TxTsc, LEN_WEP_TSC, 1);
		else if ((pKey->CipherAlg == CIPHER_TKIP) || (pKey->CipherAlg == CIPHER_AES))
			inc_iv_byte(pKey->TxTsc, LEN_WPA_TSC, 1);

	}

}

#endif /* SOFT_ENCRYPT */

/*
	==========================================================================
	Description:
		Send out a NULL frame to a specified STA at a higher TX rate. The
		purpose is to ensure the designated client is okay to received at this
		rate.
	==========================================================================
 */
void RtmpEnqueueNullFrame(
	struct rtmp_adapter *pAd,
	u8 *       pAddr,
	u8         TxRate,
	u8         PID,
	u8         apidx,
    bool       bQosNull,
    bool       bEOSP,
    u8         OldUP)
{
	PHEADER_802_11 pNullFr;
	u8 *pFrame;
	ULONG		   Length;

	/* since TxRate may change, we have to change Duration each time */
	pFrame = kmalloc(MGMT_DMA_BUFFER_SIZE, GFP_ATOMIC);
	pNullFr = (PHEADER_802_11) pFrame;
	Length = sizeof(HEADER_802_11);

	if (pFrame) {

		pNullFr->FC.Type = BTYPE_DATA;
		pNullFr->FC.FrDs = 1;
		pNullFr->Duration = RTMPCalcDuration(pAd, TxRate, 14);


#ifdef UAPSD_SUPPORT
		if (bQosNull)
		{
			u8 *qos_p = ((u8 *)pNullFr) + Length;

			pNullFr->FC.SubType = SUBTYPE_QOS_NULL;

			/* copy QOS control bytes */
			qos_p[0] = ((bEOSP) ? (1 << 4) : 0) | OldUP;
			qos_p[1] = 0;
			Length += 2;
		} /* End of if */
#endif /* UAPSD_SUPPORT */

		DBGPRINT(RT_DEBUG_INFO, ("send NULL Frame @%d Mbps to AID#%d...\n", RateIdToMbps[TxRate], PID & 0x3f));
		MiniportMMRequest(pAd, MapUserPriorityToAccessCategory[7], (u8 *)pNullFr, Length);
		kfree(pFrame);
	}
}



#ifdef WFA_VHT_PF
#ifdef IP_ASSEMBLY
typedef union ip_flags_frag_offset {
	struct {
#ifdef RT_BIG_ENDIAN
		USHORT flags_reserved:1;
		USHORT flags_may_frag:1;
		USHORT flags_more_frag:1;
		USHORT frag_offset:13;
#else
		USHORT frag_offset:13;
		USHORT flags_more_frag:1;
		USHORT flags_may_frag:1;
		USHORT flags_reserved:1;
#endif
	} field;
	USHORT word;
} IP_FLAGS_FRAG_OFFSET;

typedef struct ip_v4_hdr {
#ifdef RT_BIG_ENDIAN
	u8 version:4, ihl:4;
#else
	u8 ihl:4, version:4;
#endif
	u8 tos;
	USHORT tot_len;
	USHORT identifier;
} IP_V4_HDR;


INT ip_assembly_timeout(struct rtmp_adapter*pAd, MAC_TABLE_ENTRY *pEntry, ULONG Now, u8 QueIdx)
{
	QUEUE_HEADER *queue;
	ULONG *ip_pkt_jiffies;
	INT i;
	struct ip_frag_q *fragQ;

	if ((pEntry->ip_queue1[QueIdx].Number != 0)
		&& (RTMP_TIME_AFTER(Now, (pEntry->ip_pkt1_jiffies[QueIdx]) + (1000 * OS_HZ))))
	{
		PQUEUE_ENTRY pBackupPktEntry;
		struct sk_buff * pBackupPkt;

		while (1) {
			pBackupPktEntry = RemoveHeadQueue(&pEntry->ip_queue1[QueIdx]);
			if (pBackupPktEntry == NULL)
				break;
			pBackupPkt = QUEUE_ENTRY_TO_PACKET(pBackupPktEntry);
			RTMPFreeNdisPacket(pAd, pBackupPkt);
		}
		pEntry->ip_id1[QueIdx] = -1;
		pEntry->ip_id1_FragSize[QueIdx] - -1;
		pEntry->ip_pkt1_jiffies[QueIdx] = 0;
	}


	NdisGetSystemUpTime(&Now);
	if ((pEntry->ip_queue2[QueIdx].Number != 0)
		&& (RTMP_TIME_AFTER(Now, (pEntry->ip_pkt2_jiffies[QueIdx]) + (1000 * OS_HZ))))
	{
		PQUEUE_ENTRY pBackupPktEntry;
		struct sk_buff * pBackupPkt;

		while (1) {
			pBackupPktEntry = RemoveHeadQueue(&pEntry->ip_queue2[QueIdx]);
			if (pBackupPktEntry == NULL)
				break;
			pBackupPkt = QUEUE_ENTRY_TO_PACKET(pBackupPktEntry);
			RTMPFreeNdisPacket(pAd, pBackupPkt);
		}

		pEntry->ip_id2[QueIdx] = -1;
		pEntry->ip_id2_FragSize[QueIdx] - -1;
		pEntry->ip_pkt2_jiffies[QueIdx] = 0;
	}

	return true;
}


INT ip_assembly(
	struct rtmp_adapter*pAd,
	u8 QueIdx,
	struct sk_buff * pPacket,
	PACKET_INFO PacketInfo,
	MAC_TABLE_ENTRY *pEntry)
{
	QUEUE_HEADER *pAC_Queue1, *pAC_Queue2;
	INT32 *pAC_ID1, *pAC_ID2, *pAC_ID1_FragSize, *pAC_ID2_FragSize;
	ULONG *pAC_Jiffies1, *pAC_Jiffies2;
	IP_V4_HDR *pIpv4Hdr, Ipv4Hdr;
	IP_FLAGS_FRAG_OFFSET *pFlags_frag_offset, Flags_frag_offset;
	ULONG Now;
	u32 i;
	QUEUE_HEADER *pTempqueue;
	PQUEUE_ENTRY pBackupPktEntry;
	struct sk_buff * pBackupPkt;


	pAC_Queue1 = &pEntry->ip_queue1[QueIdx];
	pAC_Queue2 = &pEntry->ip_queue2[QueIdx];
	pAC_ID1 = &pEntry->ip_id1[QueIdx];
	pAC_ID2 = &pEntry->ip_id2[QueIdx];
	pAC_ID1_FragSize = &pEntry->ip_id1_FragSize[QueIdx];
	pAC_ID2_FragSize = &pEntry->ip_id2_FragSize[QueIdx];
	pAC_Jiffies1 = &pEntry->ip_pkt1_jiffies[QueIdx];
	pAC_Jiffies2 = &pEntry->ip_pkt2_jiffies[QueIdx];

	NdisGetSystemUpTime(&Now);
	ip_assembly_timeout(pAd, pEntry, Now, QueIdx);

	if (RTMP_GET_PACKET_IPV4(pPacket) &&
	    ((pAd->TxSwQueue[QueIdx].Number >= (pAd->TxSwQMaxLen >> 1)) ||
	    	((pAC_Queue1->Number) || (pAC_Queue2->Number)))
	)
	{
		pIpv4Hdr = (IP_V4_HDR *)(PacketInfo.pFirstBuffer + LENGTH_802_3);
		pFlags_frag_offset = (IP_FLAGS_FRAG_OFFSET *) (PacketInfo.pFirstBuffer + LENGTH_802_3 + 6);
		Flags_frag_offset.word = ntohs(pFlags_frag_offset->word);
		Ipv4Hdr.identifier = ntohs(pIpv4Hdr->identifier);
		Ipv4Hdr.tot_len = ntohs(pIpv4Hdr->tot_len);
		Ipv4Hdr.ihl = pIpv4Hdr->ihl;

		/* check if 1st fragment */
		if ((Flags_frag_offset.field.flags_more_frag == 1) &&
		    (Flags_frag_offset.field.frag_offset == 0))
		{
			NdisGetSystemUpTime(&Now);
			if ((*pAC_ID1) == -1) {
				*pAC_ID1 = Ipv4Hdr.identifier;
				*pAC_Jiffies1 = Now;
				*pAC_ID1_FragSize = Ipv4Hdr.tot_len - (Ipv4Hdr.ihl * 4);
				InsertTailQueue(pAC_Queue1, PACKET_TO_QUEUE_ENTRY(pPacket));
				return 0;
			} else if ((*pAC_ID2) == -1) {
				*pAC_ID2 = Ipv4Hdr.identifier;
				*pAC_Jiffies2 = Now;
				*pAC_ID2_FragSize = Ipv4Hdr.tot_len - (Ipv4Hdr.ihl * 4);
				InsertTailQueue(pAC_Queue2, PACKET_TO_QUEUE_ENTRY(pPacket));
				return 0;
			}

			/* free backup fragments */
			if ((*pAC_Jiffies1) > (*pAC_Jiffies2)) {
				pTempqueue = pAC_Queue2;
				*pAC_ID2 = Ipv4Hdr.identifier;
			} else {
				pTempqueue = pAC_Queue1;
				*pAC_ID1 = Ipv4Hdr.identifier;
			}

			if (pTempqueue->Number != 0) {
				while (1) {
					pBackupPktEntry = RemoveHeadQueue(pTempqueue);
					if (pBackupPktEntry == NULL)
						break;
					pBackupPkt = QUEUE_ENTRY_TO_PACKET(pBackupPktEntry);
					RTMPFreeNdisPacket(pAd, pBackupPkt);
				}
			}
			goto go_original_path;
		}
		else
		{
			/* check if last fragment */
			if ((Ipv4Hdr.identifier == (*pAC_ID1)) || (Ipv4Hdr.identifier == (*pAC_ID2)))
			{
				if (Ipv4Hdr.identifier == (*pAC_ID1)) {
					InsertTailQueue(pAC_Queue1, PACKET_TO_QUEUE_ENTRY(pPacket));
					pTempqueue = pAC_Queue1;
				} else {
					InsertTailQueue(pAC_Queue2, PACKET_TO_QUEUE_ENTRY(pPacket));
					pTempqueue = pAC_Queue2;
				}

				/* the last fragment */
				if ((Flags_frag_offset.field.flags_more_frag == 0)
				    && (Flags_frag_offset.field.frag_offset != 0))
				{
					u32 fragment_count = 0;
					bool bDrop = false;
					if (Ipv4Hdr.identifier == (*pAC_ID1)) {
						fragment_count = ((Flags_frag_offset.field.frag_offset * 8) / (*pAC_ID1_FragSize)) + 1;
						if (pTempqueue->Number != fragment_count)
							bDrop = true;
						*pAC_ID1 = -1;
					}

					if (Ipv4Hdr.identifier == (*pAC_ID2)) {
						fragment_count = ((Flags_frag_offset.field.frag_offset * 8) / (*pAC_ID2_FragSize)) + 1;
						if (pTempqueue->Number != fragment_count)
							bDrop = true;
						*pAC_ID2 = -1;
					}

					/*
						if number does not equal coreect fragment count or no enough space,
						free backup fragments to SwTxQueue[]
					*/
					if ((bDrop == true) ||
					    (pAd->TxSwQueue[QueIdx].Number > (pAd->TxSwQMaxLen - pTempqueue->Number)))
					{
						while (1) {
							pBackupPktEntry = RemoveHeadQueue(pTempqueue);
							if (pBackupPktEntry == NULL)
								break;
							pBackupPkt = QUEUE_ENTRY_TO_PACKET(pBackupPktEntry);
							RTMPFreeNdisPacket(pAd, pBackupPkt);
						}
						return 0;
					}

					/* move backup fragments to SwTxQueue[] */
					NdisAcquireSpinLock(&pAd->TxSwQueueLock[QueIdx]);
					while (1) {
						pBackupPktEntry = RemoveHeadQueue(pTempqueue);
						if (pBackupPktEntry == NULL)
							break;
						InsertTailQueueAc(pAd, pEntry, &pAd->TxSwQueue[QueIdx], pBackupPktEntry);
					}
					NdisReleaseSpinLock(&pAd->TxSwQueueLock[QueIdx]);

					return 0;
				}
			}
			else
			{
				/*
				   bypass none-fist fragmented packets (we should not drop this packet) when
				   1. (pAd->TxSwQueue[QueIdx].Number >= (pAd->TxSwQMaxLen[QueIdx] >> 1) and
				   2. two fragmented buffer are empty
				 */
				if (((*pAC_ID1) == -1) && ((*pAC_ID2) == -1))
					goto go_original_path;

				if ((Flags_frag_offset.field.flags_more_frag != 0)
				    && (Flags_frag_offset.field.frag_offset != 0))
				{
					RTMPFreeNdisPacket(pAd, pPacket);
					return 0;
				}
				goto go_original_path;
			}
		}
	}

go_original_path:
	return -1;
}

#endif /* IP_ASSEMBLY */
#endif /* WFA_VHT_PF */

void StopDmaRx(
	struct rtmp_adapter*pAd,
	u8 Level)
{
	struct sk_buff *	pRxPacket;
	RX_BLK			RxBlk, *pRxBlk;
	u32 RxPending = 0, MacReg = 0, MTxCycle = 0;
	bool bReschedule = false;
	bool bCmdRspPacket = false;
	u8 IdleNums = 0;

	DBGPRINT(RT_DEBUG_TRACE, ("====> %s\n", __FUNCTION__));

	/*
		process whole rx ring
	*/
	while (1)
	{
		if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_NIC_NOT_EXIST))
			return;
		pRxBlk = &RxBlk;
		pRxPacket = GetPacketFromRxRing(pAd, pRxBlk, &bReschedule, &RxPending, &bCmdRspPacket);
		if ((RxPending == 0) && (bReschedule == false))
			break;
		else
			RTMPFreeNdisPacket(pAd, pRxPacket);
	}

	/*
		Check DMA Rx idle
	*/
	for (MTxCycle = 0; MTxCycle < 2000; MTxCycle++)
	{

#ifdef  RTMP_MAC_USB
		MacReg = mt7610u_read32(pAd, USB_DMA_CFG);
		//mt7610u_read32(pAd, USB_DMA_CFG, &MacReg);
		if ((MacReg & 0x40000000) && (IdleNums < 10))
		{
			IdleNums++;
			RTMPusecDelay(50);
		}
		else
		{
			break;
		}
#endif

		if (MacReg == 0xFFFFFFFF)
		{
			RTMP_SET_FLAG(pAd, fRTMP_ADAPTER_NIC_NOT_EXIST);
			return;
		}
	}

	if (MTxCycle >= 2000)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s:RX DMA busy!! DMA_CFG = 0x%08x\n", __FUNCTION__, MacReg));
	}

	if (Level == RTMP_HALT)
	{
		/*
			Disable DMA RX
		*/


	}

	DBGPRINT(RT_DEBUG_TRACE, ("<==== %s\n", __FUNCTION__));
}

void StopDmaTx(
	struct rtmp_adapter*pAd,
	u8 Level)
{
	u32 MacReg = 0, MTxCycle = 0;
	u8 IdleNums = 0;

	DBGPRINT(RT_DEBUG_TRACE, ("====> %s\n", __FUNCTION__));


	for (MTxCycle = 0; MTxCycle < 2000; MTxCycle++)
	{

#ifdef RTMP_MAC_USB
		MacReg = mt7610u_read32(pAd, USB_DMA_CFG);
		//mt7610u_read32(pAd, USB_DMA_CFG, &MacReg);
		if (((MacReg & 0x80000000) == 0) && IdleNums > 10)
		{
			break;
		}
		else
		{
			IdleNums++;
			RTMPusecDelay(50);
		}
#endif

		if (MacReg == 0xFFFFFFFF)
		{
			//RTMP_SET_FLAG(pAd, fRTMP_ADAPTER_NIC_NOT_EXIST);
			return;
		}
	}

	if (MTxCycle >= 2000)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("TX DMA busy!! DMA_CFG(%x)\n", MacReg));
	}

	if (Level == RTMP_HALT)
	{

	}

	DBGPRINT(RT_DEBUG_TRACE, ("<==== %s\n", __FUNCTION__));
}

