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


#ifdef RTMP_MAC_USB

#include	"rt_config.h"


int RTUSBFreeDescriptorRelease(struct rtmp_adapter*pAd, u8 BulkOutPipeId)
{
	HT_TX_CONTEXT *pHTTXContext;
	unsigned long IrqFlags;


	pHTTXContext = &pAd->TxContext[BulkOutPipeId];
	RTMP_IRQ_LOCK(&pAd->TxContextQueueLock[BulkOutPipeId], IrqFlags);
	pHTTXContext->bCurWriting = false;
	RTMP_IRQ_UNLOCK(&pAd->TxContextQueueLock[BulkOutPipeId], IrqFlags);

	return NDIS_STATUS_SUCCESS;
}


/*
	========================================================================

	Routine	Description:
		This subroutine will scan through releative ring descriptor to find
		out avaliable free ring descriptor and compare with request size.

	Arguments:
		pAd	Pointer	to our adapter
		RingType	Selected Ring

	Return Value:
		NDIS_STATUS_FAILURE		Not enough free descriptor
		NDIS_STATUS_SUCCESS		Enough free descriptor

	Note:

	========================================================================
*/
int	RTUSBFreeDescRequest(
	struct rtmp_adapter*pAd,
	u8 BulkOutPipeId,
	u32 req_cnt)
{
	int	 Status = NDIS_STATUS_FAILURE;
	unsigned long IrqFlags;
	HT_TX_CONTEXT *pHTTXContext;


	pHTTXContext = &pAd->TxContext[BulkOutPipeId];
	RTMP_IRQ_LOCK(&pAd->TxContextQueueLock[BulkOutPipeId], IrqFlags);
#ifdef USB_BULK_BUF_ALIGMENT
	if( ((pHTTXContext->CurWriteIdx< pHTTXContext->NextBulkIdx  ) &&   (pHTTXContext->NextBulkIdx - pHTTXContext->CurWriteIdx == 1))
		|| ((pHTTXContext->CurWriteIdx ==(BUF_ALIGMENT_RINGSIZE -1) ) &&  (pHTTXContext->NextBulkIdx == 0 )))
	{
		RTUSB_SET_BULK_FLAG(pAd, (fRTUSB_BULK_OUT_DATA_NORMAL << BulkOutPipeId));

	}
	else if (pHTTXContext->bCurWriting == true)
	{
		DBGPRINT(RT_DEBUG_TRACE,("BUF_ALIGMENT RTUSBFreeD c3 --> QueIdx=%d, CWPos=%ld, NBOutPos=%ld!\n", BulkOutPipeId, pHTTXContext->CurWritePosition, pHTTXContext->NextBulkOutPosition));
		RTUSB_SET_BULK_FLAG(pAd, (fRTUSB_BULK_OUT_DATA_NORMAL << BulkOutPipeId));
	}

#else
	if ((pHTTXContext->CurWritePosition < pHTTXContext->NextBulkOutPosition) && ((pHTTXContext->CurWritePosition + req_cnt + LOCAL_TXBUF_SIZE) > pHTTXContext->NextBulkOutPosition))
	{

		RTUSB_SET_BULK_FLAG(pAd, (fRTUSB_BULK_OUT_DATA_NORMAL << BulkOutPipeId));
	}
	else if ((pHTTXContext->CurWritePosition == 8) && (pHTTXContext->NextBulkOutPosition < (req_cnt + LOCAL_TXBUF_SIZE)))
	{
		RTUSB_SET_BULK_FLAG(pAd, (fRTUSB_BULK_OUT_DATA_NORMAL << BulkOutPipeId));
	}
	else if (pHTTXContext->bCurWriting == true)
	{
		DBGPRINT(RT_DEBUG_TRACE,("RTUSBFreeD c3 --> QueIdx=%d, CWPos=%ld, NBOutPos=%ld!\n", BulkOutPipeId, pHTTXContext->CurWritePosition, pHTTXContext->NextBulkOutPosition));
		RTUSB_SET_BULK_FLAG(pAd, (fRTUSB_BULK_OUT_DATA_NORMAL << BulkOutPipeId));
	}
#endif /* USB_BULK_BUF_ALIGMENT */
	else
	{
		Status = NDIS_STATUS_SUCCESS;
	}
	RTMP_IRQ_UNLOCK(&pAd->TxContextQueueLock[BulkOutPipeId], IrqFlags);


	return Status;
}


bool RTUSBNeedQueueBackForAgg(struct rtmp_adapter*pAd, u8 BulkOutPipeId)
{
	HT_TX_CONTEXT *pHTTXContext;
	bool needQueBack = false;
	unsigned long   IrqFlags;


	pHTTXContext = &pAd->TxContext[BulkOutPipeId];

	RTMP_IRQ_LOCK(&pAd->TxContextQueueLock[BulkOutPipeId], IrqFlags);
	if ((pHTTXContext->IRPPending == true)  /*&& (pAd->TxSwQueue[BulkOutPipeId].Number == 0) */)
	{
		if ((pHTTXContext->CurWritePosition < pHTTXContext->ENextBulkOutPosition) &&
			(((pHTTXContext->ENextBulkOutPosition+MAX_AGGREGATION_SIZE) < MAX_TXBULK_LIMIT) || (pHTTXContext->CurWritePosition > MAX_AGGREGATION_SIZE)))
		{
			needQueBack = true;
		}
		else if ((pHTTXContext->CurWritePosition > pHTTXContext->ENextBulkOutPosition) &&
				 ((pHTTXContext->ENextBulkOutPosition + MAX_AGGREGATION_SIZE) < pHTTXContext->CurWritePosition))
		{
			needQueBack = true;
		}
	}
	RTMP_IRQ_UNLOCK(&pAd->TxContextQueueLock[BulkOutPipeId], IrqFlags);

	return needQueBack;

}


/*
	========================================================================

	Routine	Description:
		Calculates the duration which is required to transmit out frames
	with given size and specified rate.

	Arguments:
		pTxD		Pointer to transmit descriptor
		Ack			Setting for Ack requirement bit
		Fragment	Setting for Fragment bit
		RetryMode	Setting for retry mode
		Ifs			Setting for IFS gap
		Rate		Setting for transmit rate
		Service		Setting for service
		Length		Frame length
		TxPreamble  Short or Long preamble when using CCK rates
		QueIdx - 0-3, according to 802.11e/d4.4 June/2003

	Return Value:
		None

	IRQL = PASSIVE_LEVEL
	IRQL = DISPATCH_LEVEL

	========================================================================
*/
void rlt_usb_write_txinfo(
	struct rtmp_adapter*pAd,
	union txinfo_nmac *pTxInfo,
	unsigned short USBDMApktLen,
	bool bWiv,
	u8 QueueSel,
	u8 NextValid,
	u8 TxBurst)
{
	struct txinfo_nmac_pkt *nmac_info;

	nmac_info = &pTxInfo->txinfo_nmac_pkt;
	nmac_info->pkt_80211 = 1;
	nmac_info->info_type = 0;
	nmac_info->d_port = 0;
	nmac_info->cso = 0;
	nmac_info->tso = 0;

	pTxInfo->txinfo_nmac_pkt.pkt_len = USBDMApktLen;
	pTxInfo->txinfo_nmac_pkt.QSEL = QueueSel;
	if (QueueSel != FIFO_EDCA)
		DBGPRINT(RT_DEBUG_TRACE, ("====> QueueSel != FIFO_EDCA <====\n"));
	pTxInfo->txinfo_nmac_pkt.next_vld = false; /*NextValid;   Need to check with Jan about this.*/
	pTxInfo->txinfo_nmac_pkt.tx_burst = TxBurst;
	pTxInfo->txinfo_nmac_pkt.wiv = bWiv;
#ifndef USB_BULK_BUF_ALIGMENT
	pTxInfo->txinfo_nmac_pkt.rsv0 = 0;
#else
	pTxInfo->bFragLasAlignmentsectiontRound = 0;
#endif /* USB_BULK_BUF_ALIGMENT */
}


static void rlt_usb_update_txinfo(
	struct rtmp_adapter*pAd,
	union txinfo_nmac *pTxInfo,
	TX_BLK *pTxBlk)
{
}


#ifdef CONFIG_STA_SUPPORT
void ComposePsPoll(struct rtmp_adapter*pAd)
{
	union txinfo_nmac *pTxInfo;
	struct txwi_nmac *pTxWI;
	u8 TXWISize = sizeof(struct txwi_nmac);
	u8 *buf;
	unsigned short data_len;


	DBGPRINT(RT_DEBUG_TRACE, ("ComposePsPoll\n"));
	memset(&pAd->PsPollFrame, 0, sizeof (PSPOLL_FRAME));

	pAd->PsPollFrame.FC.PwrMgmt = 0;
	pAd->PsPollFrame.FC.Type = BTYPE_CNTL;
	pAd->PsPollFrame.FC.SubType = SUBTYPE_PS_POLL;
	pAd->PsPollFrame.Aid = pAd->StaActive.Aid | 0xC000;
	memcpy(pAd->PsPollFrame.Bssid, pAd->CommonCfg.Bssid, ETH_ALEN);
	memcpy(pAd->PsPollFrame.Ta, pAd->CurrentAddress, ETH_ALEN);

	buf = &pAd->PsPollContext.TransferBuffer->field.WirelessPacket[0];

	pTxInfo = (union txinfo_nmac *)buf;
	pTxWI = (struct txwi_nmac *)&buf[TXINFO_SIZE];
	memset(buf, 0, 100);
	data_len = sizeof (PSPOLL_FRAME);
	rlt_usb_write_txinfo(pAd, pTxInfo, data_len + TXWISize + TSO_SIZE, true,
						EpToQueue[MGMTPIPEIDX], false, false);
	RTMPWriteTxWI(pAd, pTxWI, false, false, false, false, true, false, 0,
		      BSSID_WCID, data_len, 0, 0,
		      (u8) pAd->CommonCfg.MlmeTransmit.field.MCS,
		      IFS_BACKOFF, false, &pAd->CommonCfg.MlmeTransmit);
	memmove((void *)&buf[TXWISize + TXINFO_SIZE + TSO_SIZE], (void *)&pAd->PsPollFrame, data_len);
	/* Append 4 extra zero bytes. */
	pAd->PsPollContext.BulkOutSize = TXINFO_SIZE + TXWISize + TSO_SIZE + data_len + 4;
}
#endif /* CONFIG_STA_SUPPORT */


/* IRQL = DISPATCH_LEVEL */
void ComposeNullFrame(struct rtmp_adapter*pAd)
{
	union txinfo_nmac *pTxInfo;
	struct txwi_nmac *pTxWI;
	u8 *buf;
	u8 TXWISize = sizeof(struct txwi_nmac);
	unsigned short data_len = sizeof(pAd->NullFrame);;


	memset(&pAd->NullFrame, 0, data_len);
	pAd->NullFrame.FC.Type = BTYPE_DATA;
	pAd->NullFrame.FC.SubType = SUBTYPE_NULL_FUNC;
	pAd->NullFrame.FC.ToDs = 1;
	memcpy(pAd->NullFrame.Addr1, pAd->CommonCfg.Bssid, ETH_ALEN);
	memcpy(pAd->NullFrame.Addr2, pAd->CurrentAddress, ETH_ALEN);
	memcpy(pAd->NullFrame.Addr3, pAd->CommonCfg.Bssid, ETH_ALEN);
	buf = &pAd->NullContext.TransferBuffer->field.WirelessPacket[0];
	memset(buf, 0, 100);
	pTxInfo = (union txinfo_nmac *)buf;
	pTxWI = (struct txwi_nmac *)&buf[TXINFO_SIZE];
	rlt_usb_write_txinfo(pAd, pTxInfo,
			(unsigned short)(data_len + TXWISize + TSO_SIZE), true,
			EpToQueue[MGMTPIPEIDX], false, false);
	RTMPWriteTxWI(pAd, pTxWI, false, false, false, false, true, false, 0,
		      BSSID_WCID, data_len, 0, 0,
		      (u8)pAd->CommonCfg.MlmeTransmit.field.MCS,
		      IFS_BACKOFF, false, &pAd->CommonCfg.MlmeTransmit);
	memmove((void *)&buf[TXWISize + TXINFO_SIZE], (void *)&pAd->NullFrame, data_len);
	pAd->NullContext.BulkOutSize = TXINFO_SIZE + TXWISize + TSO_SIZE + data_len + 4;
}


/*
	We can do copy the frame into pTxContext when match following conditions.
		=>
		=>
		=>
*/
static inline int RtmpUSBCanDoWrite(
	struct rtmp_adapter*pAd,
	u8 QueIdx,
	HT_TX_CONTEXT *pHTTXContext)
{
	int	canWrite = NDIS_STATUS_RESOURCES;

#ifdef USB_BULK_BUF_ALIGMENT
	if( ((pHTTXContext->CurWriteIdx< pHTTXContext->NextBulkIdx  ) &&   (pHTTXContext->NextBulkIdx - pHTTXContext->CurWriteIdx == 1))
		|| ((pHTTXContext->CurWriteIdx ==(BUF_ALIGMENT_RINGSIZE -1) ) &&  (pHTTXContext->NextBulkIdx == 0 )))
	{
		DBGPRINT(RT_DEBUG_ERROR,("RtmpUSBCanDoWrite USB_BULK_BUF_ALIGMENT c1!\n"));
		RTUSB_SET_BULK_FLAG(pAd, (fRTUSB_BULK_OUT_DATA_NORMAL << QueIdx));
	}
	else if (pHTTXContext->bCurWriting == true)
	{
		DBGPRINT(RT_DEBUG_ERROR,("RtmpUSBCanDoWrite USB_BULK_BUF_ALIGMENT c3!!\n"));

	}
#else

	if (((pHTTXContext->CurWritePosition) < pHTTXContext->NextBulkOutPosition) && (pHTTXContext->CurWritePosition + LOCAL_TXBUF_SIZE) > pHTTXContext->NextBulkOutPosition)
	{
		DBGPRINT(RT_DEBUG_ERROR,("RtmpUSBCanDoWrite c1!\n"));
		RTUSB_SET_BULK_FLAG(pAd, (fRTUSB_BULK_OUT_DATA_NORMAL << QueIdx));
	}
	else if ((pHTTXContext->CurWritePosition == 8) && (pHTTXContext->NextBulkOutPosition < LOCAL_TXBUF_SIZE))
	{
		DBGPRINT(RT_DEBUG_ERROR,("RtmpUSBCanDoWrite c2!\n"));
		RTUSB_SET_BULK_FLAG(pAd, (fRTUSB_BULK_OUT_DATA_NORMAL << QueIdx));
	}
	else if (pHTTXContext->bCurWriting == true)
	{
		DBGPRINT(RT_DEBUG_ERROR,("RtmpUSBCanDoWrite c3!\n"));
	}
	else if ((pHTTXContext->ENextBulkOutPosition == 8)  && ((pHTTXContext->CurWritePosition + 7912 ) > MAX_TXBULK_LIMIT)  )
	{
		DBGPRINT(RT_DEBUG_ERROR,("RtmpUSBCanDoWrite c4!\n"));
		RTUSB_SET_BULK_FLAG(pAd, (fRTUSB_BULK_OUT_DATA_NORMAL << QueIdx));
	}

#endif /* USB_BULK_BUF_ALIGMENT */
	else
	{
		canWrite = NDIS_STATUS_SUCCESS;
	}


	return canWrite;
}

unsigned short	RtmpUSB_WriteFragTxResource(
	struct rtmp_adapter*pAd,
	TX_BLK *pTxBlk,
	u8 fragNum,
	unsigned short *freeCnt)
{
	HT_TX_CONTEXT	*pHTTXContext;
	unsigned short			hwHdrLen;	/* The hwHdrLen consist of 802.11 header length plus the header padding length.*/
	u32			fillOffset;
	union txinfo_nmac	*pTxInfo;
	struct txwi_nmac 	*pTxWI;
	u8 *		pWirelessPacket = NULL;
	u8 		QueIdx;
	int		Status;
	unsigned long	IrqFlags;
	u32			USBDMApktLen = 0, DMAHdrLen, padding;
#ifdef USB_BULK_BUF_ALIGMENT
	bool 		bLasAlignmentsectiontRound = false;
#else
	bool 		TxQLastRound = false;
#endif /* USB_BULK_BUF_ALIGMENT */
	u8 TXWISize = sizeof(struct txwi_nmac);


	/* get Tx Ring Resource & Dma Buffer address*/

	QueIdx = pTxBlk->QueIdx;
	pHTTXContext  = &pAd->TxContext[QueIdx];

	RTMP_IRQ_LOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);

	pHTTXContext  = &pAd->TxContext[QueIdx];
	fillOffset = pHTTXContext->CurWritePosition;

	if(fragNum == 0)
	{
		/* Check if we have enough space for this bulk-out batch.*/
		Status = RtmpUSBCanDoWrite(pAd, QueIdx, pHTTXContext);
		if (Status == NDIS_STATUS_SUCCESS)
		{
			pHTTXContext->bCurWriting = true;

#ifndef USB_BULK_BUF_ALIGMENT
			/* Reserve space for 8 bytes padding.*/
			if ((pHTTXContext->ENextBulkOutPosition == pHTTXContext->CurWritePosition))
			{
				pHTTXContext->ENextBulkOutPosition += 8;
				pHTTXContext->CurWritePosition += 8;
				fillOffset += 8;
			}
#endif /* USB_BULK_BUF_ALIGMENT */
			pTxBlk->Priv = 0;
			pHTTXContext->CurWriteRealPos = pHTTXContext->CurWritePosition;
		}
		else
		{
			RTMP_IRQ_UNLOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);

			RTMPFreeNdisPacket(pAd, pTxBlk->pPacket);
			return(Status);
		}
	}
	else
	{
		/* For sub-sequent frames of this bulk-out batch. Just copy it to our bulk-out buffer.*/
		Status = ((pHTTXContext->bCurWriting == true) ? NDIS_STATUS_SUCCESS : NDIS_STATUS_FAILURE);
		if (Status == NDIS_STATUS_SUCCESS)
		{
			fillOffset += pTxBlk->Priv;
		}
		else
		{
			RTMP_IRQ_UNLOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);

			RTMPFreeNdisPacket(pAd, pTxBlk->pPacket);
			return(Status);
		}
	}

	memset((u8 *)(&pTxBlk->HeaderBuf[0]), 0, TXINFO_SIZE);
	pTxInfo = (union txinfo_nmac *)(&pTxBlk->HeaderBuf[0]);
	pTxWI= (struct txwi_nmac *)(&pTxBlk->HeaderBuf[TXINFO_SIZE]);

	pWirelessPacket = &pHTTXContext->TransferBuffer->field.WirelessPacket[fillOffset];

	/* copy TXWI + WLAN Header + LLC into DMA Header Buffer*/
	/*hwHdrLen = ROUND_UP(pTxBlk->MpduHeaderLen, 4);*/
	hwHdrLen = pTxBlk->MpduHeaderLen + pTxBlk->HdrPadLen;

	/* Build our URB for USBD*/
	DMAHdrLen = TXWISize + hwHdrLen;
	USBDMApktLen = DMAHdrLen + pTxBlk->SrcBufLen;
	padding = (4 - (USBDMApktLen % 4)) & 0x03;	/* round up to 4 byte alignment*/
	USBDMApktLen += padding;

	pTxBlk->Priv += (TXINFO_SIZE + USBDMApktLen);

	/* For TxInfo, the length of USBDMApktLen = TXWI_SIZE + 802.11 header + payload*/
	rlt_usb_write_txinfo(pAd, pTxInfo, (unsigned short)(USBDMApktLen), false, FIFO_EDCA, false /*NextValid*/,  false);

	if (fragNum == pTxBlk->TotalFragNum)
	{
		pTxInfo->txinfo_nmac_pkt.tx_burst = 0;

#ifdef USB_BULK_BUF_ALIGMENT
		/*
			when CurWritePosition > 0x6000  mean that it is at the max bulk out  size,
			we CurWriteIdx must move to the next alignment section.
			Otherwirse,  CurWriteIdx will be moved to the next section at databulkout.


			(((pHTTXContext->CurWritePosition + 3906)& 0x00007fff) & 0xffff6000) == 0x00006000)
			we must make sure that the last fragNun packet just over the 0x6000
			otherwise it will error because the last frag packet will at the section but will not bulk out.
			ex:   when secoend packet writeresouce and it > 0x6000
				And the last packet writesource and it also > 0x6000  at this time CurWriteIdx++
				but when data bulk out , because at second packet it will > 0x6000 , the last packet will not bulk out.

		*/

		if ( ((pHTTXContext->CurWritePosition + 3906)  & 0x00006000) == 0x00006000)
		{

			bLasAlignmentsectiontRound = true;
			pTxInfo->bFragLasAlignmentsectiontRound = 1;
		}
#else
		if ((pHTTXContext->CurWritePosition + pTxBlk->Priv + 3906)> MAX_TXBULK_LIMIT)
		{
			pTxInfo->txinfo_nmac_pkt.rsv0 = 1;
			TxQLastRound = true;
		}
#endif /* USB_BULK_BUF_ALIGMENT */
	}
	else
	{
		pTxInfo->txinfo_nmac_pkt.tx_burst = 1;
	}

	memmove(pWirelessPacket, pTxBlk->HeaderBuf, TXINFO_SIZE + TXWISize + hwHdrLen);
#ifdef RT_BIG_ENDIAN
	RTMPFrameEndianChange(pAd, (u8 *)(pWirelessPacket + TXINFO_SIZE + TXWISize), DIR_WRITE, false);
#endif /* RT_BIG_ENDIAN */
	pWirelessPacket += (TXINFO_SIZE + TXWISize + hwHdrLen);
	pHTTXContext->CurWriteRealPos += (TXINFO_SIZE + TXWISize + hwHdrLen);

	RTMP_IRQ_UNLOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);

	memmove(pWirelessPacket, pTxBlk->pSrcBufData, pTxBlk->SrcBufLen);

	/*	Zero the last padding.*/
	pWirelessPacket += pTxBlk->SrcBufLen;
	memset(pWirelessPacket, 0, padding + 8);

	if (fragNum == pTxBlk->TotalFragNum)
	{
		RTMP_IRQ_LOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);

		/* Update the pHTTXContext->CurWritePosition. 3906 used to prevent the NextBulkOut is a A-RALINK/A-MSDU Frame.*/
		pHTTXContext->CurWritePosition += pTxBlk->Priv;
#ifndef USB_BULK_BUF_ALIGMENT
		if (TxQLastRound == true)
			pHTTXContext->CurWritePosition = 8;
#endif /* USB_BULK_BUF_ALIGMENT */
#ifdef USB_BULK_BUF_ALIGMENT
		if(bLasAlignmentsectiontRound == true)
		{
			pHTTXContext->CurWritePosition = ((CUR_WRITE_IDX_INC(pHTTXContext->CurWriteIdx, BUF_ALIGMENT_RINGSIZE)) * 0x8000);
		}
#endif /* USB_BULK_BUF_ALIGMENT */

		pHTTXContext->CurWriteRealPos = pHTTXContext->CurWritePosition;

#ifdef UAPSD_SUPPORT
#endif /* UAPSD_SUPPORT */

		/* Finally, set bCurWriting as false*/
	pHTTXContext->bCurWriting = false;

		RTMP_IRQ_UNLOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);

		/* succeed and release the skb buffer*/
		RTMPFreeNdisPacket(pAd, pTxBlk->pPacket);
	}


	return(Status);

}


unsigned short RtmpUSB_WriteSingleTxResource(
	struct rtmp_adapter*pAd,
	TX_BLK *pTxBlk,
	bool bIsLast,
	unsigned short *freeCnt)
{
	HT_TX_CONTEXT *pHTTXContext;
	u32 fillOffset;
	union txinfo_nmac *pTxInfo;
	struct txwi_nmac *pTxWI;
	u8 *pWirelessPacket, *buf;
	u8 QueIdx;
	unsigned long	IrqFlags;
	int Status;
	u32 hdr_copy_len, hdr_len, dma_len = 0, padding;
#ifndef USB_BULK_BUF_ALIGMENT
	bool bTxQLastRound = false;
#endif /* USB_BULK_BUF_ALIGMENT */
	u8 TXWISize = sizeof(struct txwi_nmac);


	/* get Tx Ring Resource & Dma Buffer address*/
	QueIdx = pTxBlk->QueIdx;

	RTMP_IRQ_LOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);
	pHTTXContext  = &pAd->TxContext[QueIdx];
	fillOffset = pHTTXContext->CurWritePosition;



	/* Check ring full */
	Status = RtmpUSBCanDoWrite(pAd, QueIdx, pHTTXContext);
	if(Status == NDIS_STATUS_SUCCESS)
	{
		pHTTXContext->bCurWriting = true;
		buf = &pTxBlk->HeaderBuf[0];
		pTxInfo = (union txinfo_nmac *)buf;
		pTxWI= (struct txwi_nmac *)&buf[TXINFO_SIZE];

#ifndef USB_BULK_BUF_ALIGMENT
		/* Reserve space for 8 bytes padding.*/
		if ((pHTTXContext->ENextBulkOutPosition == pHTTXContext->CurWritePosition))
		{
			pHTTXContext->ENextBulkOutPosition += 8;
			pHTTXContext->CurWritePosition += 8;
			fillOffset += 8;
		}
#endif /* USB_BULK_BUF_ALIGMENT */
		pHTTXContext->CurWriteRealPos = pHTTXContext->CurWritePosition;

		pWirelessPacket = &pHTTXContext->TransferBuffer->field.WirelessPacket[fillOffset];

		/* Build our URB for USBD */
		hdr_len = TXWISize + TSO_SIZE + pTxBlk->MpduHeaderLen + pTxBlk->HdrPadLen;
		hdr_copy_len = TXINFO_SIZE + hdr_len;
		dma_len = hdr_len + pTxBlk->SrcBufLen;
		padding = (4 - (dma_len % 4)) & 0x03;	/* round up to 4 byte alignment*/
		dma_len += padding;

		pTxBlk->Priv = (TXINFO_SIZE + dma_len);

		/* For TxInfo, the length of USBDMApktLen = TXWI_SIZE + TSO_SIZE + 802.11 header + payload */
		rlt_usb_write_txinfo(pAd, pTxInfo, (unsigned short)(dma_len), false, FIFO_EDCA, false /*NextValid*/,  false);


#ifndef USB_BULK_BUF_ALIGMENT
		if ((pHTTXContext->CurWritePosition + 3906 + pTxBlk->Priv) > MAX_TXBULK_LIMIT)
		{
			pTxInfo->txinfo_nmac_pkt.rsv0 = 1;
			bTxQLastRound = true;
		}
#endif /* USB_BULK_BUF_ALIGMENT */

		memmove(pWirelessPacket, pTxBlk->HeaderBuf, hdr_copy_len);
#ifdef RT_BIG_ENDIAN
		RTMPFrameEndianChange(pAd, (u8 *)(pWirelessPacket + TXINFO_SIZE + TXWISize + TSO_SIZE), DIR_WRITE, false);
#endif /* RT_BIG_ENDIAN */
		pWirelessPacket += (hdr_copy_len);

		/* We unlock it here to prevent the first 8 bytes maybe over-writed issue.*/
		/*	1. First we got CurWritePosition but the first 8 bytes still not write to the pTxcontext.*/
		/*	2. An interrupt break our routine and handle bulk-out complete.*/
		/*	3. In the bulk-out compllete, it need to do another bulk-out, */
		/*			if the ENextBulkOutPosition is just the same as CurWritePosition, it will save the first 8 bytes from CurWritePosition,*/
		/*			but the payload still not copyed. the pTxContext->SavedPad[] will save as allzero. and set the bCopyPad = true.*/
		/*	4. Interrupt complete.*/
		/*  5. Our interrupted routine go back and fill the first 8 bytes to pTxContext.*/
		/*	6. Next time when do bulk-out, it found the bCopyPad==true and will copy the SavedPad[] to pTxContext->NextBulkOutPosition.*/
		/*		and the packet will wrong.*/
		pHTTXContext->CurWriteRealPos += hdr_copy_len;
#ifndef USB_BULK_BUF_ALIGMENT
		RTMP_IRQ_UNLOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);
#endif /* USB_BULK_BUF_ALIGMENT */

#ifdef TX_PKT_SG
		if (pTxBlk->pkt_info.BufferCount > 1) {
			INT i, len;
			void *data;
			PKT_SG_T *sg = &pTxBlk->pkt_info.sg_list[0];

			for (i = 0 ; i < pTxBlk->pkt_info.BufferCount; i++) {
				data = sg[i].data;
				len = sg[i].len;
				if (i == 0) {
					len -= ((unsigned long)pTxBlk->pSrcBufData - (unsigned long)sg[i].data);
					data = pTxBlk->pSrcBufData;
				}
				//DBGPRINT(RT_DEBUG_TRACE, ("%s:sg[%d]=0x%x, len=%d\n", __FUNCTION__, i, data, len));
				if (len <= 0) {
					DBGPRINT(RT_DEBUG_ERROR, ("%s():sg[%d] info error, sg.data=0x%x, sg.len=%d, pTxBlk->pSrcBufData=0x%x, pTxBlk->SrcBufLen=%d, data=0x%x, len=%d\n",
								__FUNCTION__, i, sg[i].data, sg[i].len, pTxBlk->pSrcBufData, pTxBlk->SrcBufLen, data, len));
					break;
				}
				memmove(pWirelessPacket, data, len);
				pWirelessPacket += len;
			}
		}
		else
#endif /* TX_PKT_SG */
		{
			memmove(pWirelessPacket, pTxBlk->pSrcBufData, pTxBlk->SrcBufLen);
			pWirelessPacket += pTxBlk->SrcBufLen;
		}

#ifndef USB_BULK_BUF_ALIGMENT
		memset(pWirelessPacket, 0, padding + 8);
		RTMP_IRQ_LOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);
#endif /* USB_BULK_BUF_ALIGMENT */

		pHTTXContext->CurWritePosition += pTxBlk->Priv;
#ifdef UAPSD_SUPPORT
#endif /* UAPSD_SUPPORT */
#ifdef USB_BULK_BUF_ALIGMENT
		/*
			when CurWritePosition > 0x6000  mean that it is at the max bulk out size,
			we CurWriteIdx must move to the next alignment section.
			Otherwirse,  CurWriteIdx will be moved to the next section at databulkout.

			Writingflag = true ,mean that when we writing resource ,and databulkout happen,
			So we bulk out when this packet finish.
		*/
		if ( (pHTTXContext->CurWritePosition  & 0x00006000) == 0x00006000)
		{
			pHTTXContext->CurWritePosition = ((CUR_WRITE_IDX_INC(pHTTXContext->CurWriteIdx, BUF_ALIGMENT_RINGSIZE)) * 0x8000);
		}
#else
		if (bTxQLastRound)
			pHTTXContext->CurWritePosition = 8;
#endif /* USB_BULK_BUF_ALIGMENT */

		pHTTXContext->CurWriteRealPos = pHTTXContext->CurWritePosition;
		pHTTXContext->bCurWriting = false;
	}


	RTMP_IRQ_UNLOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);


	/* succeed and release the skb buffer*/
	RTMPFreeNdisPacket(pAd, pTxBlk->pPacket);

	return(Status);

}


unsigned short RtmpUSB_WriteMultiTxResource(
	struct rtmp_adapter*pAd,
	TX_BLK *pTxBlk,
	u8 frmNum,
	unsigned short *freeCnt)
{
	HT_TX_CONTEXT *pHTTXContext;
	unsigned short hwHdrLen;	/* The hwHdrLen consist of 802.11 header length plus the header padding length.*/
	u32 fillOffset;
	union txinfo_nmac *pTxInfo;
	struct txwi_nmac *pTxWI;
	u8 *pWirelessPacket = NULL;
	u8 QueIdx;
	int Status;
	unsigned long IrqFlags;
	u8 TXWISize = sizeof(struct txwi_nmac);


	/* get Tx Ring Resource & Dma Buffer address*/
	QueIdx = pTxBlk->QueIdx;
	pHTTXContext  = &pAd->TxContext[QueIdx];

	RTMP_IRQ_LOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);

	if(frmNum == 0)
	{
		/* Check if we have enough space for this bulk-out batch.*/
		Status = RtmpUSBCanDoWrite(pAd, QueIdx, pHTTXContext);
		if (Status == NDIS_STATUS_SUCCESS)
		{
			pHTTXContext->bCurWriting = true;

			pTxInfo = (union txinfo_nmac *)(&pTxBlk->HeaderBuf[0]);
			pTxWI= (struct txwi_nmac *)(&pTxBlk->HeaderBuf[TXINFO_SIZE]);

#ifndef USB_BULK_BUF_ALIGMENT
			/* Reserve space for 8 bytes padding.*/
			if ((pHTTXContext->ENextBulkOutPosition == pHTTXContext->CurWritePosition))
			{

				pHTTXContext->CurWritePosition += 8;
				pHTTXContext->ENextBulkOutPosition += 8;
			}
#endif /* USB_BULK_BUF_ALIGMENT */
			fillOffset = pHTTXContext->CurWritePosition;
			pHTTXContext->CurWriteRealPos = pHTTXContext->CurWritePosition;

			pWirelessPacket = &pHTTXContext->TransferBuffer->field.WirelessPacket[fillOffset];


			/* Copy TXINFO + TXWI + WLAN Header + LLC into DMA Header Buffer*/

			if (pTxBlk->TxFrameType == TX_AMSDU_FRAME)
				/*hwHdrLen = ROUND_UP(pTxBlk->MpduHeaderLen-LENGTH_AMSDU_SUBFRAMEHEAD, 4)+LENGTH_AMSDU_SUBFRAMEHEAD;*/
				hwHdrLen = pTxBlk->MpduHeaderLen-LENGTH_AMSDU_SUBFRAMEHEAD + pTxBlk->HdrPadLen + LENGTH_AMSDU_SUBFRAMEHEAD;
			else if (pTxBlk->TxFrameType == TX_RALINK_FRAME)
				/*hwHdrLen = ROUND_UP(pTxBlk->MpduHeaderLen-LENGTH_ARALINK_HEADER_FIELD, 4)+LENGTH_ARALINK_HEADER_FIELD;*/
				hwHdrLen = pTxBlk->MpduHeaderLen-LENGTH_ARALINK_HEADER_FIELD + pTxBlk->HdrPadLen + LENGTH_ARALINK_HEADER_FIELD;
			else
				/*hwHdrLen = ROUND_UP(pTxBlk->MpduHeaderLen, 4);*/
				hwHdrLen = pTxBlk->MpduHeaderLen + pTxBlk->HdrPadLen;

			/* Update the pTxBlk->Priv.*/
			pTxBlk->Priv = TXINFO_SIZE + TXWISize + hwHdrLen;

			/*	pTxInfo->USBDMApktLen now just a temp value and will to correct latter.*/
			rlt_usb_write_txinfo(pAd, pTxInfo, (unsigned short)(pTxBlk->Priv), false, FIFO_EDCA, false /*NextValid*/,  false);

			/* Copy it.*/
			memmove(pWirelessPacket, pTxBlk->HeaderBuf, pTxBlk->Priv);
#ifdef RT_BIG_ENDIAN
			RTMPFrameEndianChange(pAd, (u8 *)(pWirelessPacket+ TXINFO_SIZE + TXWISize), DIR_WRITE, false);
#endif /* RT_BIG_ENDIAN */
			pHTTXContext->CurWriteRealPos += pTxBlk->Priv;
			pWirelessPacket += pTxBlk->Priv;
		}
	}
	else
	{	/* For sub-sequent frames of this bulk-out batch. Just copy it to our bulk-out buffer.*/

		Status = ((pHTTXContext->bCurWriting == true) ? NDIS_STATUS_SUCCESS : NDIS_STATUS_FAILURE);
		if (Status == NDIS_STATUS_SUCCESS)
		{
			fillOffset =  (pHTTXContext->CurWritePosition + pTxBlk->Priv);
			pWirelessPacket = &pHTTXContext->TransferBuffer->field.WirelessPacket[fillOffset];

			/*hwHdrLen = pTxBlk->MpduHeaderLen;*/
			memmove(pWirelessPacket, pTxBlk->HeaderBuf, pTxBlk->MpduHeaderLen);
			pWirelessPacket += (pTxBlk->MpduHeaderLen);
			pTxBlk->Priv += pTxBlk->MpduHeaderLen;
		}
		else
		{	/* It should not happened now unless we are going to shutdown.*/
			DBGPRINT(RT_DEBUG_ERROR, ("WriteMultiTxResource():bCurWriting is false when handle sub-sequent frames.\n"));
			Status = NDIS_STATUS_FAILURE;
		}
	}


	/*
		We unlock it here to prevent the first 8 bytes maybe over-write issue.
		1. First we got CurWritePosition but the first 8 bytes still not write to the pTxContext.
		2. An interrupt break our routine and handle bulk-out complete.
		3. In the bulk-out compllete, it need to do another bulk-out,
			if the ENextBulkOutPosition is just the same as CurWritePosition, it will save the first 8 bytes from CurWritePosition,
			but the payload still not copyed. the pTxContext->SavedPad[] will save as allzero. and set the bCopyPad = true.
		4. Interrupt complete.
		5. Our interrupted routine go back and fill the first 8 bytes to pTxContext.
		6. Next time when do bulk-out, it found the bCopyPad==true and will copy the SavedPad[] to pTxContext->NextBulkOutPosition.
			and the packet will wrong.
	*/
	RTMP_IRQ_UNLOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);

	if (Status != NDIS_STATUS_SUCCESS)
	{
		DBGPRINT(RT_DEBUG_ERROR,("WriteMultiTxResource: CWPos = %ld, NBOutPos = %ld.\n", pHTTXContext->CurWritePosition, pHTTXContext->NextBulkOutPosition));
		goto done;
	}

	/* Copy the frame content into DMA buffer and update the pTxBlk->Priv*/
	memmove(pWirelessPacket, pTxBlk->pSrcBufData, pTxBlk->SrcBufLen);
	pWirelessPacket += pTxBlk->SrcBufLen;
	pTxBlk->Priv += pTxBlk->SrcBufLen;

done:
	/* Release the skb buffer here*/
	RTMPFreeNdisPacket(pAd, pTxBlk->pPacket);

	return(Status);

}


void RtmpUSB_FinalWriteTxResource(
	struct rtmp_adapter*pAd,
	TX_BLK *pTxBlk,
	unsigned short totalMPDUSize,
	unsigned short TxIdx)
{
	u8 		QueIdx;
	HT_TX_CONTEXT	*pHTTXContext;
	u32			fillOffset;
	union txinfo_nmac	*pTxInfo;
	struct txwi_nmac 	*pTxWI;
	u32			USBDMApktLen, padding;
	unsigned long	IrqFlags;
	u8 *		pWirelessPacket;

	QueIdx = pTxBlk->QueIdx;
	pHTTXContext  = &pAd->TxContext[QueIdx];

	RTMP_IRQ_LOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);

	if (pHTTXContext->bCurWriting == true)
	{
		fillOffset = pHTTXContext->CurWritePosition;
#ifndef USB_BULK_BUF_ALIGMENT
		if (((pHTTXContext->ENextBulkOutPosition == pHTTXContext->CurWritePosition) || ((pHTTXContext->ENextBulkOutPosition-8) == pHTTXContext->CurWritePosition))
			&& (pHTTXContext->bCopySavePad == true))
			pWirelessPacket = (u8 *)(&pHTTXContext->SavedPad[0]);
		else
#endif /* USB_BULK_BUF_ALIGMENT */
			pWirelessPacket = (u8 *)(&pHTTXContext->TransferBuffer->field.WirelessPacket[fillOffset]);


		/* Update TxInfo->USBDMApktLen , */
		/*		the length = TXWI_SIZE + 802.11_hdr + 802.11_hdr_pad + payload_of_all_batch_frames + Bulk-Out-padding*/

		pTxInfo = (union txinfo_nmac *)(pWirelessPacket);

		/* Calculate the bulk-out padding*/
		USBDMApktLen = pTxBlk->Priv - TXINFO_SIZE;
		padding = (4 - (USBDMApktLen % 4)) & 0x03;	/* round up to 4 byte alignment*/
		USBDMApktLen += padding;

		pTxInfo->txinfo_nmac_pkt.pkt_len = USBDMApktLen;


		/*
			Update TXWI->TxWIMPDUByteCnt,
				the length = 802.11 header + payload_of_all_batch_frames
		*/
		pTxWI= (struct txwi_nmac *)(pWirelessPacket + TXINFO_SIZE);
		pTxWI->TxWIMPDUByteCnt = totalMPDUSize;


		/* Update the pHTTXContext->CurWritePosition*/

		pHTTXContext->CurWritePosition += (TXINFO_SIZE + USBDMApktLen);
#ifdef USB_BULK_BUF_ALIGMENT
		/*
			when CurWritePosition > 0x6000  mean that it is at the max bulk out size,
			we CurWriteIdx must move to the next alignment section.
			Otherwirse,  CurWriteIdx will be moved to the next section at databulkout.

			Writingflag = true ,mean that when we writing resource ,and databulkout happen,
			So we bulk out when this packet finish.
		*/

		if ( (pHTTXContext->CurWritePosition  & 0x00006000) == 0x00006000)
		{
			pHTTXContext->CurWritePosition = ((CUR_WRITE_IDX_INC(pHTTXContext->CurWriteIdx, BUF_ALIGMENT_RINGSIZE)) * 0x8000);
		}
#else
		if ((pHTTXContext->CurWritePosition + 3906)> MAX_TXBULK_LIMIT)
		{	/* Add 3906 for prevent the NextBulkOut packet size is a A-RALINK/A-MSDU Frame.*/
			pHTTXContext->CurWritePosition = 8;
			pTxInfo->txinfo_nmac_pkt.rsv0 = 1;
		}
#endif /* USB_BULK_BUF_ALIGMENT */

		pHTTXContext->CurWriteRealPos = pHTTXContext->CurWritePosition;

#ifdef UAPSD_SUPPORT
#endif /* UAPSD_SUPPORT */


		/*	Zero the last padding.*/
		pWirelessPacket = (&pHTTXContext->TransferBuffer->field.WirelessPacket[fillOffset + pTxBlk->Priv]);
		memset(pWirelessPacket, 0, padding + 8);

		/* Finally, set bCurWriting as false*/
		pHTTXContext->bCurWriting = false;

	}
	else
	{	/* It should not happened now unless we are going to shutdown.*/
		DBGPRINT(RT_DEBUG_ERROR, ("FinalWriteTxResource():bCurWriting is false when handle last frames.\n"));
	}

	RTMP_IRQ_UNLOCK(&pAd->TxContextQueueLock[QueIdx], IrqFlags);

}


void RtmpUSBDataLastTxIdx(
	struct rtmp_adapter*pAd,
	u8 QueIdx,
	unsigned short TxIdx)
{
	/* DO nothing for USB.*/
}


/*
	When can do bulk-out:
		1. TxSwFreeIdx < TX_RING_SIZE;
			It means has at least one Ring entity is ready for bulk-out, kick it out.
		2. If TxSwFreeIdx == TX_RING_SIZE
			Check if the CurWriting flag is false, if it's false, we can do kick out.

*/
void RtmpUSBDataKickOut(
	struct rtmp_adapter*pAd,
	TX_BLK *pTxBlk,
	u8 QueIdx)
{
	RTUSB_SET_BULK_FLAG(pAd, (fRTUSB_BULK_OUT_DATA_NORMAL << QueIdx));
	RTUSBKickBulkOut(pAd);

}


/*
	Must be run in Interrupt context
	This function handle RT2870 specific TxDesc and cpu index update and kick the packet out.
 */
int RtmpUSBMgmtKickOut(
	struct rtmp_adapter*pAd,
	u8 QueIdx,
	struct sk_buff * pPacket,
	u8 *pSrcBufVA,
	unsigned int SrcBufLen)
{
	union txinfo_nmac *pTxInfo;
	unsigned long BulkOutSize;
	u8 padLen;
	u8 *pDest;
	unsigned long SwIdx = pAd->MgmtRing.TxCpuIdx;
	TX_CONTEXT *pMLMEContext = (PTX_CONTEXT)pAd->MgmtRing.Cell[SwIdx].AllocVa;
	unsigned long IrqFlags;


	pTxInfo = (union txinfo_nmac *)(pSrcBufVA);

	/* Build our URB for USBD*/
	BulkOutSize = (SrcBufLen + 3) & (~3);
	rlt_usb_write_txinfo(pAd, pTxInfo, (unsigned short)(BulkOutSize - TXINFO_SIZE), true, EpToQueue[MGMTPIPEIDX], false,  false);

	BulkOutSize += 4; /* Always add 4 extra bytes at every packet.*/

//+++Add by shiang for debug
if (0) {
	DBGPRINT(RT_DEBUG_OFF, ("-->%s():shiang-6590, QueIdx=%d, SrcBufLen=%d\n", __FUNCTION__, QueIdx, SrcBufLen));
	dump_txinfo(pAd, &pTxInfo->txinfo_nmac_pkt);;
	dumpTxWI(pAd, (struct txwi_nmac *)(pSrcBufVA + TXINFO_SIZE));
}
//---Add by shiang for debug

/* WY , it cause Tx hang on Amazon_SE , Max said the padding is useless*/
	/* If BulkOutSize is multiple of BulkOutMaxPacketSize, add extra 4 bytes again.*/
/*	if ((BulkOutSize % pAd->BulkOutMaxPacketSize) == 0)*/
/*		BulkOutSize += 4;*/

	padLen = BulkOutSize - SrcBufLen;
	ASSERT((padLen <= RTMP_PKT_TAIL_PADDING));

	/* Now memzero all extra padding bytes.*/
	pDest = (u8 *)(pSrcBufVA + SrcBufLen);
	skb_put(pPacket, padLen);
	memset(pDest, 0, padLen);

	RTMP_IRQ_LOCK(&pAd->MLMEBulkOutLock, IrqFlags);

	pAd->MgmtRing.Cell[pAd->MgmtRing.TxCpuIdx].pNdisPacket = pPacket;
	pMLMEContext->TransferBuffer = (TX_BUFFER *) pPacket->data;

	/* Length in TxInfo should be 8 less than bulkout size.*/
	pMLMEContext->BulkOutSize = BulkOutSize;
	pMLMEContext->InUse = true;
	pMLMEContext->bWaitingBulkOut = true;

#ifdef UAPSD_SUPPORT
		/*
			If the packet is QoS Null frame, we mark the packet with its WCID;
			If not, we mark the packet with bc/mc WCID = 0.

			We will handle it in rtusb_mgmt_dma_done_tasklet().

			Even AP send a QoS Null frame but not EOSP frame in USB mode,
			then we will call UAPSD_SP_Close() and we will check
			pEntry->bAPSDFlagSPStart() so do not worry about it.
		*/
#endif /* UAPSD_SUPPORT */

/*
	pAd->RalinkCounters.KickTxCount++;
	pAd->RalinkCounters.OneSecTxDoneCount++;

	if (pAd->MgmtRing.TxSwFreeIdx == MGMT_RING_SIZE)
		needKickOut = true;
*/

	/* Decrease the TxSwFreeIdx and Increase the TX_CTX_IDX*/
	pAd->MgmtRing.TxSwFreeIdx--;
	INC_RING_INDEX(pAd->MgmtRing.TxCpuIdx, MGMT_RING_SIZE);

	RTMP_IRQ_UNLOCK(&pAd->MLMEBulkOutLock, IrqFlags);

	RTUSB_SET_BULK_FLAG(pAd, fRTUSB_BULK_OUT_MLME);
	/*if (needKickOut)*/
	RTUSBKickBulkOut(pAd);

	return 0;
}


void RtmpUSBNullFrameKickOut(
	struct rtmp_adapter*pAd,
	u8 QueIdx,
	u8 *pNullFrame,
	u32 frameLen)
{
	if (pAd->NullContext.InUse == false)
	{
		PTX_CONTEXT pNullContext;
		union txinfo_nmac *pTxInfo;
		struct txwi_nmac *pTxWI;
		u8 *pWirelessPkt;
		u8 TXWISize = sizeof(struct txwi_nmac);

		pNullContext = &(pAd->NullContext);

		/* Set the in use bit*/
		pNullContext->InUse = true;
		pWirelessPkt = (u8 *)&pNullContext->TransferBuffer->field.WirelessPacket[0];

		memset(&pWirelessPkt[0], 0, 100);
		pTxInfo = (union txinfo_nmac *)&pWirelessPkt[0];
		rlt_usb_write_txinfo(pAd, pTxInfo, (unsigned short)(frameLen + TXWISize + TSO_SIZE), true, EpToQueue[MGMTPIPEIDX], false,  false);
		pTxInfo->txinfo_nmac_pkt.QSEL = FIFO_EDCA;
		pTxWI = (struct txwi_nmac *)&pWirelessPkt[TXINFO_SIZE];
		RTMPWriteTxWI(pAd, pTxWI,  false, false, false, false, true, false, 0, BSSID_WCID, frameLen,
			0, 0, (u8)pAd->CommonCfg.MlmeTransmit.field.MCS, IFS_HTTXOP, false, &pAd->CommonCfg.MlmeTransmit);
#ifdef RT_BIG_ENDIAN
		RTMPWIEndianChange(pTxWI, sizeof(*pTxWI));
#endif /* RT_BIG_ENDIAN */
		memmove(&pWirelessPkt[TXWISize + TXINFO_SIZE + TSO_SIZE], pNullFrame, frameLen);
#ifdef RT_BIG_ENDIAN
		RTMPFrameEndianChange(pAd, (u8 *)&pWirelessPkt[TXINFO_SIZE + TXWISize + TSO_SIZE], DIR_WRITE, false);
#endif /* RT_BIG_ENDIAN */
		pAd->NullContext.BulkOutSize =  TXINFO_SIZE + TXWISize + TSO_SIZE + frameLen + 4;
		pAd->NullContext.BulkOutSize = ( pAd->NullContext.BulkOutSize + 3) & (~3);

		/* Fill out frame length information for global Bulk out arbitor*/
		/*pNullContext->BulkOutSize = TransferBufferLength;*/
		DBGPRINT(RT_DEBUG_TRACE, ("%s - Send NULL Frame @%d Mbps...\n", __FUNCTION__, RateIdToMbps[pAd->CommonCfg.TxRate]));
		RTUSB_SET_BULK_FLAG(pAd, fRTUSB_BULK_OUT_DATA_NULL);

		pAd->Sequence = (pAd->Sequence+1) & MAXSEQ;

		/* Kick bulk out */
		RTUSBKickBulkOut(pAd);
	}

}


/*
========================================================================
Routine Description:
    Get a received packet.

Arguments:
	pAd					device control block
	pSaveRxD			receive descriptor information
	*pbReschedule		need reschedule flag
	*pRxPending			pending received packet flag

Return Value:
    the recieved packet

Note:
========================================================================
*/
struct sk_buff * GetPacketFromRxRing(
	struct rtmp_adapter*pAd,
	RX_BLK *pRxBlk,
	bool *pbReschedule,
	u32 *pRxPending,
	bool *bCmdRspPacket)
{
	RX_CONTEXT *pRxContext;
	struct sk_buff * pNetPkt;
	u8 *pData, *RXDMA;
	unsigned long ThisFrameLen, RxBufferLength, valid_len;
	struct rxwi_nmac *pRxWI;
	u8 RXWISize = sizeof(struct rxwi_nmac);
	struct rtmp_rxinfo *pRxInfo;
	RXFCE_INFO *pRxFceInfo;

	*bCmdRspPacket = false;


	pRxContext = &pAd->RxContext[pAd->NextRxBulkInReadIndex];
	if ((pRxContext->Readable == false) || (pRxContext->InUse == true))
		return NULL;

	RxBufferLength = pRxContext->BulkInOffset - pAd->ReadPosition;
	valid_len = RXDMA_FIELD_SIZE * 2;

	if (RxBufferLength < valid_len)
	{
		goto label_null;
	}

	pData = &pRxContext->TransferBuffer[pAd->ReadPosition];

	RXDMA = pData;
	/* The RXDMA field is 4 bytes, now just use the first 2 bytes. The Length including the (RXWI + MSDU + Padding) */
	ThisFrameLen = *pData + (*(pData+1)<<8);

	if (ThisFrameLen == 0)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("BIRIdx(%d): RXDMALen is zero.[%ld], BulkInBufLen = %ld)\n",
								pAd->NextRxBulkInReadIndex, ThisFrameLen, pRxContext->BulkInOffset));
		goto label_null;
	}
	if ((ThisFrameLen & 0x3) != 0)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("BIRIdx(%d): RXDMALen not multiple of 4.[%ld], BulkInBufLen = %ld)\n",
								pAd->NextRxBulkInReadIndex, ThisFrameLen, pRxContext->BulkInOffset));
		goto label_null;
	}

	if ((ThisFrameLen + 8) > RxBufferLength)	/* 8 for (RXDMA_FIELD_SIZE + sizeof(struct rtmp_rxinfo))*/
	{
		DBGPRINT(RT_DEBUG_ERROR,("BIRIdx(%d):FrameLen(0x%lx) outranges. BulkInLen=0x%lx, remaining RxBufLen=0x%lx, ReadPos=0x%lx\n",
						pAd->NextRxBulkInReadIndex, ThisFrameLen, pRxContext->BulkInOffset, RxBufferLength, pAd->ReadPosition));

		/* error frame. finish this loop*/
		goto label_null;
	}

	/* skip USB frame length field*/
	pData += RXDMA_FIELD_SIZE;

	pRxFceInfo = (RXFCE_INFO *)(pData + ThisFrameLen);

	/* Check if command response or data packet */
	if ((pRxFceInfo->info_type == CMD_PACKET) && (pAd->chipCap.CmdRspRxRing == RX_RING0))
	{
		//CmdRspEventCallbackHandle(pAd, RXDMA);

		/* Update next packet read position.*/
		pAd->ReadPosition += (sizeof(*pRxFceInfo) * 2 + pRxFceInfo->pkt_len);

		*bCmdRspPacket = true;

		goto label_null;
	}

	pRxInfo = (struct rtmp_rxinfo *)pData;

	pData += RXINFO_SIZE;

	pRxWI = (struct rxwi_nmac *)pData;

#ifdef RT_BIG_ENDIAN
	RTMPWIEndianChange(pData, sizeof(struct rxwi_nmac));
#endif /* RT_BIG_ENDIAN */
	if (pRxWI->RxWIMPDUByteCnt > ThisFrameLen)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s():pRxWIMPDUtotalByteCount(%d) large than RxDMALen(%ld)\n",
									__FUNCTION__, pRxWI->RxWIMPDUByteCnt, ThisFrameLen));
		goto label_null;
	}
#ifdef RT_BIG_ENDIAN
	RTMPWIEndianChange(pData, sizeof(struct rxwi_nmac));
#endif /* RT_BIG_ENDIAN */

	/* allocate a rx packet*/
	pNetPkt = dev_alloc_skb(ThisFrameLen);
	if (pNetPkt == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR,("%s():Cannot Allocate sk buffer for this Bulk-In buffer!\n", __FUNCTION__));
		goto label_null;
	}

	/* copy the rx packet*/
	RTMP_USB_PKT_COPY(get_netdev_from_bssid(pAd, BSS0), pNetPkt, ThisFrameLen, pData);

#ifdef RT_BIG_ENDIAN
	RTMPDescriptorEndianChange((u8 *)pRxInfo, TYPE_RXINFO);
#endif /* RT_BIG_ENDIAN */

	memmove((void *)&pRxBlk->hw_rx_info[0], (void *)pRxFceInfo, sizeof(RXFCE_INFO));
	pRxBlk->pRxFceInfo = (RXFCE_INFO *)&pRxBlk->hw_rx_info[0];

	memmove(&pRxBlk->hw_rx_info[RXINFO_OFFSET], pRxInfo, RXINFO_SIZE);
	pRxBlk->pRxInfo = (struct rtmp_rxinfo *)&pRxBlk->hw_rx_info[RXINFO_OFFSET];


	/* update next packet read position.*/
	pAd->ReadPosition += (ThisFrameLen + RXDMA_FIELD_SIZE + RXINFO_SIZE);	/* 8 for (RXDMA_FIELD_SIZE + sizeof(struct rtmp_rxinfo))*/

	return pNetPkt;

label_null:

	return NULL;
}


#ifdef CONFIG_STA_SUPPORT
/*
	========================================================================

	Routine	Description:
		Check Rx descriptor, return NDIS_STATUS_FAILURE if any error dound

	Arguments:
		pRxD		Pointer	to the Rx descriptor

	Return Value:
		NDIS_STATUS_SUCCESS		No err
		NDIS_STATUS_FAILURE		Error

	Note:

	========================================================================
*/
int	RTMPCheckRxError(
	struct rtmp_adapter*pAd,
	PHEADER_802_11 pHeader,
	struct rxwi_nmac *pRxWI,
	struct rtmp_rxinfo *pRxInfo)
{
	PCIPHER_KEY pWpaKey;
	INT dBm;

	if(pRxInfo == NULL)
		return(NDIS_STATUS_FAILURE);

	/* Phy errors & CRC errors*/
	if (pRxInfo->Crc)
	{
		/* Check RSSI for Noise Hist statistic collection.*/
		dBm = (INT) (pRxWI->RxWIRSSI0) - pAd->BbpRssiToDbmDelta;
		if (dBm <= -87)
			pAd->StaCfg.RPIDensity[0] += 1;
		else if (dBm <= -82)
			pAd->StaCfg.RPIDensity[1] += 1;
		else if (dBm <= -77)
			pAd->StaCfg.RPIDensity[2] += 1;
		else if (dBm <= -72)
			pAd->StaCfg.RPIDensity[3] += 1;
		else if (dBm <= -67)
			pAd->StaCfg.RPIDensity[4] += 1;
		else if (dBm <= -62)
			pAd->StaCfg.RPIDensity[5] += 1;
		else if (dBm <= -57)
			pAd->StaCfg.RPIDensity[6] += 1;
		else if (dBm > -57)
			pAd->StaCfg.RPIDensity[7] += 1;

		return(NDIS_STATUS_FAILURE);
	}

	/* Add Rx size to channel load counter, we should ignore error counts*/
	pAd->StaCfg.CLBusyBytes += (pRxWI->RxWIMPDUByteCnt + 14);

#ifndef CLIENT_WDS
	if (pHeader->FC.ToDs
		)
	{
		DBGPRINT_RAW(RT_DEBUG_ERROR, ("Err;FC.ToDs\n"));
		return NDIS_STATUS_FAILURE;
	}
#endif /* CLIENT_WDS */

	/* Paul 04-03 for OFDM Rx length issue*/
	if (pRxWI->RxWIMPDUByteCnt > MAX_AGGREGATION_SIZE)
	{
		DBGPRINT_RAW(RT_DEBUG_ERROR, ("received packet too long\n"));
		return NDIS_STATUS_FAILURE;
	}

	/* Drop not U2M frames, cant's drop here because we will drop beacon in this case*/
	/* I am kind of doubting the U2M bit operation*/
	/* if (pRxD->U2M == 0)*/
	/*	return(NDIS_STATUS_FAILURE);*/

	/* drop decyption fail frame*/
	if (pRxInfo->Decrypted && pRxInfo->CipherErr)
	{
		/* MIC Error*/
		if ((pRxInfo->CipherErr == 2) && pRxInfo->MyBss)
		{
			pWpaKey = &pAd->SharedKey[BSS0][pRxWI->RxWIKeyIndex];
#ifdef WPA_SUPPLICANT_SUPPORT
            if (pAd->StaCfg.WpaSupplicantUP)
                WpaSendMicFailureToWpaSupplicant(pAd->net_dev,
                                   (pWpaKey->Type == PAIRWISEKEY) ? true:false);
            else
#endif /* WPA_SUPPLICANT_SUPPORT */
			RTMPReportMicError(pAd, pWpaKey);
			DBGPRINT_RAW(RT_DEBUG_ERROR,("Rx MIC Value error\n"));
		}

		if (pRxInfo->Decrypted &&
			(pAd->SharedKey[BSS0][pRxWI->RxWIKeyIndex].CipherAlg == CIPHER_AES) &&
			(pHeader->Sequence == pAd->FragFrame.Sequence))
		{

			/* Acceptable since the First FragFrame no CipherErr problem.*/
			return(NDIS_STATUS_SUCCESS);
		}

		return(NDIS_STATUS_FAILURE);
	}

	return(NDIS_STATUS_SUCCESS);
}


void RtmpUsbStaAsicForceWakeupTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3)
{
	struct rtmp_adapter*pAd = (struct rtmp_adapter*)FunctionContext;



	if (pAd && pAd->Mlme.AutoWakeupTimerRunning)
	{
		RTUSBBulkReceive(pAd);

		OPSTATUS_CLEAR_FLAG(pAd, fOP_STATUS_DOZE);
		pAd->Mlme.AutoWakeupTimerRunning = false;
	}
}


void RT28xxUsbStaAsicForceWakeup(
	struct rtmp_adapter *pAd,
	bool       bFromTx)
{
	bool Canceled;

	if (pAd->Mlme.AutoWakeupTimerRunning)
	{
		RTMPCancelTimer(&pAd->Mlme.AutoWakeupTimer, &Canceled);
		pAd->Mlme.AutoWakeupTimerRunning = false;
	}

	OPSTATUS_CLEAR_FLAG(pAd, fOP_STATUS_DOZE);
}


void RT28xxUsbStaAsicSleepThenAutoWakeup(
	struct rtmp_adapter *pAd,
	unsigned short TbttNumToNextWakeUp)
{


	/* Not going to sleep if in the Count Down Time*/
	if (pAd->CountDowntoPsm > 0)
		return;


	/* we have decided to SLEEP, so at least do it for a BEACON period.*/
	if (TbttNumToNextWakeUp == 0)
		TbttNumToNextWakeUp = 1;

	RTMPSetTimer(&pAd->Mlme.AutoWakeupTimer, AUTO_WAKEUP_TIMEOUT);
	pAd->Mlme.AutoWakeupTimerRunning = true;

	/* cancel bulk-in IRPs prevent blocking CPU enter C3.*/
	if((pAd->PendingRx > 0) && (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_NIC_NOT_EXIST)))
	{
		RTUSBCancelPendingBulkInIRP(pAd);
		/* resend bulk-in IRPs to receive beacons after a period of (pAd->CommonCfg.BeaconPeriod - 40) ms*/
		pAd->PendingRx = 0;
	}


	OPSTATUS_SET_FLAG(pAd, fOP_STATUS_DOZE);

}
#endif /* CONFIG_STA_SUPPORT */

#endif /* RTMP_MAC_USB */

