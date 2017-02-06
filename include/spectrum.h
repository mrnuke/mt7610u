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


#ifndef __SPECTRUM_H__
#define __SPECTRUM_H__

#include "rtmp_type.h"
#include "spectrum_def.h"


u8 GetRegulatoryMaxTxPwr(
	struct rtmp_adapter *pAd,
	u8 channel);

/*
	==========================================================================
	Description:
		Prepare Measurement request action frame and enqueue it into
		management queue waiting for transmition.

	Parametrs:
		1. the destination mac address of the frame.

	Return	: None.
	==========================================================================
 */
void MakeMeasurementReqFrame(
	struct rtmp_adapter *pAd,
	u8 *pOutBuffer,
	unsigned long *pFrameLen,
	u8 TotalLen,
	u8 Category,
	u8 Action,
	u8 MeasureToken,
	u8 MeasureReqMode,
	u8 MeasureReqType,
	uint16_t NumOfRepetitions);

/*
	==========================================================================
	Description:
		Prepare Measurement report action frame and enqueue it into
		management queue waiting for transmition.

	Parametrs:
		1. the destination mac address of the frame.

	Return	: None.
	==========================================================================
 */
void EnqueueMeasurementRep(
	struct rtmp_adapter *pAd,
	u8 *pDA,
	u8 DialogToken,
	u8 MeasureToken,
	u8 MeasureReqMode,
	u8 MeasureReqType,
	u8 ReportInfoLen,
	u8 * pReportInfo);

/*
	==========================================================================
	Description:
		Prepare TPC Request action frame and enqueue it into
		management queue waiting for transmition.

	Parametrs:
		1. the destination mac address of the frame.

	Return	: None.
	==========================================================================
 */
void EnqueueTPCReq(
	struct rtmp_adapter *pAd,
	u8 *pDA,
	u8 DialogToken);

/*
	==========================================================================
	Description:
		Prepare TPC Report action frame and enqueue it into
		management queue waiting for transmition.

	Parametrs:
		1. the destination mac address of the frame.

	Return	: None.
	==========================================================================
 */
void EnqueueTPCRep(
	struct rtmp_adapter *pAd,
	u8 *pDA,
	u8 DialogToken,
	u8 TxPwr,
	u8 LinkMargin);

/*
	==========================================================================
	Description:
		Spectrun action frames Handler such as channel switch annoucement,
		measurement report, measurement request actions frames.

	Parametrs:
		Elme - MLME message containing the received frame

	Return	: None.
	==========================================================================
 */
void PeerSpectrumAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

/*
	==========================================================================
	Description:

	Parametrs:

	Return	: None.
	==========================================================================
 */
int Set_MeasureReq_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

int Set_TpcReq_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

int Set_PwrConstraint(
	struct rtmp_adapter *pAd,
	char *		arg);


int	MeasureReqTabInit(
	struct rtmp_adapter *pAd);

void MeasureReqTabExit(
	struct rtmp_adapter *pAd);

PMEASURE_REQ_ENTRY MeasureReqLookUp(
	struct rtmp_adapter *pAd,
	u8			DialogToken);

PMEASURE_REQ_ENTRY MeasureReqInsert(
	struct rtmp_adapter *pAd,
	u8			DialogToken);

void MeasureReqDelete(
	struct rtmp_adapter *pAd,
	u8			DialogToken);

void InsertChannelRepIE(
	struct rtmp_adapter *pAd,
	u8 *pFrameBuf,
	unsigned long *pFrameLen,
	char *pCountry,
	u8 RegulatoryClass);

void InsertTpcReportIE(
	struct rtmp_adapter *pAd,
	u8 *pFrameBuf,
	unsigned long *pFrameLen,
	u8 TxPwr,
	u8 LinkMargin);

void InsertDialogToken(
	struct rtmp_adapter *pAd,
	u8 *pFrameBuf,
	unsigned long *pFrameLen,
	u8 DialogToken);

int	TpcReqTabInit(
	struct rtmp_adapter *pAd);

void TpcReqTabExit(
	struct rtmp_adapter *pAd);

void NotifyChSwAnnToPeerAPs(
	struct rtmp_adapter *pAd,
	u8 *pRA,
	u8 *pTA,
	u8 ChSwMode,
	u8 Channel);

void RguClass_BuildBcnChList(
	struct rtmp_adapter *pAd,
	u8 *pBuf,
	unsigned long *pBufLen);
#endif /* __SPECTRUM_H__ */

