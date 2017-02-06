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


#ifndef	__WFD_H__
#define	__WFD_H__

#ifdef WFD_SUPPORT

#include "rtmp_type.h"

INT Set_WfdEnable_Proc(
    struct rtmp_adapter *	pAd,
    char *		arg);

#ifdef RT_CFG80211_SUPPORT
INT Set_WfdInsertIe_Proc
(
	struct rtmp_adapter *	pAd,
	char *		arg);
#endif /* RT_CFG80211_SUPPORT */

INT Set_WfdDeviceType_Proc(
    struct rtmp_adapter *	pAd,
    char *		arg);

INT Set_WfdCouple_Proc(
    struct rtmp_adapter *	pAd,
    char *		arg);

INT Set_WfdSessionAvailable_Proc(
    struct rtmp_adapter *	pAd,
    char *		arg);

INT Set_WfdCP_Proc(
    struct rtmp_adapter *	pAd,
    char *		arg);

INT	Set_WfdRtspPort_Proc(
    struct rtmp_adapter *	pAd,
    char *		arg);

INT	Set_WfdMaxThroughput_Proc(
    struct rtmp_adapter *	pAd,
    char *		arg);

INT Set_WfdLocalIp_Proc(
    struct rtmp_adapter *	pAd,
    char *		arg);

INT Set_PeerRtspPort_Proc(
    struct rtmp_adapter *	pAd,
    char *		arg);

void WfdMakeWfdIE(
	struct rtmp_adapter *pAd,
	unsigned long			WfdIeBitmap,
	u8 *		pOutBuf,
	unsigned long			*pIeLen);

unsigned long InsertWfdSubelmtTlv(
	struct rtmp_adapter *	pAd,
	u8 		SubId,
	u8 *		pInBuffer,
	u8 *		pOutBuffer,
	unsigned int				Action);

void WfdParseSubElmt(
	struct rtmp_adapter *	pAd,
	PWFD_ENTRY_INFO	pWfdEntryInfo,
	void 				*Msg,
	unsigned long 			MsgLen);

void WfdCfgInit(
	struct rtmp_adapter *pAd);

#endif /* WFD_SUPPORT */
#endif /* __WFD_H__ */

