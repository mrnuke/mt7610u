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


#ifdef RT_CFG80211_SUPPORT

#define RT_CFG80211_REGISTER(__pDev, __pNetDev)								\
	CFG80211_Register(__pDev, __pNetDev);

#define RT_CFG80211_BEACON_CR_PARSE(__pAd, __pVIE, __LenVIE)				\
	CFG80211_BeaconCountryRegionParse((void *)__pAd, __pVIE, __LenVIE);

#define RT_CFG80211_CRDA_REG_HINT(__pAd, __pCountryIe, __CountryIeLen)		\
	CFG80211_RegHint((void *)__pAd, __pCountryIe, __CountryIeLen);

#define RT_CFG80211_CRDA_REG_HINT11D(__pAd, __pCountryIe, __CountryIeLen)	\
	CFG80211_RegHint11D((void *)__pAd, __pCountryIe, __CountryIeLen);

#define RT_CFG80211_CRDA_REG_RULE_APPLY(__pAd)								\
	CFG80211_RegRuleApply((void *)__pAd, NULL, __pAd->Cfg80211_Alpha2);

#define RT_CFG80211_SCANNING_INFORM(__pAd, __BssIdx, __ChanId, __pFrame,	\
			__FrameLen, __RSSI)									\
	CFG80211_Scaning((void *)__pAd, __BssIdx, __ChanId, __pFrame,			\
						__FrameLen, __RSSI);

#define RT_CFG80211_SCAN_END(__pAd, __FlgIsAborted)							\
	CFG80211_ScanEnd((void *)__pAd, __FlgIsAborted);

#define RT_CFG80211_REINIT(__pAd)											\
	CFG80211_SupBandReInit((void *)__pAd);									\

#define RT_CFG80211_CONN_RESULT_INFORM(__pAd, __pBSSID, __pReqIe, __ReqIeLen,\
			__pRspIe, __RspIeLen, __FlgIsSuccess)							\
	CFG80211_ConnectResultInform((void *)__pAd, __pBSSID,					\
			__pReqIe, __ReqIeLen, __pRspIe, __RspIeLen, __FlgIsSuccess);

#define RT_CFG80211_RFKILL_STATUS_UPDATE(_pAd, _active) \
	CFG80211_RFKillStatusUpdate(_pAd, _active);

#define CFG80211_BANDINFO_FILL(__pAd, __pBandInfo)							\
{																			\
	(__pBandInfo)->RFICType = __pAd->RFICType;								\
	(__pBandInfo)->MpduDensity = __pAd->CommonCfg.BACapability.field.MpduDensity;\
	(__pBandInfo)->TxStream = __pAd->CommonCfg.TxStream;					\
	(__pBandInfo)->RxStream = __pAd->CommonCfg.RxStream;					\
	(__pBandInfo)->MaxTxPwr = 0;											\
	if (WMODE_EQUAL(__pAd->CommonCfg.PhyMode, WMODE_B))				\
		(__pBandInfo)->FlgIsBMode = true;									\
	else																	\
		(__pBandInfo)->FlgIsBMode = false;									\
	(__pBandInfo)->MaxBssTable = MAX_LEN_OF_BSS_TABLE;						\
	(__pBandInfo)->RtsThreshold = pAd->CommonCfg.RtsThreshold;				\
	(__pBandInfo)->FragmentThreshold = pAd->CommonCfg.FragmentThreshold;	\
	(__pBandInfo)->RetryMaxCnt = 0;											\
	(__pBandInfo)->RetryMaxCnt = mt7610u_read32(__pAd, TX_RTY_CFG);		\
}


/* utilities used in DRV module */
INT CFG80211DRV_IoctlHandle(
	void 				*pAdSrc,
	RTMP_IOCTL_INPUT_STRUCT	*wrq,
	INT						cmd,
	USHORT					subcmd,
	void 				*pData,
	ULONG					Data);

bool CFG80211DRV_OpsSetChannel(
	void 					*pAdOrg,
	void 					*pData);

bool CFG80211DRV_OpsChgVirtualInf(
	void 					*pAdOrg,
	void 					*pFlgFilter,
	u8						IfType);

bool CFG80211DRV_OpsScan(
	void 					*pAdOrg);

bool CFG80211DRV_OpsJoinIbss(
	void 					*pAdOrg,
	void 					*pData);

bool CFG80211DRV_OpsLeave(
	void 					*pAdOrg);

bool CFG80211DRV_StaGet(
	void 					*pAdOrg,
	void 					*pData);

bool CFG80211DRV_Connect(
	void 					*pAdOrg,
	void 					*pData);

bool CFG80211DRV_KeyAdd(
	void 					*pAdOrg,
	void 					*pData);

void CFG80211DRV_RegNotify(
	void 					*pAdOrg,
	void 					*pData);

void CFG80211DRV_SurveyGet(
	void 					*pAdOrg,
	void 					*pData);

void CFG80211DRV_PmkidConfig(
	void 					*pAdOrg,
	void 					*pData);

void CFG80211_RegHint(
	void 					*pAdCB,
	u8 				*pCountryIe,
	ULONG					CountryIeLen);

void CFG80211_RegHint11D(
	void 					*pAdCB,
	u8 				*pCountryIe,
	ULONG					CountryIeLen);

void CFG80211_ScanEnd(
	void 					*pAdCB,
	bool 				FlgIsAborted);

void CFG80211_ConnectResultInform(
	void 					*pAdCB,
	u8 				*pBSSID,
	u8 				*pReqIe,
	u32					ReqIeLen,
	u8 				*pRspIe,
	u32					RspIeLen,
	u8 				FlgIsSuccess);

bool CFG80211_SupBandReInit(
	void 					*pAdCB);

void CFG80211_RegRuleApply(
	void 					*pAdCB,
	void 					*pWiphy,
	u8 				*pAlpha2);

void CFG80211_Scaning(
	void 					*pAdCB,
	u32					BssIdx,
	u32					ChanId,
	u8 				*pFrame,
	u32					FrameLen,
	int32_t					RSSI);

#ifdef RFKILL_HW_SUPPORT
void CFG80211_RFKillStatusUpdate(
	void *				pAd,
	bool 				active);
#endif /* RFKILL_HW_SUPPORT */

void CFG80211_UnRegister(
	void 					*pAdOrg,
	void 					*pNetDev);

#ifdef RT_P2P_SPECIFIC_WIRELESS_EVENT
INT CFG80211_SendWirelessEvent(
	void                                         *pAdCB,
	u8 					*pMacAddr);
#endif /* RT_P2P_SPECIFIC_WIRELESS_EVENT */

#endif /* RT_CFG80211_SUPPORT */

/* End of cfg80211extr.h */
