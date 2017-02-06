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


#ifndef __AP_H__
#define __AP_H__




/* ============================================================= */
/*      Common definition */
/* ============================================================= */
#define MBSS_VLAN_INFO_GET(												\
	__pAd, __VLAN_VID, __VLAN_Priority, __FromWhichBSSID) 				\
{																		\
	if ((__FromWhichBSSID < __pAd->ApCfg.BssidNum) &&					\
		(__FromWhichBSSID < HW_BEACON_MAX_NUM) &&						\
		(__pAd->ApCfg.MBSSID[__FromWhichBSSID].VLAN_VID != 0))			\
	{																	\
		__VLAN_VID = __pAd->ApCfg.MBSSID[__FromWhichBSSID].VLAN_VID;	\
		__VLAN_Priority = __pAd->ApCfg.MBSSID[__FromWhichBSSID].VLAN_Priority; \
	}																	\
}

/* ============================================================= */
/*      Function Prototypes */
/* ============================================================= */

/* ap_data.c */

bool APBridgeToWirelessSta(
    struct rtmp_adapter *  pAd,
    u8 *         pHeader,
    unsigned int            HdrLen,
    u8 *         pData,
    unsigned int            DataLen,
    unsigned long           fromwdsidx);

void RTMP_BASetup(
	struct rtmp_adapter *pAd,
	PMAC_TABLE_ENTRY pMacEntry,
	u8 UserPriority);

void APSendPackets(
	struct rtmp_adapter *  pAd,
	struct sk_buff **ppPacketArray,
	unsigned int			NumberOfPackets);

int APSendPacket(
    struct rtmp_adapter *  pAd,
    struct sk_buff *    pPacket);

int APInsertPsQueue(
	struct rtmp_adapter *pAd,
	struct sk_buff * pPacket,
	MAC_TABLE_ENTRY *pMacEntry,
	u8 QueIdx);

int APHardTransmit(
	struct rtmp_adapter *pAd,
	TX_BLK			*pTxBlk,
	u8 		QueIdx);

void APRxEAPOLFrameIndicate(
	struct rtmp_adapter *pAd,
	MAC_TABLE_ENTRY	*pEntry,
	RX_BLK			*pRxBlk,
	u8 		FromWhichBSSID);

int APCheckRxError(
	struct rtmp_adapter*pAd,
	struct rtmp_rxinfo *pRxInfo,
	u8 Wcid);

bool APCheckClass2Class3Error(
    struct rtmp_adapter *  pAd,
	unsigned long Wcid,
	PHEADER_802_11  pHeader);

void APHandleRxPsPoll(
	struct rtmp_adapter *pAd,
	u8 *		pAddr,
	unsigned short			Aid,
    bool 		isActive);

void    RTMPDescriptorEndianChange(
    u8 *         pData,
    unsigned long           DescriptorType);

void    RTMPFrameEndianChange(
    struct rtmp_adapter *  pAd,
    u8 *         pData,
    unsigned long           Dir,
    bool         FromRxDoneInt);

/* ap_assoc.c */

void APAssocStateMachineInit(
    struct rtmp_adapter *  pAd,
    STATE_MACHINE *S,
    STATE_MACHINE_FUNC Trans[]);


void MbssKickOutStas(
	struct rtmp_adapter *pAd,
	int apidx,
	unsigned short Reason);

void APMlmeKickOutSta(
    struct rtmp_adapter *pAd,
	u8 *pStaAddr,
	u8 Wcid,
	unsigned short Reason);



void  APCls3errAction(
    struct rtmp_adapter *  pAd,
	unsigned long Wcid,
    PHEADER_802_11	pHeader);

/*
void RTMPAddClientSec(
	struct rtmp_adapter *pAd,
	u8 BssIdx,
	u8 	 KeyIdx,
	u8 	 CipherAlg,
	u8 *	 pKey,
	u8 *	 pTxMic,
	u8 *	 pRxMic,
	MAC_TABLE_ENTRY *pEntry);
*/

/* ap_auth.c */

void APAuthStateMachineInit(
    struct rtmp_adapter *pAd,
    STATE_MACHINE *Sm,
    STATE_MACHINE_FUNC Trans[]);

void APCls2errAction(
    struct rtmp_adapter *pAd,
	unsigned long Wcid,
    PHEADER_802_11	pHeader);

/* ap_connect.c */


void APMakeBssBeacon(
    struct rtmp_adapter *  pAd,
	int				apidx);

void  APUpdateBeaconFrame(
    struct rtmp_adapter *  pAd,
	int				apidx);

void APMakeAllBssBeacon(
    struct rtmp_adapter *  pAd);

void  APUpdateAllBeaconFrame(
    struct rtmp_adapter *  pAd);


/* ap_sync.c */

void APSyncStateMachineInit(
    struct rtmp_adapter *pAd,
    STATE_MACHINE *Sm,
    STATE_MACHINE_FUNC Trans[]);

void APScanTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void APInvalidStateWhenScan(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void APScanTimeoutAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void APPeerProbeReqAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

void APPeerBeaconAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

void APMlmeScanReqAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void APPeerBeaconAtScanAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void APScanCnclAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void ApSiteSurvey(
	struct rtmp_adapter * 		pAd,
	PNDIS_802_11_SSID	pSsid,
	u8 			ScanType,
	bool 			ChannelSel);

void SupportRate(
	u8 *SupRate,
	u8 SupRateLen,
	u8 *ExtRate,
	u8 ExtRateLen,
	u8 **Rates,
	u8 *RatesLen,
	u8 *pMaxSupportRate);


bool ApScanRunning(
	struct rtmp_adapter *pAd);

#ifdef DOT11N_DRAFT3
void APOverlappingBSSScan(
	struct rtmp_adapter*pAd);

int GetBssCoexEffectedChRange(
	struct rtmp_adapter*pAd,
	BSS_COEX_CH_RANGE *pCoexChRange);

#endif /* DOT11N_DRAFT3 */

/* ap_wpa.c */
void WpaStateMachineInit(
    struct rtmp_adapter *  pAd,
    STATE_MACHINE *Sm,
    STATE_MACHINE_FUNC Trans[]);

/* ap_mlme.c */
void APMlmePeriodicExec(
    struct rtmp_adapter *  pAd);

bool APMsgTypeSubst(
    struct rtmp_adapter *pAd,
    PFRAME_802_11 pFrame,
    int *Machine,
    int *MsgType);

void APQuickResponeForRateUpExec(
    void *SystemSpecific1,
    void *FunctionContext,
    void *SystemSpecific2,
    void *SystemSpecific3);

#ifdef RTMP_MAC_USB
void BeaconUpdateExec(
    void *SystemSpecific1,
    void *FunctionContext,
    void *SystemSpecific2,
    void *SystemSpecific3);
#endif /* RTMP_MAC_USB */

void RTMPSetPiggyBack(
	struct rtmp_adapter *pAd,
	bool 		bPiggyBack);

void APAsicEvaluateRxAnt(
	struct rtmp_adapter *pAd);

void APAsicRxAntEvalTimeout(
	struct rtmp_adapter *pAd);

/* ap.c */
int APInitialize(
    struct rtmp_adapter *  pAd);

void APShutdown(
    struct rtmp_adapter *   pAd);

void APStartUp(
    struct rtmp_adapter *  pAd);

void APStop(
    struct rtmp_adapter *  pAd);

void APCleanupPsQueue(
    struct rtmp_adapter *  pAd,
    PQUEUE_HEADER   pQueue);


void MacTableMaintenance(
    struct rtmp_adapter *pAd);

u32 MacTableAssocStaNumGet(
	struct rtmp_adapter *pAd);

MAC_TABLE_ENTRY *APSsPsInquiry(
    struct rtmp_adapter *  pAd,
    u8 *         pAddr,
    SST             *Sst,
    unsigned short          *Aid,
    u8           *PsMode,
    u8           *Rate);

bool APPsIndicate(
    struct rtmp_adapter *  pAd,
    u8 *         pAddr,
	unsigned long Wcid,
    u8           Psm);

#ifdef DOT11_N_SUPPORT
void APUpdateOperationMode(
    struct rtmp_adapter *pAd);
#endif /* DOT11_N_SUPPORT */

void APUpdateCapabilityAndErpIe(
	struct rtmp_adapter *pAd);

bool ApCheckAccessControlList(
	struct rtmp_adapter *pAd,
	u8 *       pAddr,
	u8         Apidx);

void ApUpdateAccessControlList(
    struct rtmp_adapter *pAd,
    u8         Apidx);

void ApEnqueueNullFrame(
	struct rtmp_adapter *pAd,
	u8 *       pAddr,
	u8         TxRate,
	u8         PID,
	u8         apidx,
    bool       bQosNull,
    bool       bEOSP,
    u8         OldUP);

/* ap_sanity.c */


bool PeerAssocReqCmmSanity(
    struct rtmp_adapter *pAd,
	bool isRessoc,
    void *Msg,
    int MsgLen,
    IE_LISTS *ie_lists);


bool PeerDisassocReqSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pAddr2,
    uint16_t	*SeqNum,
    unsigned short *Reason);

bool PeerDeauthReqSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pAddr2,
   	uint16_t	*SeqNum,
    unsigned short *Reason);

bool APPeerAuthSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
	u8 *pAddr1,
    u8 *pAddr2,
    unsigned short *Alg,
    unsigned short *Seq,
    unsigned short *Status,
    char *ChlgText
	);


#ifdef DOT1X_SUPPORT
/* ap_cfg.h */
int	Set_OwnIPAddr_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

int	Set_EAPIfName_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

int	Set_PreAuthIfName_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

/* Define in ap.c */
bool DOT1X_InternalCmdAction(
    struct rtmp_adapter *pAd,
    MAC_TABLE_ENTRY *pEntry,
    u8			cmd);

bool DOT1X_EapTriggerAction(
    struct rtmp_adapter *pAd,
    MAC_TABLE_ENTRY *pEntry);
#endif /* DOT1X_SUPPORT */
#endif  /* __AP_H__ */

void AP_E2PROM_IOCTL_PostCtrl(
	RTMP_IOCTL_INPUT_STRUCT	*wrq,
	char *				msg);

void IAPP_L2_UpdatePostCtrl(
	struct rtmp_adapter *pAd,
    u8 *mac_p,
    int  bssid);
