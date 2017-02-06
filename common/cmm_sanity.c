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

extern u8 CISCO_OUI[];

extern u8 WPA_OUI[];
extern u8 RSN_OUI[];
extern u8 WME_INFO_ELEM[];
extern u8 WME_PARM_ELEM[];
extern u8 RALINK_OUI[];
extern u8 BROADCOM_OUI[];
extern u8    WPS_OUI[];



typedef struct wsc_ie_probreq_data
{
	u8 ssid[32];
	u8 macAddr[6];
	u8 data[2];
} WSC_IE_PROBREQ_DATA;

/*
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        true if all parameters are OK, false otherwise

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
bool MlmeAddBAReqSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pAddr2)
{
    PMLME_ADDBA_REQ_STRUCT   pInfo;

    pInfo = (MLME_ADDBA_REQ_STRUCT *)Msg;

    if ((MsgLen != sizeof(MLME_ADDBA_REQ_STRUCT)))
    {
        DBGPRINT(RT_DEBUG_TRACE, ("MlmeAddBAReqSanity fail - message lenght not correct.\n"));
        return false;
    }

    if ((pInfo->Wcid >= MAX_LEN_OF_MAC_TABLE))
    {
        DBGPRINT(RT_DEBUG_TRACE, ("MlmeAddBAReqSanity fail - The peer Mac is not associated yet.\n"));
        return false;
    }

	/*
    if ((pInfo->BaBufSize > MAX_RX_REORDERBUF) || (pInfo->BaBufSize < 2))
    {
        DBGPRINT(RT_DEBUG_TRACE, ("MlmeAddBAReqSanity fail - Rx Reordering buffer too big or too small\n"));
        return false;
    }
	*/

    if ((pInfo->pAddr[0]&0x01) == 0x01)
    {
        DBGPRINT(RT_DEBUG_TRACE, ("MlmeAddBAReqSanity fail - broadcast address not support BA\n"));
        return false;
    }

    return true;
}

/*
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        true if all parameters are OK, false otherwise

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
bool MlmeDelBAReqSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen)
{
	MLME_DELBA_REQ_STRUCT *pInfo;
	pInfo = (MLME_DELBA_REQ_STRUCT *)Msg;

    if ((MsgLen != sizeof(MLME_DELBA_REQ_STRUCT)))
    {
        DBGPRINT(RT_DEBUG_ERROR, ("MlmeDelBAReqSanity fail - message lenght not correct.\n"));
        return false;
    }

    if ((pInfo->Wcid >= MAX_LEN_OF_MAC_TABLE))
    {
        DBGPRINT(RT_DEBUG_ERROR, ("MlmeDelBAReqSanity fail - The peer Mac is not associated yet.\n"));
        return false;
    }

    if ((pInfo->TID & 0xf0))
    {
        DBGPRINT(RT_DEBUG_ERROR, ("MlmeDelBAReqSanity fail - The peer TID is incorrect.\n"));
        return false;
    }

	if (memcmp(pAd->MacTab.Content[pInfo->Wcid].Addr, pInfo->Addr, ETH_ALEN) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, ("MlmeDelBAReqSanity fail - the peer addr dosen't exist.\n"));
        return false;
    }

    return true;
}

bool PeerAddBAReqActionSanity(
    struct rtmp_adapter *pAd,
    void *pMsg,
    unsigned long MsgLen,
	u8 *pAddr2)
{
	PFRAME_802_11 pFrame = (PFRAME_802_11)pMsg;
	PFRAME_ADDBA_REQ pAddFrame;
	pAddFrame = (PFRAME_ADDBA_REQ)(pMsg);
	if (MsgLen < (sizeof(FRAME_ADDBA_REQ)))
	{
		DBGPRINT(RT_DEBUG_ERROR,("PeerAddBAReqActionSanity: ADDBA Request frame length size = %ld incorrect\n", MsgLen));
		return false;
	}
	/* we support immediate BA.*/
#ifdef UNALIGNMENT_SUPPORT
	{
		BA_PARM		tmpBaParm;

		memmove((u8 *)(&tmpBaParm), (u8 *)(&pAddFrame->BaParm), sizeof(BA_PARM));
		*(unsigned short *)(&tmpBaParm) = cpu2le16(*(unsigned short *)(&tmpBaParm));
		memmove((u8 *)(&pAddFrame->BaParm), (u8 *)(&tmpBaParm), sizeof(BA_PARM));
	}
#else
	*(unsigned short *)(&pAddFrame->BaParm) = cpu2le16(*(unsigned short *)(&pAddFrame->BaParm));
#endif
	pAddFrame->TimeOutValue = cpu2le16(pAddFrame->TimeOutValue);
	pAddFrame->BaStartSeq.word = cpu2le16(pAddFrame->BaStartSeq.word);

	memcpy(pAddr2, pFrame->Hdr.Addr2, ETH_ALEN);

	if (pAddFrame->BaParm.BAPolicy != IMMED_BA)
	{
		DBGPRINT(RT_DEBUG_ERROR,("PeerAddBAReqActionSanity: ADDBA Request Ba Policy[%d] not support\n", pAddFrame->BaParm.BAPolicy));
		DBGPRINT(RT_DEBUG_ERROR,("ADDBA Request. tid=%x, Bufsize=%x, AMSDUSupported=%x \n", pAddFrame->BaParm.TID, pAddFrame->BaParm.BufSize, pAddFrame->BaParm.AMSDUSupported));
		return false;
	}

	return true;
}

bool PeerAddBARspActionSanity(
    struct rtmp_adapter *pAd,
    void *pMsg,
    unsigned long MsgLen)
{
	/*PFRAME_802_11 pFrame = (PFRAME_802_11)pMsg;*/
	PFRAME_ADDBA_RSP pAddFrame;

	pAddFrame = (PFRAME_ADDBA_RSP)(pMsg);
	if (MsgLen < (sizeof(FRAME_ADDBA_RSP)))
	{
		DBGPRINT(RT_DEBUG_ERROR,("PeerAddBARspActionSanity: ADDBA Response frame length size = %ld incorrect\n", MsgLen));
		return false;
	}
	/* we support immediate BA.*/
#ifdef UNALIGNMENT_SUPPORT
	{
		BA_PARM		tmpBaParm;

		memmove((u8 *)(&tmpBaParm), (u8 *)(&pAddFrame->BaParm), sizeof(BA_PARM));
		*(unsigned short *)(&tmpBaParm) = cpu2le16(*(unsigned short *)(&tmpBaParm));
		memmove((u8 *)(&pAddFrame->BaParm), (u8 *)(&tmpBaParm), sizeof(BA_PARM));
	}
#else
	*(unsigned short *)(&pAddFrame->BaParm) = cpu2le16(*(unsigned short *)(&pAddFrame->BaParm));
#endif
	pAddFrame->StatusCode = cpu2le16(pAddFrame->StatusCode);
	pAddFrame->TimeOutValue = cpu2le16(pAddFrame->TimeOutValue);

	if (pAddFrame->BaParm.BAPolicy != IMMED_BA)
	{
		DBGPRINT(RT_DEBUG_ERROR,("PeerAddBAReqActionSanity: ADDBA Response Ba Policy[%d] not support\n", pAddFrame->BaParm.BAPolicy));
		return false;
	}

	return true;

}

bool PeerDelBAActionSanity(
    struct rtmp_adapter *pAd,
    u8 Wcid,
    void *pMsg,
    unsigned long MsgLen )
{
	/*PFRAME_802_11 pFrame = (PFRAME_802_11)pMsg;*/
	PFRAME_DELBA_REQ  pDelFrame;
	if (MsgLen != (sizeof(FRAME_DELBA_REQ)))
		return false;

	if (Wcid >= MAX_LEN_OF_MAC_TABLE)
		return false;

	pDelFrame = (PFRAME_DELBA_REQ)(pMsg);

	*(unsigned short *)(&pDelFrame->DelbaParm) = cpu2le16(*(unsigned short *)(&pDelFrame->DelbaParm));
	pDelFrame->ReasonCode = cpu2le16(pDelFrame->ReasonCode);

	return true;
}


bool PeerBeaconAndProbeRspSanity_Old(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8  MsgChannel,
    u8 *pAddr2,
    u8 *pBssid,
    CHAR Ssid[],
    u8 *pSsidLen,
    u8 *pBssType,
    unsigned short *pBeaconPeriod,
    u8 *pChannel,
    u8 *pNewChannel,
    LARGE_INTEGER *pTimestamp,
    CF_PARM *pCfParm,
    unsigned short *pAtimWin,
    unsigned short *pCapabilityInfo,
    u8 *pErp,
    u8 *pDtimCount,
    u8 *pDtimPeriod,
    u8 *pBcastFlag,
    u8 *pMessageToMe,
    u8 SupRate[],
    u8 *pSupRateLen,
    u8 ExtRate[],
    u8 *pExtRateLen,
    u8 *pCkipFlag,
    u8 *pAironetCellPowerLimit,
    PEDCA_PARM pEdcaParm,
    PQBSS_LOAD_PARM pQbssLoad,
    PQOS_CAPABILITY_PARM pQosCapability,
    unsigned long *pRalinkIe,
    u8 *pHtCapabilityLen,
#ifdef CONFIG_STA_SUPPORT
    u8 *pPreNHtCapabilityLen,
#endif /* CONFIG_STA_SUPPORT */
    HT_CAPABILITY_IE *pHtCapability,
    EXT_CAP_INFO_ELEMENT	*pExtCapInfo,
    u8 *AddHtInfoLen,
    ADD_HT_INFO_IE *AddHtInfo,
    u8 *NewExtChannelOffset,		/* Ht extension channel offset(above or below)*/
    unsigned short *LengthVIE,
    PNDIS_802_11_VARIABLE_IEs pVIE)
{
    u8 			*Ptr;
#ifdef CONFIG_STA_SUPPORT
	u8 				TimLen;
#endif /* CONFIG_STA_SUPPORT */
    PFRAME_802_11		pFrame;
    PEID_STRUCT         pEid;
    u8 			SubType;
    u8 			Sanity;
    /*u8 			ECWMin, ECWMax;*/
    /*MAC_CSR9_STRUC		Csr9;*/
    unsigned long				Length = 0;
	u8 			*pPeerWscIe = NULL;
	INT					PeerWscIeLen = 0;
    u8 			LatchRfChannel = 0;


	/*
		For some 11a AP which didn't have DS_IE, we use two conditions to decide the channel
		1. If the AP is 11n enabled, then check the control channel.
		2. If the AP didn't have any info about channel, use the channel we received this
			frame as the channel. (May inaccuracy!!)
	*/
	u8 		CtrlChannel = 0;

	/* ULLI : need check return value ? */

	pPeerWscIe = kmalloc(512, GFP_ATOMIC);
    /* Add for 3 necessary EID field check*/
    Sanity = 0;

    *pAtimWin = 0;
    *pErp = 0;
    *pDtimCount = 0;
    *pDtimPeriod = 0;
    *pBcastFlag = 0;
    *pMessageToMe = 0;
    *pExtRateLen = 0;
    *pCkipFlag = 0;			        /* Default of CkipFlag is 0*/
    *pAironetCellPowerLimit = 0xFF;  /* Default of AironetCellPowerLimit is 0xFF*/
    *LengthVIE = 0;					/* Set the length of VIE to init value 0*/
    *pHtCapabilityLen = 0;					/* Set the length of VIE to init value 0*/
#ifdef CONFIG_STA_SUPPORT
	if (pAd->OpMode == OPMODE_STA)
		*pPreNHtCapabilityLen = 0;					/* Set the length of VIE to init value 0*/
#endif /* CONFIG_STA_SUPPORT */
    *AddHtInfoLen = 0;					/* Set the length of VIE to init value 0*/
    memset(pExtCapInfo, 0, sizeof(EXT_CAP_INFO_ELEMENT));
    *pRalinkIe = 0;
    *pNewChannel = 0;
    *NewExtChannelOffset = 0xff;	/*Default 0xff means no such IE*/
    pCfParm->bValid = false;        /* default: no IE_CF found*/
    pQbssLoad->bValid = false;      /* default: no IE_QBSS_LOAD found*/
    pEdcaParm->bValid = false;      /* default: no IE_EDCA_PARAMETER found*/
    pQosCapability->bValid = false; /* default: no IE_QOS_CAPABILITY found*/

    pFrame = (PFRAME_802_11)Msg;

    /* get subtype from header*/
    SubType = (u8)pFrame->Hdr.FC.SubType;

    /* get Addr2 and BSSID from header*/
    memcpy(pAddr2, pFrame->Hdr.Addr2, ETH_ALEN);
    memcpy(pBssid, pFrame->Hdr.Addr3, ETH_ALEN);

    Ptr = pFrame->Octet;
    Length += LENGTH_802_11;

    /* get timestamp from payload and advance the pointer*/
    memmove(pTimestamp, Ptr, TIMESTAMP_LEN);

	pTimestamp->u.LowPart = cpu2le32(pTimestamp->u.LowPart);
	pTimestamp->u.HighPart = cpu2le32(pTimestamp->u.HighPart);

    Ptr += TIMESTAMP_LEN;
    Length += TIMESTAMP_LEN;

    /* get beacon interval from payload and advance the pointer*/
    memmove(pBeaconPeriod, Ptr, 2);
    Ptr += 2;
    Length += 2;

    /* get capability info from payload and advance the pointer*/
    memmove(pCapabilityInfo, Ptr, 2);
    Ptr += 2;
    Length += 2;

    if (CAP_IS_ESS_ON(*pCapabilityInfo))
        *pBssType = BSS_INFRA;
    else
        *pBssType = BSS_ADHOC;

    pEid = (PEID_STRUCT) Ptr;

    /* get variable fields from payload and advance the pointer*/
    while ((Length + 2 + pEid->Len) <= MsgLen)
    {

        /* Secure copy VIE to VarIE[MAX_VIE_LEN] didn't overflow.*/
        if ((*LengthVIE + pEid->Len + 2) >= MAX_VIE_LEN)
        {
            DBGPRINT(RT_DEBUG_WARN, ("%s() - Variable IEs out of resource [len(=%d) > MAX_VIE_LEN(=%d)]\n",
                    __FUNCTION__, (*LengthVIE + pEid->Len + 2), MAX_VIE_LEN));
            break;
        }

        switch(pEid->Eid)
        {
            case IE_SSID:
                /* Already has one SSID EID in this beacon, ignore the second one*/
                if (Sanity & 0x1)
                    break;
                if(pEid->Len <= MAX_LEN_OF_SSID)
                {
                    memmove(Ssid, pEid->Octet, pEid->Len);
                    *pSsidLen = pEid->Len;
                    Sanity |= 0x1;
                }
                else
                {
                    DBGPRINT(RT_DEBUG_TRACE, ("%s() - wrong IE_SSID (len=%d)\n", __FUNCTION__, pEid->Len));
                    goto SanityCheck;
                }
                break;

            case IE_SUPP_RATES:
                if(pEid->Len <= MAX_LEN_OF_SUPPORTED_RATES)
                {
                    Sanity |= 0x2;
                    memmove(SupRate, pEid->Octet, pEid->Len);
                    *pSupRateLen = pEid->Len;

                    /*
						TODO: 2004-09-14 not a good design here, cause it exclude extra
							rates from ScanTab. We should report as is. And filter out
							unsupported rates in MlmeAux
					*/
                    /* Check against the supported rates*/
                    /* RTMPCheckRates(pAd, SupRate, pSupRateLen);*/
                }
                else
                {
                    DBGPRINT(RT_DEBUG_TRACE, ("%s() - wrong IE_SUPP_RATES (len=%d)\n",__FUNCTION__, pEid->Len));
                    goto SanityCheck;
                }
                break;

            case IE_HT_CAP:
			if (pEid->Len >= SIZE_HT_CAP_IE)  /*Note: allow extension.!!*/
			{
				memmove(pHtCapability, pEid->Octet, sizeof(HT_CAPABILITY_IE));
				*pHtCapabilityLen = SIZE_HT_CAP_IE;	/* Nnow we only support 26 bytes.*/

				*(unsigned short *)(&pHtCapability->HtCapInfo) = cpu2le16(*(unsigned short *)(&pHtCapability->HtCapInfo));
#ifdef UNALIGNMENT_SUPPORT
				{
					EXT_HT_CAP_INFO extHtCapInfo;
					memmove((u8 *)(&extHtCapInfo), (u8 *)(&pHtCapability->ExtHtCapInfo), sizeof(EXT_HT_CAP_INFO));
					*(unsigned short *)(&extHtCapInfo) = cpu2le16(*(unsigned short *)(&extHtCapInfo));
					memmove((u8 *)(&pHtCapability->ExtHtCapInfo), (u8 *)(&extHtCapInfo), sizeof(EXT_HT_CAP_INFO));
				}
#else
				*(unsigned short *)(&pHtCapability->ExtHtCapInfo) = cpu2le16(*(unsigned short *)(&pHtCapability->ExtHtCapInfo));
#endif /* UNALIGNMENT_SUPPORT */

#ifdef CONFIG_STA_SUPPORT
				IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
				{
					*pPreNHtCapabilityLen = 0;	/* Now we only support 26 bytes.*/

					Ptr = (u8 *) pVIE;
					memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
					*LengthVIE += (pEid->Len + 2);
				}
#endif /* CONFIG_STA_SUPPORT */
			}
			else
			{
				DBGPRINT(RT_DEBUG_WARN, ("%s() - wrong IE_HT_CAP. pEid->Len = %d\n", __FUNCTION__, pEid->Len));
			}

		break;
            case IE_ADD_HT:
			if (pEid->Len >= sizeof(ADD_HT_INFO_IE))
			{
				/*
					This IE allows extension, but we can ignore extra bytes beyond our
					knowledge , so only copy first sizeof(ADD_HT_INFO_IE)
				*/
				memmove(AddHtInfo, pEid->Octet, sizeof(ADD_HT_INFO_IE));
				*AddHtInfoLen = SIZE_ADD_HT_INFO_IE;

				CtrlChannel = AddHtInfo->ControlChan;

				*(unsigned short *)(&AddHtInfo->AddHtInfo2) = cpu2le16(*(unsigned short *)(&AddHtInfo->AddHtInfo2));
				*(unsigned short *)(&AddHtInfo->AddHtInfo3) = cpu2le16(*(unsigned short *)(&AddHtInfo->AddHtInfo3));

#ifdef CONFIG_STA_SUPPORT
				IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
				{
			                Ptr = (u8 *) pVIE;
			                memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
			                *LengthVIE += (pEid->Len + 2);
				}
#endif /* CONFIG_STA_SUPPORT */
			}
			else
			{
				DBGPRINT(RT_DEBUG_WARN, ("%s() - wrong IE_ADD_HT. \n", __FUNCTION__));
			}

		break;
            case IE_SECONDARY_CH_OFFSET:
			if (pEid->Len == 1)
			{
				*NewExtChannelOffset = pEid->Octet[0];
			}
			else
			{
				DBGPRINT(RT_DEBUG_WARN, ("%s() - wrong IE_SECONDARY_CH_OFFSET. \n", __FUNCTION__));
			}

		break;
            case IE_FH_PARM:
                DBGPRINT(RT_DEBUG_TRACE, ("%s(IE_FH_PARM) \n", __FUNCTION__));
                break;

            case IE_DS_PARM:
                if(pEid->Len == 1)
                {
                    *pChannel = *pEid->Octet;
#ifdef CONFIG_STA_SUPPORT
					IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
					{
						if (ChannelSanity(pAd, *pChannel) == 0)
						{

							goto SanityCheck;
						}
					}
#endif /* CONFIG_STA_SUPPORT */
                    Sanity |= 0x4;
                }
                else
                {
                    DBGPRINT(RT_DEBUG_TRACE, ("%s() - wrong IE_DS_PARM (len=%d)\n",__FUNCTION__,pEid->Len));
                    goto SanityCheck;
                }
                break;

            case IE_CF_PARM:
                if(pEid->Len == 6)
                {
                    pCfParm->bValid = true;
                    pCfParm->CfpCount = pEid->Octet[0];
                    pCfParm->CfpPeriod = pEid->Octet[1];
                    pCfParm->CfpMaxDuration = pEid->Octet[2] + 256 * pEid->Octet[3];
                    pCfParm->CfpDurRemaining = pEid->Octet[4] + 256 * pEid->Octet[5];
                }
                else
                {
                    DBGPRINT(RT_DEBUG_TRACE, ("%s() - wrong IE_CF_PARM\n", __FUNCTION__));
					if (pPeerWscIe)
						kfree(pPeerWscIe);
                    return false;
                }
                break;

            case IE_IBSS_PARM:
                if(pEid->Len == 2)
                {
                    memmove(pAtimWin, pEid->Octet, pEid->Len);
                }
                else
                {
                    DBGPRINT(RT_DEBUG_TRACE, ("%s() - wrong IE_IBSS_PARM\n", __FUNCTION__));
					if (pPeerWscIe)
						kfree(pPeerWscIe);
                    return false;
                }
                break;

#ifdef CONFIG_STA_SUPPORT
            case IE_TIM:
                if(SubType == SUBTYPE_BEACON)
                {
					if (INFRA_ON(pAd) && memcmp(pBssid, pAd->CommonCfg.Bssid, ETH_ALEN) == 0)
                    {
                        GetTimBit((char *)pEid, pAd->StaActive.Aid, &TimLen, pBcastFlag, pDtimCount, pDtimPeriod, pMessageToMe);
                    }
                }
                break;
#endif /* CONFIG_STA_SUPPORT */
            case IE_CHANNEL_SWITCH_ANNOUNCEMENT:
                if(pEid->Len == 3)
                {
                	*pNewChannel = pEid->Octet[1];	/*extract new channel number*/
                }
                break;

            /*
				New for WPA
				CCX v2 has the same IE, we need to parse that too
				Wifi WMM use the same IE vale, need to parse that too
			*/
            /* case IE_WPA:*/
            case IE_VENDOR_SPECIFIC:
                /* Check the OUI version, filter out non-standard usage*/
                if (memcmp(pEid->Octet, RALINK_OUI, 3) == 0 && (pEid->Len == 7))
                {
			if (pEid->Octet[3] != 0)
        				*pRalinkIe = pEid->Octet[3];
        			else
        				*pRalinkIe = 0xf0000000; /* Set to non-zero value (can't set bit0-2) to represent this is Ralink Chip. So at linkup, we will set ralinkchip flag.*/
                }
#ifdef CONFIG_STA_SUPPORT
#ifdef DOT11_N_SUPPORT
		/* This HT IE is before IEEE draft set HT IE value.2006-09-28 by Jan.*/

                /* Other vendors had production before IE_HT_CAP value is assigned. To backward support those old-firmware AP,*/
                /* Check broadcom-defiend pre-802.11nD1.0 OUI for HT related IE, including HT Capatilities IE and HT Information IE*/
                else if ((*pHtCapabilityLen == 0) && memcmp(pEid->Octet, PRE_N_HT_OUI, 3) == 0 &&
			 (pEid->Len >= 4) && (pAd->OpMode == OPMODE_STA))
                {
                    if ((pEid->Octet[3] == OUI_PREN_HT_CAP) && (pEid->Len >= 30) && (*pHtCapabilityLen == 0))
                    {
                        memmove(pHtCapability, &pEid->Octet[4], sizeof(HT_CAPABILITY_IE));
                        *pPreNHtCapabilityLen = SIZE_HT_CAP_IE;
                    }

                    if ((pEid->Octet[3] == OUI_PREN_ADD_HT) && (pEid->Len >= 26))
                    {
                        memmove(AddHtInfo, &pEid->Octet[4], sizeof(ADD_HT_INFO_IE));
                        *AddHtInfoLen = SIZE_ADD_HT_INFO_IE;
                    }
                }
#endif /* DOT11_N_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */
                else if (memcmp(pEid->Octet, WPA_OUI, 4) == 0)
                {
                    /* Copy to pVIE which will report to bssid list.*/
                    Ptr = (u8 *) pVIE;
                    memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
                    *LengthVIE += (pEid->Len + 2);
                }
                else if (memcmp(pEid->Octet, WME_PARM_ELEM, 6) == 0 && (pEid->Len == 24))
                {
                    u8 *ptr;
                    int i;

                    /* parsing EDCA parameters*/
                    pEdcaParm->bValid          = true;
                    pEdcaParm->bQAck           = false; /* pEid->Octet[0] & 0x10;*/
                    pEdcaParm->bQueueRequest   = false; /* pEid->Octet[0] & 0x20;*/
                    pEdcaParm->bTxopRequest    = false; /* pEid->Octet[0] & 0x40;*/
                    pEdcaParm->EdcaUpdateCount = pEid->Octet[6] & 0x0f;
                    pEdcaParm->bAPSDCapable    = (pEid->Octet[6] & 0x80) ? 1 : 0;
                    ptr = &pEid->Octet[8];
                    for (i=0; i<4; i++)
                    {
                        u8 aci = (*ptr & 0x60) >> 5; /* b5~6 is AC INDEX*/
                        pEdcaParm->bACM[aci]  = (((*ptr) & 0x10) == 0x10);   /* b5 is ACM*/
                        pEdcaParm->Aifsn[aci] = (*ptr) & 0x0f;               /* b0~3 is AIFSN*/
                        pEdcaParm->Cwmin[aci] = *(ptr+1) & 0x0f;             /* b0~4 is Cwmin*/
                        pEdcaParm->Cwmax[aci] = *(ptr+1) >> 4;               /* b5~8 is Cwmax*/
                        pEdcaParm->Txop[aci]  = *(ptr+2) + 256 * (*(ptr+3)); /* in unit of 32-us*/
                        ptr += 4; /* point to next AC*/
                    }
                }
                else if (memcmp(pEid->Octet, WME_INFO_ELEM, 6) == 0 && (pEid->Len == 7))
                {
                    /* parsing EDCA parameters*/
                    pEdcaParm->bValid          = true;
                    pEdcaParm->bQAck           = false; /* pEid->Octet[0] & 0x10;*/
                    pEdcaParm->bQueueRequest   = false; /* pEid->Octet[0] & 0x20;*/
                    pEdcaParm->bTxopRequest    = false; /* pEid->Octet[0] & 0x40;*/
                    pEdcaParm->EdcaUpdateCount = pEid->Octet[6] & 0x0f;
                    pEdcaParm->bAPSDCapable    = (pEid->Octet[6] & 0x80) ? 1 : 0;

                    /* use default EDCA parameter*/
                    pEdcaParm->bACM[QID_AC_BE]  = 0;
                    pEdcaParm->Aifsn[QID_AC_BE] = 3;
                    pEdcaParm->Cwmin[QID_AC_BE] = CW_MIN_IN_BITS;
                    pEdcaParm->Cwmax[QID_AC_BE] = CW_MAX_IN_BITS;
                    pEdcaParm->Txop[QID_AC_BE]  = 0;

                    pEdcaParm->bACM[QID_AC_BK]  = 0;
                    pEdcaParm->Aifsn[QID_AC_BK] = 7;
                    pEdcaParm->Cwmin[QID_AC_BK] = CW_MIN_IN_BITS;
                    pEdcaParm->Cwmax[QID_AC_BK] = CW_MAX_IN_BITS;
                    pEdcaParm->Txop[QID_AC_BK]  = 0;

                    pEdcaParm->bACM[QID_AC_VI]  = 0;
                    pEdcaParm->Aifsn[QID_AC_VI] = 2;
                    pEdcaParm->Cwmin[QID_AC_VI] = CW_MIN_IN_BITS-1;
                    pEdcaParm->Cwmax[QID_AC_VI] = CW_MAX_IN_BITS;
                    pEdcaParm->Txop[QID_AC_VI]  = 96;   /* AC_VI: 96*32us ~= 3ms*/

                    pEdcaParm->bACM[QID_AC_VO]  = 0;
                    pEdcaParm->Aifsn[QID_AC_VO] = 2;
                    pEdcaParm->Cwmin[QID_AC_VO] = CW_MIN_IN_BITS-2;
                    pEdcaParm->Cwmax[QID_AC_VO] = CW_MAX_IN_BITS-1;
                    pEdcaParm->Txop[QID_AC_VO]  = 48;   /* AC_VO: 48*32us ~= 1.5ms*/
                }
				else if (memcmp(pEid->Octet, WPS_OUI, 4) == 0)
                {
					if (PeerWscIeLen >= 512)
						DBGPRINT(RT_DEBUG_ERROR, ("%s: PeerWscIeLen = %d (>= 512)\n", __FUNCTION__, PeerWscIeLen));
					if (pPeerWscIe && (PeerWscIeLen < 512))
					{
						memmove(pPeerWscIe+PeerWscIeLen, pEid->Octet+4, pEid->Len-4);
						PeerWscIeLen += (pEid->Len - 4);
					}



                }


                break;

            case IE_EXT_SUPP_RATES:
                if (pEid->Len <= MAX_LEN_OF_SUPPORTED_RATES)
                {
                    memmove(ExtRate, pEid->Octet, pEid->Len);
                    *pExtRateLen = pEid->Len;

                    /*
						TODO: 2004-09-14 not a good design here, cause it exclude extra rates
								from ScanTab. We should report as is. And filter out unsupported
								rates in MlmeAux
					*/
                    /* Check against the supported rates*/
                    /* RTMPCheckRates(pAd, ExtRate, pExtRateLen);*/
                }
                break;

            case IE_ERP:
                if (pEid->Len == 1)
                {
                    *pErp = (u8)pEid->Octet[0];
                }
                break;

            case IE_AIRONET_CKIP:
                /*
					0. Check Aironet IE length, it must be larger or equal to 28
						Cisco AP350 used length as 28
						Cisco AP12XX used length as 30
				*/
                if (pEid->Len < (CKIP_NEGOTIATION_LENGTH - 2))
                    break;

                /* 1. Copy CKIP flag byte to buffer for process*/
                *pCkipFlag = *(pEid->Octet + 8);
                break;

            case IE_AP_TX_POWER:
                /* AP Control of Client Transmit Power*/
                /*0. Check Aironet IE length, it must be 6*/
                if (pEid->Len != 0x06)
                    break;

                /* Get cell power limit in dBm*/
                if (memcmp(pEid->Octet, CISCO_OUI, 3) == 0)
                    *pAironetCellPowerLimit = *(pEid->Octet + 4);
                break;

            /* WPA2 & 802.11i RSN*/
            case IE_RSN:
                /* There is no OUI for version anymore, check the group cipher OUI before copying*/
                if (memcmp(pEid->Octet + 2, RSN_OUI, 3) == 0)
                {
                    /* Copy to pVIE which will report to microsoft bssid list.*/
                    Ptr = (u8 *) pVIE;
                    memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
                    *LengthVIE += (pEid->Len + 2);
                }
                break;

#ifdef CONFIG_STA_SUPPORT
#if defined (EXT_BUILD_CHANNEL_LIST) || defined (RT_CFG80211_SUPPORT)
			case IE_COUNTRY:
				Ptr = (u8 *) pVIE;
                memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
                *LengthVIE += (pEid->Len + 2);
				break;
#endif /* EXT_BUILD_CHANNEL_LIST */
#endif /* CONFIG_STA_SUPPORT */

            case IE_QBSS_LOAD:
                if (pEid->Len == 5)
                {
                    pQbssLoad->bValid = true;
                    pQbssLoad->StaNum = pEid->Octet[0] + pEid->Octet[1] * 256;
                    pQbssLoad->ChannelUtilization = pEid->Octet[2];
                    pQbssLoad->RemainingAdmissionControl = pEid->Octet[3] + pEid->Octet[4] * 256;

					/* Copy to pVIE*/
                    Ptr = (u8 *) pVIE;
                    memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
                    *LengthVIE += (pEid->Len + 2);
                }
                break;



			case IE_EXT_CAPABILITY:
				if (pEid->Len >= 1)
				{
					u8 MaxSize;
					u8 MySize = sizeof(EXT_CAP_INFO_ELEMENT);

					MaxSize = min(pEid->Len, MySize);

					memmove(pExtCapInfo,&pEid->Octet[0], MaxSize);
				}
				break;
            default:
                break;
        }

        Length = Length + 2 + pEid->Len;  /* Eid[1] + Len[1]+ content[Len]*/
        pEid = (PEID_STRUCT)((u8 *)pEid + 2 + pEid->Len);
    }

	LatchRfChannel = MsgChannel;

		if ((pAd->LatchRfRegs.Channel > 14) && ((Sanity & 0x4) == 0))
		{
			if (CtrlChannel != 0)
				*pChannel = CtrlChannel;
			else
				*pChannel = LatchRfChannel;
			Sanity |= 0x4;
		}

		if (pPeerWscIe && (PeerWscIeLen > 0) && (PeerWscIeLen < 512))
		{
			u8 WscIe[] = {0xdd, 0x00, 0x00, 0x50, 0xF2, 0x04};
			Ptr = (u8 *) pVIE;
			WscIe[1] = PeerWscIeLen + 4;
			memmove(Ptr + *LengthVIE, WscIe, 6);
			memmove(Ptr + *LengthVIE + 6, pPeerWscIe, PeerWscIeLen);
			*LengthVIE += (PeerWscIeLen + 6);
		}


SanityCheck:
	if (pPeerWscIe)
		kfree(pPeerWscIe);

	if (Sanity != 0x7)
	{
		DBGPRINT(RT_DEBUG_LOUD, ("%s() - missing field, Sanity=0x%02x\n", __FUNCTION__, Sanity));
		return false;
	}
	else
	{
		return true;
	}

}


/*
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        true if all parameters are OK, false otherwise

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
bool PeerBeaconAndProbeRspSanity(
	struct rtmp_adapter *pAd,
	void *Msg,
	unsigned long MsgLen,
	u8  MsgChannel,
	BCN_IE_LIST *ie_list,
	unsigned short *LengthVIE,
	PNDIS_802_11_VARIABLE_IEs pVIE)
{
	u8 *Ptr;
#ifdef CONFIG_STA_SUPPORT
	u8 TimLen;
#endif /* CONFIG_STA_SUPPORT */
	PFRAME_802_11 pFrame;
	PEID_STRUCT pEid;
	u8 SubType;
	u8 Sanity;
	unsigned long Length = 0;
	u8 *pPeerWscIe = NULL;
	INT PeerWscIeLen = 0;
	u8 LatchRfChannel = 0;


	/*
		For some 11a AP which didn't have DS_IE, we use two conditions to decide the channel
		1. If the AP is 11n enabled, then check the control channel.
		2. If the AP didn't have any info about channel, use the channel we received this
			frame as the channel. (May inaccuracy!!)
	*/
	u8 CtrlChannel = 0;


	/* ULLI : need check return value ? */

	pPeerWscIe = kmalloc(512, GFP_ATOMIC);
	Sanity = 0;		/* Add for 3 necessary EID field check*/

	ie_list->AironetCellPowerLimit = 0xFF;  /* Default of AironetCellPowerLimit is 0xFF*/
	ie_list->NewExtChannelOffset = 0xff;	/*Default 0xff means no such IE*/
	*LengthVIE = 0; /* Set the length of VIE to init value 0*/

	pFrame = (PFRAME_802_11)Msg;

	/* get subtype from header*/
	SubType = (u8)pFrame->Hdr.FC.SubType;

    /* get Addr2 and BSSID from header*/
	memcpy(&ie_list->Addr1[0], pFrame->Hdr.Addr1, ETH_ALEN);
	memcpy(&ie_list->Addr2[0], pFrame->Hdr.Addr2, ETH_ALEN);
	memcpy(&ie_list->Bssid[0], pFrame->Hdr.Addr3, ETH_ALEN);

    Ptr = pFrame->Octet;
    Length += LENGTH_802_11;

    /* get timestamp from payload and advance the pointer*/
    memmove(&ie_list->TimeStamp, Ptr, TIMESTAMP_LEN);

	ie_list->TimeStamp.u.LowPart = cpu2le32(ie_list->TimeStamp.u.LowPart);
	ie_list->TimeStamp.u.HighPart = cpu2le32(ie_list->TimeStamp.u.HighPart);

    Ptr += TIMESTAMP_LEN;
    Length += TIMESTAMP_LEN;

    /* get beacon interval from payload and advance the pointer*/
    memmove(&ie_list->BeaconPeriod, Ptr, 2);
    Ptr += 2;
    Length += 2;

    /* get capability info from payload and advance the pointer*/
    memmove(&ie_list->CapabilityInfo, Ptr, 2);
    Ptr += 2;
    Length += 2;

    if (CAP_IS_ESS_ON(ie_list->CapabilityInfo))
        ie_list->BssType = BSS_INFRA;
    else
        ie_list->BssType = BSS_ADHOC;

    pEid = (PEID_STRUCT) Ptr;

    /* get variable fields from payload and advance the pointer*/
    while ((Length + 2 + pEid->Len) <= MsgLen)
    {

        /* Secure copy VIE to VarIE[MAX_VIE_LEN] didn't overflow.*/
        if ((*LengthVIE + pEid->Len + 2) >= MAX_VIE_LEN)
        {
            DBGPRINT(RT_DEBUG_WARN, ("%s() - Variable IEs out of resource [len(=%d) > MAX_VIE_LEN(=%d)]\n",
                    __FUNCTION__, (*LengthVIE + pEid->Len + 2), MAX_VIE_LEN));
            break;
        }

        switch(pEid->Eid)
	{
		case IE_SSID:
			/* Already has one SSID EID in this beacon, ignore the second one*/
			if (Sanity & 0x1)
				break;
			if(pEid->Len <= MAX_LEN_OF_SSID)
			{
				memmove(&ie_list->Ssid[0], pEid->Octet, pEid->Len);
				ie_list->SsidLen = pEid->Len;
				Sanity |= 0x1;
			}
			else
			{
				DBGPRINT(RT_DEBUG_TRACE, ("%s() - wrong IE_SSID (len=%d)\n",__FUNCTION__,pEid->Len));
				goto SanityCheck;
			}
			break;

		case IE_SUPP_RATES:
			if(pEid->Len <= MAX_LEN_OF_SUPPORTED_RATES)
			{
				Sanity |= 0x2;
				memmove(&ie_list->SupRate[0], pEid->Octet, pEid->Len);
				ie_list->SupRateLen = pEid->Len;

				/*
				TODO: 2004-09-14 not a good design here, cause it exclude extra
				rates from ScanTab. We should report as is. And filter out
				unsupported rates in MlmeAux
				*/
				/* Check against the supported rates*/
				/* RTMPCheckRates(pAd, SupRate, pSupRateLen);*/
			}
			else
			{
				DBGPRINT(RT_DEBUG_TRACE, ("%s() - wrong IE_SUPP_RATES (len=%d)\n",__FUNCTION__,pEid->Len));
				goto SanityCheck;
			}
			break;

		case IE_HT_CAP:
			if (pEid->Len >= SIZE_HT_CAP_IE)  /*Note: allow extension.!!*/
			{
				memmove(&ie_list->HtCapability, pEid->Octet, sizeof(HT_CAPABILITY_IE));
				ie_list->HtCapabilityLen = SIZE_HT_CAP_IE;	/* Nnow we only support 26 bytes.*/

				*(unsigned short *)(&ie_list->HtCapability.HtCapInfo) = cpu2le16(*(unsigned short *)(&ie_list->HtCapability.HtCapInfo));
#ifdef UNALIGNMENT_SUPPORT
				{
					EXT_HT_CAP_INFO extHtCapInfo;
					memmove((u8 *)(&extHtCapInfo), (u8 *)(&ie_list->HtCapability.ExtHtCapInfo), sizeof(EXT_HT_CAP_INFO));
					*(unsigned short *)(&extHtCapInfo) = cpu2le16(*(unsigned short *)(&extHtCapInfo));
					memmove((u8 *)(&ie_list->HtCapability.ExtHtCapInfo), (u8 *)(&extHtCapInfo), sizeof(EXT_HT_CAP_INFO));
				}
#else
				*(unsigned short *)(&ie_list->HtCapability.ExtHtCapInfo) = cpu2le16(*(unsigned short *)(&ie_list->HtCapability.ExtHtCapInfo));
#endif /* UNALIGNMENT_SUPPORT */

#ifdef CONFIG_STA_SUPPORT
				IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
				{
					ie_list->PreNHtCapabilityLen = 0;	/* Now we only support 26 bytes.*/

					Ptr = (u8 *) pVIE;
					memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
					*LengthVIE += (pEid->Len + 2);
				}
#endif /* CONFIG_STA_SUPPORT */
			}
			else
			{
				DBGPRINT(RT_DEBUG_WARN, ("%s() - wrong IE_HT_CAP. pEid->Len = %d\n", __FUNCTION__, pEid->Len));
			}

			break;
		case IE_ADD_HT:
			if (pEid->Len >= sizeof(ADD_HT_INFO_IE))
			{
				/*
				This IE allows extension, but we can ignore extra bytes beyond our
				knowledge , so only copy first sizeof(ADD_HT_INFO_IE)
				*/
				memmove(&ie_list->AddHtInfo, pEid->Octet, sizeof(ADD_HT_INFO_IE));
				ie_list->AddHtInfoLen = SIZE_ADD_HT_INFO_IE;

				CtrlChannel = ie_list->AddHtInfo.ControlChan;

				*(unsigned short *)(&ie_list->AddHtInfo.AddHtInfo2) = cpu2le16(*(unsigned short *)(&ie_list->AddHtInfo.AddHtInfo2));
				*(unsigned short *)(&ie_list->AddHtInfo.AddHtInfo3) = cpu2le16(*(unsigned short *)(&ie_list->AddHtInfo.AddHtInfo3));

#ifdef CONFIG_STA_SUPPORT
				IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
				{
					Ptr = (u8 *) pVIE;
					memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
					*LengthVIE += (pEid->Len + 2);
				}
#endif /* CONFIG_STA_SUPPORT */
			}
			else
			{
				DBGPRINT(RT_DEBUG_WARN, ("%s() - wrong IE_ADD_HT. \n", __FUNCTION__));
			}

			break;
		case IE_SECONDARY_CH_OFFSET:
			if (pEid->Len == 1)
				ie_list->NewExtChannelOffset = pEid->Octet[0];
			else
			{
				DBGPRINT(RT_DEBUG_WARN, ("%s() - wrong IE_SECONDARY_CH_OFFSET. \n", __FUNCTION__));
			}
			break;

		case IE_FH_PARM:
			DBGPRINT(RT_DEBUG_TRACE, ("%s(IE_FH_PARM) \n", __FUNCTION__));
			break;

		case IE_DS_PARM:
			if(pEid->Len == 1)
			{
				ie_list->Channel = *pEid->Octet;
#ifdef CONFIG_STA_SUPPORT
				IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
				{
					if (ChannelSanity(pAd, ie_list->Channel) == 0)
					{
						goto SanityCheck;
					}
				}
#endif /* CONFIG_STA_SUPPORT */
				Sanity |= 0x4;
			}
			else
			{
				DBGPRINT(RT_DEBUG_TRACE, ("%s() - wrong IE_DS_PARM (len=%d)\n",__FUNCTION__,pEid->Len));
				goto SanityCheck;
			}
			break;

		case IE_CF_PARM:
			if(pEid->Len == 6)
			{
				ie_list->CfParm.bValid = true;
				ie_list->CfParm.CfpCount = pEid->Octet[0];
				ie_list->CfParm.CfpPeriod = pEid->Octet[1];
				ie_list->CfParm.CfpMaxDuration = pEid->Octet[2] + 256 * pEid->Octet[3];
				ie_list->CfParm.CfpDurRemaining = pEid->Octet[4] + 256 * pEid->Octet[5];
			}
			else
			{
				DBGPRINT(RT_DEBUG_TRACE, ("%s() - wrong IE_CF_PARM\n", __FUNCTION__));
				if (pPeerWscIe)
					kfree(pPeerWscIe);
				return false;
			}
			break;

		case IE_IBSS_PARM:
			if(pEid->Len == 2)
			{
				memmove(&ie_list->AtimWin, pEid->Octet, pEid->Len);
			}
			else
			{
				DBGPRINT(RT_DEBUG_TRACE, ("%s() - wrong IE_IBSS_PARM\n", __FUNCTION__));
				if (pPeerWscIe)
					kfree(pPeerWscIe);
				return false;
			}
			break;

#ifdef CONFIG_STA_SUPPORT
		case IE_TIM:
			if(SubType == SUBTYPE_BEACON)
			{
				if (INFRA_ON(pAd) &&
				    memcmp(&ie_list->Bssid[0], pAd->CommonCfg.Bssid, ETH_ALEN) == 0)
				{
					GetTimBit((char *)pEid, pAd->StaActive.Aid, &TimLen, &ie_list->BcastFlag,
					&ie_list->DtimCount, &ie_list->DtimPeriod, &ie_list->MessageToMe);
				}
			}
			break;
#endif /* CONFIG_STA_SUPPORT */
		case IE_CHANNEL_SWITCH_ANNOUNCEMENT:
			if(pEid->Len == 3)
				ie_list->NewChannel = pEid->Octet[1];	/*extract new channel number*/
			break;

			/*
			New for WPA
			CCX v2 has the same IE, we need to parse that too
			Wifi WMM use the same IE vale, need to parse that too
			*/
		/* case IE_WPA:*/
		case IE_VENDOR_SPECIFIC:
			/* Check the OUI version, filter out non-standard usage*/
			if (memcmp(pEid->Octet, RALINK_OUI, 3) == 0 && (pEid->Len == 7))
			{
				if (pEid->Octet[3] != 0)
					ie_list->RalinkIe = pEid->Octet[3];
				else
					ie_list->RalinkIe = 0xf0000000; /* Set to non-zero value (can't set bit0-2) to represent this is Ralink Chip. So at linkup, we will set ralinkchip flag.*/
			}
#ifdef CONFIG_STA_SUPPORT
#ifdef DOT11_N_SUPPORT
			/* This HT IE is before IEEE draft set HT IE value.2006-09-28 by Jan.*/

			/* Other vendors had production before IE_HT_CAP value is assigned. To backward support those old-firmware AP,*/
			/* Check broadcom-defiend pre-802.11nD1.0 OUI for HT related IE, including HT Capatilities IE and HT Information IE*/
			else if ((ie_list->HtCapabilityLen == 0) &&
			         memcmp(pEid->Octet, PRE_N_HT_OUI, 3) == 0 && (pEid->Len >= 4) == 0 &&
				 (pAd->OpMode == OPMODE_STA))
			{
				if ((pEid->Octet[3] == OUI_PREN_HT_CAP) && (pEid->Len >= 30) && (ie_list->HtCapabilityLen == 0))
				{
					memmove(&ie_list->HtCapability, &pEid->Octet[4], sizeof(HT_CAPABILITY_IE));
					ie_list->PreNHtCapabilityLen = SIZE_HT_CAP_IE;
				}

				if ((pEid->Octet[3] == OUI_PREN_ADD_HT) && (pEid->Len >= 26))
				{
					memmove(&ie_list->AddHtInfo, &pEid->Octet[4], sizeof(ADD_HT_INFO_IE));
					ie_list->AddHtInfoLen = SIZE_ADD_HT_INFO_IE;
				}
			}
#endif /* DOT11_N_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */
			else if (memcmp(pEid->Octet, WPA_OUI, 4) == 0)
			{
				/* Copy to pVIE which will report to bssid list.*/
				Ptr = (u8 *) pVIE;
				memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
				*LengthVIE += (pEid->Len + 2);
			}
			else if (memcmp(pEid->Octet, WME_PARM_ELEM, 6) == 0 && (pEid->Len == 24))
			{
				u8 *ptr;
				int i;

				/* parsing EDCA parameters*/
				ie_list->EdcaParm.bValid          = true;
				ie_list->EdcaParm.bQAck           = false; /* pEid->Octet[0] & 0x10;*/
				ie_list->EdcaParm.bQueueRequest   = false; /* pEid->Octet[0] & 0x20;*/
				ie_list->EdcaParm.bTxopRequest    = false; /* pEid->Octet[0] & 0x40;*/
				ie_list->EdcaParm.EdcaUpdateCount = pEid->Octet[6] & 0x0f;
				ie_list->EdcaParm.bAPSDCapable    = (pEid->Octet[6] & 0x80) ? 1 : 0;
				ptr = &pEid->Octet[8];
				for (i=0; i<4; i++)
				{
					u8 aci = (*ptr & 0x60) >> 5; /* b5~6 is AC INDEX*/
					ie_list->EdcaParm.bACM[aci]  = (((*ptr) & 0x10) == 0x10);   /* b5 is ACM*/
					ie_list->EdcaParm.Aifsn[aci] = (*ptr) & 0x0f;               /* b0~3 is AIFSN*/
					ie_list->EdcaParm.Cwmin[aci] = *(ptr+1) & 0x0f;             /* b0~4 is Cwmin*/
					ie_list->EdcaParm.Cwmax[aci] = *(ptr+1) >> 4;               /* b5~8 is Cwmax*/
					ie_list->EdcaParm.Txop[aci]  = *(ptr+2) + 256 * (*(ptr+3)); /* in unit of 32-us*/
					ptr += 4; /* point to next AC*/
				}
			}
			else if (memcmp(pEid->Octet, WME_INFO_ELEM, 6) == 0 && (pEid->Len == 7))
			{
				/* parsing EDCA parameters*/
				ie_list->EdcaParm.bValid          = true;
				ie_list->EdcaParm.bQAck           = false; /* pEid->Octet[0] & 0x10;*/
				ie_list->EdcaParm.bQueueRequest   = false; /* pEid->Octet[0] & 0x20;*/
				ie_list->EdcaParm.bTxopRequest    = false; /* pEid->Octet[0] & 0x40;*/
				ie_list->EdcaParm.EdcaUpdateCount = pEid->Octet[6] & 0x0f;
				ie_list->EdcaParm.bAPSDCapable    = (pEid->Octet[6] & 0x80) ? 1 : 0;

				/* use default EDCA parameter*/
				ie_list->EdcaParm.bACM[QID_AC_BE]  = 0;
				ie_list->EdcaParm.Aifsn[QID_AC_BE] = 3;
				ie_list->EdcaParm.Cwmin[QID_AC_BE] = CW_MIN_IN_BITS;
				ie_list->EdcaParm.Cwmax[QID_AC_BE] = CW_MAX_IN_BITS;
				ie_list->EdcaParm.Txop[QID_AC_BE]  = 0;

				ie_list->EdcaParm.bACM[QID_AC_BK]  = 0;
				ie_list->EdcaParm.Aifsn[QID_AC_BK] = 7;
				ie_list->EdcaParm.Cwmin[QID_AC_BK] = CW_MIN_IN_BITS;
				ie_list->EdcaParm.Cwmax[QID_AC_BK] = CW_MAX_IN_BITS;
				ie_list->EdcaParm.Txop[QID_AC_BK]  = 0;

				ie_list->EdcaParm.bACM[QID_AC_VI]  = 0;
				ie_list->EdcaParm.Aifsn[QID_AC_VI] = 2;
				ie_list->EdcaParm.Cwmin[QID_AC_VI] = CW_MIN_IN_BITS-1;
				ie_list->EdcaParm.Cwmax[QID_AC_VI] = CW_MAX_IN_BITS;
				ie_list->EdcaParm.Txop[QID_AC_VI]  = 96;   /* AC_VI: 96*32us ~= 3ms*/

				ie_list->EdcaParm.bACM[QID_AC_VO]  = 0;
				ie_list->EdcaParm.Aifsn[QID_AC_VO] = 2;
				ie_list->EdcaParm.Cwmin[QID_AC_VO] = CW_MIN_IN_BITS-2;
				ie_list->EdcaParm.Cwmax[QID_AC_VO] = CW_MAX_IN_BITS-1;
				ie_list->EdcaParm.Txop[QID_AC_VO]  = 48;   /* AC_VO: 48*32us ~= 1.5ms*/
			}
			else if (memcmp(pEid->Octet, WPS_OUI, 4) == 0)
			{
				if (PeerWscIeLen >= 512)
				DBGPRINT(RT_DEBUG_ERROR, ("%s: PeerWscIeLen = %d (>= 512)\n", __FUNCTION__, PeerWscIeLen));
				if (pPeerWscIe && (PeerWscIeLen < 512))
				{
				memmove(pPeerWscIe+PeerWscIeLen, pEid->Octet+4, pEid->Len-4);
				PeerWscIeLen += (pEid->Len - 4);
				}


			}


			break;

		case IE_EXT_SUPP_RATES:
			if (pEid->Len <= MAX_LEN_OF_SUPPORTED_RATES)
			{
				memmove(&ie_list->ExtRate[0], pEid->Octet, pEid->Len);
				ie_list->ExtRateLen = pEid->Len;

				/*
				TODO: 2004-09-14 not a good design here, cause it exclude extra rates
				from ScanTab. We should report as is. And filter out unsupported
				rates in MlmeAux
				*/
				/* Check against the supported rates*/
				/* RTMPCheckRates(pAd, ExtRate, pExtRateLen);*/
			}
			break;

		case IE_ERP:
			if (pEid->Len == 1)
				ie_list->Erp = (u8)pEid->Octet[0];
			break;

		case IE_AIRONET_CKIP:
			/*
			0. Check Aironet IE length, it must be larger or equal to 28
			Cisco AP350 used length as 28
			Cisco AP12XX used length as 30
			*/
			if (pEid->Len < (CKIP_NEGOTIATION_LENGTH - 2))
				break;

			/* 1. Copy CKIP flag byte to buffer for process*/
			ie_list->CkipFlag = *(pEid->Octet + 8);
			break;

		case IE_AP_TX_POWER:
			/* AP Control of Client Transmit Power*/
			/*0. Check Aironet IE length, it must be 6*/
			if (pEid->Len != 0x06)
				break;

			/* Get cell power limit in dBm*/
			if (memcmp(pEid->Octet, CISCO_OUI, 3) == 0)
				ie_list->AironetCellPowerLimit = *(pEid->Octet + 4);
			break;

		/* WPA2 & 802.11i RSN*/
		case IE_RSN:
			/* There is no OUI for version anymore, check the group cipher OUI before copying*/
			if (memcmp(pEid->Octet + 2, RSN_OUI, 3) == 0)
			{
				/* Copy to pVIE which will report to microsoft bssid list.*/
				Ptr = (u8 *) pVIE;
				memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
				*LengthVIE += (pEid->Len + 2);
			}
			break;


#ifdef CONFIG_STA_SUPPORT
#if defined (EXT_BUILD_CHANNEL_LIST) || defined (RT_CFG80211_SUPPORT)
		case IE_COUNTRY:
			Ptr = (u8 *) pVIE;
			memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
			*LengthVIE += (pEid->Len + 2);
			break;
#endif /* EXT_BUILD_CHANNEL_LIST */
#endif /* CONFIG_STA_SUPPORT */

		case IE_QBSS_LOAD:
			if (pEid->Len == 5)
			{
				ie_list->QbssLoad.bValid = true;
				ie_list->QbssLoad.StaNum = pEid->Octet[0] + pEid->Octet[1] * 256;
				ie_list->QbssLoad.ChannelUtilization = pEid->Octet[2];
				ie_list->QbssLoad.RemainingAdmissionControl = pEid->Octet[3] + pEid->Octet[4] * 256;

				/* Copy to pVIE*/
				Ptr = (u8 *) pVIE;
				memmove(Ptr + *LengthVIE, &pEid->Eid, pEid->Len + 2);
				*LengthVIE += (pEid->Len + 2);
			}
			break;



		case IE_EXT_CAPABILITY:
			if (pEid->Len >= 1)
			{
				memmove(&ie_list->ExtCapInfo,&pEid->Octet[0], sizeof(EXT_CAP_INFO_ELEMENT) /*4*/);
				break;
			}

#ifdef DOT11_VHT_AC
		case IE_VHT_CAP:
			if (pEid->Len == sizeof(VHT_CAP_IE)) {
				memmove(&ie_list->vht_cap_ie, &pEid->Octet[0], sizeof(VHT_CAP_IE));
				ie_list->vht_cap_len = pEid->Len;
			}
			break;
		case IE_VHT_OP:
			if (pEid->Len == sizeof(VHT_OP_IE)) {
				memmove(&ie_list->vht_op_ie, &pEid->Octet[0], sizeof(VHT_OP_IE));
				ie_list->vht_op_len = pEid->Len;
			}
			break;
#endif /* DOT11_VHT_AC */

		default:
			break;
		}

		Length = Length + 2 + pEid->Len;  /* Eid[1] + Len[1]+ content[Len]*/
		pEid = (PEID_STRUCT)((u8 *)pEid + 2 + pEid->Len);
    }

	LatchRfChannel = MsgChannel;

	if ((pAd->LatchRfRegs.Channel > 14) && ((Sanity & 0x4) == 0))
	{
		if (CtrlChannel != 0)
			ie_list->Channel = CtrlChannel;
		else
			ie_list->Channel = LatchRfChannel;
		Sanity |= 0x4;
	}

	if (pPeerWscIe && (PeerWscIeLen > 0) && (PeerWscIeLen < 512))
	{
		u8 WscIe[] = {0xdd, 0x00, 0x00, 0x50, 0xF2, 0x04};
		Ptr = (u8 *) pVIE;
		WscIe[1] = PeerWscIeLen + 4;
		memmove(Ptr + *LengthVIE, WscIe, 6);
		memmove(Ptr + *LengthVIE + 6, pPeerWscIe, PeerWscIeLen);
		*LengthVIE += (PeerWscIeLen + 6);
	}


SanityCheck:
	if (pPeerWscIe)
		kfree(pPeerWscIe);

	if (Sanity != 0x7)
	{
		DBGPRINT(RT_DEBUG_LOUD, ("%s() - missing field, Sanity=0x%02x\n", __FUNCTION__, Sanity));
		return false;
	}
	else
	{
		return true;
	}
}


#ifdef DOT11N_DRAFT3
/*
	==========================================================================
	Description:
		MLME message sanity check for some IE addressed  in 802.11n d3.03.
	Return:
		true if all parameters are OK, false otherwise

	IRQL = DISPATCH_LEVEL

	==========================================================================
 */
bool PeerBeaconAndProbeRspSanity2(
	struct rtmp_adapter *pAd,
	void *Msg,
	unsigned long MsgLen,
	OVERLAP_BSS_SCAN_IE *BssScan,
	u8 	*RegClass)
{
	CHAR				*Ptr;
	PFRAME_802_11		pFrame;
	PEID_STRUCT			pEid;
	unsigned long				Length = 0;
	bool 			brc;

	pFrame = (PFRAME_802_11)Msg;

	*RegClass = 0;
	Ptr = pFrame->Octet;
	Length += LENGTH_802_11;

	/* get timestamp from payload and advance the pointer*/
	Ptr += TIMESTAMP_LEN;
	Length += TIMESTAMP_LEN;

	/* get beacon interval from payload and advance the pointer*/
	Ptr += 2;
	Length += 2;

	/* get capability info from payload and advance the pointer*/
	Ptr += 2;
	Length += 2;

	pEid = (PEID_STRUCT) Ptr;
	brc = false;

	memset(BssScan, 0, sizeof(OVERLAP_BSS_SCAN_IE));
	/* get variable fields from payload and advance the pointer*/
	while ((Length + 2 + pEid->Len) <= MsgLen)
	{
		switch(pEid->Eid)
		{
			case IE_SUPP_REG_CLASS:
				if(pEid->Len > 0)
				{
					*RegClass = *pEid->Octet;
				}
				else
				{
					DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity - wrong IE_SUPP_REG_CLASS (len=%d)\n",pEid->Len));
				}
				break;
			case IE_OVERLAPBSS_SCAN_PARM:
				if (pEid->Len == sizeof(OVERLAP_BSS_SCAN_IE))
				{
					brc = true;
					memmove(BssScan, pEid->Octet, sizeof(OVERLAP_BSS_SCAN_IE));
				}
				else
				{
					DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity - wrong IE_OVERLAPBSS_SCAN_PARM (len=%d)\n",pEid->Len));
				}
				break;

			case IE_EXT_CHANNEL_SWITCH_ANNOUNCEMENT:
				DBGPRINT(RT_DEBUG_TRACE, ("PeerBeaconAndProbeRspSanity - IE_EXT_CHANNEL_SWITCH_ANNOUNCEMENT\n"));
				break;

		}

		Length = Length + 2 + pEid->Len;  /* Eid[1] + Len[1]+ content[Len]	*/
		pEid = (PEID_STRUCT)((u8 *)pEid + 2 + pEid->Len);
	}

	return brc;

}
#endif /* DOT11N_DRAFT3 */

#if defined(AP_SCAN_SUPPORT) || defined(CONFIG_STA_SUPPORT)
/*
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
 */
bool MlmeScanReqSanity(
	struct rtmp_adapter *pAd,
	void *Msg,
	unsigned long MsgLen,
	u8 *pBssType,
	CHAR Ssid[],
	u8 *pSsidLen,
	u8 *pScanType)
{
	MLME_SCAN_REQ_STRUCT *Info;

	Info = (MLME_SCAN_REQ_STRUCT *)(Msg);
	*pBssType = Info->BssType;
	*pSsidLen = Info->SsidLen;
	memmove(Ssid, Info->Ssid, *pSsidLen);
	*pScanType = Info->ScanType;

	if ((*pBssType == BSS_INFRA || *pBssType == BSS_ADHOC || *pBssType == BSS_ANY)
		&& (SCAN_MODE_VALID(*pScanType))
	)
	{
		return true;
	}
	else
	{
		DBGPRINT(RT_DEBUG_TRACE, ("MlmeScanReqSanity fail - wrong BssType or ScanType\n"));
		return false;
	}
}
#endif

/* IRQL = DISPATCH_LEVEL*/
u8 ChannelSanity(
    struct rtmp_adapter *pAd,
    u8 channel)
{
    int i;

    for (i = 0; i < pAd->ChannelListNum; i ++)
    {
        if (channel == pAd->ChannelList[i].Channel)
            return 1;
    }
    return 0;
}

/*
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        true if all parameters are OK, false otherwise

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
bool PeerDeauthSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pAddr1,
    u8 *pAddr2,
    u8 *pAddr3,
    unsigned short *pReason)
{
	PFRAME_802_11 pFrame = (PFRAME_802_11)Msg;

	memcpy(pAddr1, pFrame->Hdr.Addr1, ETH_ALEN);
	memcpy(pAddr2, pFrame->Hdr.Addr2, ETH_ALEN);
	memcpy(pAddr3, pFrame->Hdr.Addr3, ETH_ALEN);
	memmove(pReason, &pFrame->Octet[0], 2);

	return true;
}

/*
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        true if all parameters are OK, false otherwise

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
bool PeerAuthSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pAddr,
    unsigned short *pAlg,
    unsigned short *pSeq,
    unsigned short *pStatus,
    CHAR *pChlgText)
{
    PFRAME_802_11 pFrame = (PFRAME_802_11)Msg;

    memcpy(pAddr,   pFrame->Hdr.Addr2, ETH_ALEN);
    memmove(pAlg,    &pFrame->Octet[0], 2);
    memmove(pSeq,    &pFrame->Octet[2], 2);
    memmove(pStatus, &pFrame->Octet[4], 2);

    if (*pAlg == AUTH_MODE_OPEN)
    {
        if (*pSeq == 1 || *pSeq == 2)
        {
            return true;
        }
        else
        {
            DBGPRINT(RT_DEBUG_TRACE, ("PeerAuthSanity fail - wrong Seg#\n"));
            return false;
        }
    }
    else if (*pAlg == AUTH_MODE_KEY)
    {
        if (*pSeq == 1 || *pSeq == 4)
        {
            return true;
        }
        else if (*pSeq == 2 || *pSeq == 3)
        {
            memmove(pChlgText, &pFrame->Octet[8], CIPHER_TEXT_LEN);
            return true;
        }
        else
        {
            DBGPRINT(RT_DEBUG_TRACE, ("PeerAuthSanity fail - wrong Seg#\n"));
            return false;
        }
    }
    else
    {
        DBGPRINT(RT_DEBUG_TRACE, ("PeerAuthSanity fail - wrong algorithm\n"));
        return false;
    }
}

/*
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
 */
bool MlmeAuthReqSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pAddr,
    unsigned long *pTimeout,
    unsigned short *pAlg)
{
    MLME_AUTH_REQ_STRUCT *pInfo;

    pInfo  = (MLME_AUTH_REQ_STRUCT *)Msg;
    memcpy(pAddr, pInfo->Addr, ETH_ALEN);
    *pTimeout = pInfo->Timeout;
    *pAlg = pInfo->Alg;

    if (((*pAlg == AUTH_MODE_KEY) ||(*pAlg == AUTH_MODE_OPEN)
     	) &&
        ((*pAddr & 0x01) == 0))
    {
#ifdef CONFIG_STA_SUPPORT
#endif /* CONFIG_STA_SUPPORT */
        return true;
    }
    else
    {
        DBGPRINT(RT_DEBUG_TRACE, ("MlmeAuthReqSanity fail - wrong algorithm\n"));
        return false;
    }
}

/*
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        true if all parameters are OK, false otherwise

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
bool MlmeAssocReqSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pApAddr,
    unsigned short *pCapabilityInfo,
    unsigned long *pTimeout,
    unsigned short *pListenIntv)
{
    MLME_ASSOC_REQ_STRUCT *pInfo;

    pInfo = (MLME_ASSOC_REQ_STRUCT *)Msg;
    *pTimeout = pInfo->Timeout;                             /* timeout*/
    memcpy(pApAddr, pInfo->Addr, ETH_ALEN);                   /* AP address*/
    *pCapabilityInfo = pInfo->CapabilityInfo;               /* capability info*/
    *pListenIntv = pInfo->ListenIntv;

    return true;
}

/*
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        true if all parameters are OK, false otherwise

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
bool PeerDisassocSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pAddr2,
    unsigned short *pReason)
{
    PFRAME_802_11 pFrame = (PFRAME_802_11)Msg;

    memcpy(pAddr2, pFrame->Hdr.Addr2, ETH_ALEN);
    memmove(pReason, &pFrame->Octet[0], 2);

    return true;
}

/*
	========================================================================
	Routine Description:
		Sanity check NetworkType (11b, 11g or 11a)

	Arguments:
		pBss - Pointer to BSS table.

	Return Value:
        Ndis802_11DS .......(11b)
        Ndis802_11OFDM24....(11g)
        Ndis802_11OFDM5.....(11a)

	IRQL = DISPATCH_LEVEL

	========================================================================
*/
NDIS_802_11_NETWORK_TYPE NetworkTypeInUseSanity(
    PBSS_ENTRY pBss)
{
	NDIS_802_11_NETWORK_TYPE	NetWorkType;
	u8 					rate, i;

	NetWorkType = Ndis802_11DS;

	if (pBss->Channel <= 14)
	{

		/* First check support Rate.*/
		for (i = 0; i < pBss->SupRateLen; i++)
		{
			rate = pBss->SupRate[i] & 0x7f; /* Mask out basic rate set bit*/
			if ((rate == 2) || (rate == 4) || (rate == 11) || (rate == 22))
			{
				continue;
			}
			else
			{

				/* Otherwise (even rate > 108) means Ndis802_11OFDM24*/
				NetWorkType = Ndis802_11OFDM24;
				break;
			}
		}


		/* Second check Extend Rate.*/
		if (NetWorkType != Ndis802_11OFDM24)
		{
			for (i = 0; i < pBss->ExtRateLen; i++)
			{
				rate = pBss->SupRate[i] & 0x7f; /* Mask out basic rate set bit*/
				if ((rate == 2) || (rate == 4) || (rate == 11) || (rate == 22))
				{
					continue;
				}
				else
				{

					/* Otherwise (even rate > 108) means Ndis802_11OFDM24*/
					NetWorkType = Ndis802_11OFDM24;
					break;
				}
			}
		}
	}
	else
	{
		NetWorkType = Ndis802_11OFDM5;
	}

    if (pBss->HtCapabilityLen != 0)
    {
        if (NetWorkType == Ndis802_11OFDM5)
            NetWorkType = Ndis802_11OFDM5_N;
        else
            NetWorkType = Ndis802_11OFDM24_N;
    }

	return NetWorkType;
}

#ifdef CONFIG_STA_SUPPORT
#ifdef QOS_DLS_SUPPORT
bool MlmeDlsReqSanity(
	struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    PRT_802_11_DLS *pDLS,
    unsigned short *pReason)
{
	MLME_DLS_REQ_STRUCT *pInfo;

    pInfo = (MLME_DLS_REQ_STRUCT *)Msg;

	*pDLS = pInfo->pDLS;
	*pReason = pInfo->Reason;

	return true;
}
#endif /* QOS_DLS_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */

#ifdef QOS_DLS_SUPPORT
bool PeerDlsReqSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pDA,
    u8 *pSA,
    unsigned short *pCapabilityInfo,
    unsigned short *pDlsTimeout,
    u8 *pRatesLen,
    u8 Rates[],
	u8 *pHtCapabilityLen,
    HT_CAPABILITY_IE *pHtCapability)
{
	CHAR            *Ptr;
    PFRAME_802_11	Fr = (PFRAME_802_11)Msg;
	PEID_STRUCT  eid_ptr;

    /* to prevent caller from using garbage output value*/
    *pCapabilityInfo	= 0;
    *pDlsTimeout	= 0;
	*pHtCapabilityLen = 0;

    Ptr = (char *)Fr->Octet;

	/* offset to destination MAC address (Category and Action field)*/
    Ptr += 2;

    /* get DA from payload and advance the pointer*/
    memmove(pDA, Ptr, ETH_ALEN);
    Ptr += ETH_ALEN;

    /* get SA from payload and advance the pointer*/
    memmove(pSA, Ptr, ETH_ALEN);
    Ptr += ETH_ALEN;

    /* get capability info from payload and advance the pointer*/
    memmove(pCapabilityInfo, Ptr, 2);
    Ptr += 2;

    /* get capability info from payload and advance the pointer*/
    memmove(pDlsTimeout, Ptr, 2);
    Ptr += 2;

	/* Category and Action field + DA + SA + capability + Timeout*/
	eid_ptr = (PEID_STRUCT) &Fr->Octet[18];

	while (((u8 *)eid_ptr + eid_ptr->Len + 1) < ((u8 *)Fr + MsgLen))
	{
		switch(eid_ptr->Eid)
		{
			case IE_SUPP_RATES:
                if ((eid_ptr->Len <= MAX_LEN_OF_SUPPORTED_RATES) && (eid_ptr->Len > 0))
                {
                    memmove(Rates, eid_ptr->Octet, eid_ptr->Len);
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsReqSanity - IE_SUPP_RATES., Len=%d. Rates[0]=%x\n",eid_ptr->Len, Rates[0]));
                    DBGPRINT(RT_DEBUG_TRACE, ("Rates[1]=%x %x %x %x %x %x %x\n", Rates[1], Rates[2], Rates[3], Rates[4], Rates[5], Rates[6], Rates[7]));
                    *pRatesLen = eid_ptr->Len;
                }
                else
                {
                    *pRatesLen = 8;
					Rates[0] = 0x82;
					Rates[1] = 0x84;
					Rates[2] = 0x8b;
					Rates[3] = 0x96;
					Rates[4] = 0x12;
					Rates[5] = 0x24;
					Rates[6] = 0x48;
					Rates[7] = 0x6c;
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsReqSanity - wrong IE_SUPP_RATES., Len=%d\n",eid_ptr->Len));
                }
				break;

			case IE_EXT_SUPP_RATES:
                if (eid_ptr->Len + *pRatesLen <= MAX_LEN_OF_SUPPORTED_RATES)
                {
                    memmove(&Rates[*pRatesLen], eid_ptr->Octet, eid_ptr->Len);
                    *pRatesLen = (*pRatesLen) + eid_ptr->Len;
                }
                else
                {
                    memmove(&Rates[*pRatesLen], eid_ptr->Octet, MAX_LEN_OF_SUPPORTED_RATES - (*pRatesLen));
                    *pRatesLen = MAX_LEN_OF_SUPPORTED_RATES;
                }
				break;

			case IE_HT_CAP:
				if (eid_ptr->Len >= sizeof(HT_CAPABILITY_IE))
				{
					memmove(pHtCapability, eid_ptr->Octet, sizeof(HT_CAPABILITY_IE));

					*(unsigned short *)(&pHtCapability->HtCapInfo) = cpu2le16(*(unsigned short *)(&pHtCapability->HtCapInfo));
#ifdef UNALIGNMENT_SUPPORT
					{
						EXT_HT_CAP_INFO extHtCapInfo;

						memmove((u8 *)(&extHtCapInfo), (u8 *)(&pHtCapability->ExtHtCapInfo), sizeof(EXT_HT_CAP_INFO));
						*(unsigned short *)(&extHtCapInfo) = cpu2le16(*(unsigned short *)(&extHtCapInfo));
						memmove((u8 *)(&pHtCapability->ExtHtCapInfo), (u8 *)(&extHtCapInfo), sizeof(EXT_HT_CAP_INFO));
					}
#else
					*(unsigned short *)(&pHtCapability->ExtHtCapInfo) = cpu2le16(*(unsigned short *)(&pHtCapability->ExtHtCapInfo));
#endif /* UNALIGNMENT_SUPPORT */
					*pHtCapabilityLen = sizeof(HT_CAPABILITY_IE);

					DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsReqSanity - IE_HT_CAP\n"));
				}
				else
				{
					DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsReqSanity - wrong IE_HT_CAP.eid_ptr->Len = %d\n", eid_ptr->Len));
				}
				break;

			default:
				break;
		}

		eid_ptr = (PEID_STRUCT)((u8 *)eid_ptr + 2 + eid_ptr->Len);
	}

    return true;
}

bool PeerDlsRspSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pDA,
    u8 *pSA,
    unsigned short *pCapabilityInfo,
    unsigned short *pStatus,
    u8 *pRatesLen,
    u8 Rates[],
    u8 *pHtCapabilityLen,
    HT_CAPABILITY_IE *pHtCapability)
{
    CHAR            *Ptr;
    PFRAME_802_11	Fr = (PFRAME_802_11)Msg;
	PEID_STRUCT  eid_ptr;

    /* to prevent caller from using garbage output value*/
	if (pStatus)
    *pStatus		= 0;
    *pCapabilityInfo	= 0;
	*pHtCapabilityLen = 0;

    Ptr = (char *)Fr->Octet;

	/* offset to destination MAC address (Category and Action field)*/
    Ptr += 2;

	/* get status code from payload and advance the pointer*/
	if (pStatus)
		memmove(pStatus, Ptr, 2);
    Ptr += 2;

    /* get DA from payload and advance the pointer*/
    memmove(pDA, Ptr, ETH_ALEN);
    Ptr += ETH_ALEN;

    /* get SA from payload and advance the pointer*/
    memmove(pSA, Ptr, ETH_ALEN);
    Ptr += ETH_ALEN;

	if (pStatus == 0)
	{
	    /* get capability info from payload and advance the pointer*/
	    memmove(pCapabilityInfo, Ptr, 2);
	    Ptr += 2;
	}

	/* Category and Action field + status code + DA + SA + capability*/
	eid_ptr = (PEID_STRUCT) &Fr->Octet[18];

	while (((u8 *)eid_ptr + eid_ptr->Len + 1) < ((u8 *)Fr + MsgLen))
	{
		switch(eid_ptr->Eid)
		{
			case IE_SUPP_RATES:
                if ((eid_ptr->Len <= MAX_LEN_OF_SUPPORTED_RATES) && (eid_ptr->Len > 0))
                {
                    memmove(Rates, eid_ptr->Octet, eid_ptr->Len);
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsRspSanity - IE_SUPP_RATES., Len=%d. Rates[0]=%x\n",eid_ptr->Len, Rates[0]));
                    DBGPRINT(RT_DEBUG_TRACE, ("Rates[1]=%x %x %x %x %x %x %x\n", Rates[1], Rates[2], Rates[3], Rates[4], Rates[5], Rates[6], Rates[7]));
                    *pRatesLen = eid_ptr->Len;
                }
                else
                {
                    *pRatesLen = 8;
					Rates[0] = 0x82;
					Rates[1] = 0x84;
					Rates[2] = 0x8b;
					Rates[3] = 0x96;
					Rates[4] = 0x12;
					Rates[5] = 0x24;
					Rates[6] = 0x48;
					Rates[7] = 0x6c;
                    DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsRspSanity - wrong IE_SUPP_RATES., Len=%d\n",eid_ptr->Len));
                }
				break;

			case IE_EXT_SUPP_RATES:
                if (eid_ptr->Len + *pRatesLen <= MAX_LEN_OF_SUPPORTED_RATES)
                {
                    memmove(&Rates[*pRatesLen], eid_ptr->Octet, eid_ptr->Len);
                    *pRatesLen = (*pRatesLen) + eid_ptr->Len;
                }
                else
                {
                    memmove(&Rates[*pRatesLen], eid_ptr->Octet, MAX_LEN_OF_SUPPORTED_RATES - (*pRatesLen));
                    *pRatesLen = MAX_LEN_OF_SUPPORTED_RATES;
                }
				break;

			case IE_HT_CAP:
				if (eid_ptr->Len >= sizeof(HT_CAPABILITY_IE))
				{
					memmove(pHtCapability, eid_ptr->Octet, sizeof(HT_CAPABILITY_IE));

					*(unsigned short *)(&pHtCapability->HtCapInfo) = cpu2le16(*(unsigned short *)(&pHtCapability->HtCapInfo));
#ifdef UNALIGNMENT_SUPPORT
					{
						EXT_HT_CAP_INFO extHtCapInfo;

						memmove((u8 *)(&extHtCapInfo), (u8 *)(&pHtCapability->ExtHtCapInfo), sizeof(EXT_HT_CAP_INFO));
						*(unsigned short *)(&extHtCapInfo) = cpu2le16(*(unsigned short *)(&extHtCapInfo));
						memmove((u8 *)(&pHtCapability->ExtHtCapInfo), (u8 *)(&extHtCapInfo), sizeof(EXT_HT_CAP_INFO));
					}
#else
					*(unsigned short *)(&pHtCapability->ExtHtCapInfo) = cpu2le16(*(unsigned short *)(&pHtCapability->ExtHtCapInfo));
#endif /* UNALIGNMENT_SUPPORT */
					*pHtCapabilityLen = sizeof(HT_CAPABILITY_IE);

					DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsRspSanity - IE_HT_CAP\n"));
				}
				else
				{
					DBGPRINT(RT_DEBUG_TRACE, ("PeerDlsRspSanity - wrong IE_HT_CAP.eid_ptr->Len = %d\n", eid_ptr->Len));
				}
				break;

			default:
				break;
		}

		eid_ptr = (PEID_STRUCT)((u8 *)eid_ptr + 2 + eid_ptr->Len);
	}

    return true;
}

bool PeerDlsTearDownSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pDA,
    u8 *pSA,
    unsigned short *pReason)
{
    CHAR            *Ptr;
    PFRAME_802_11	Fr = (PFRAME_802_11)Msg;

    /* to prevent caller from using garbage output value*/
    *pReason	= 0;

    Ptr = (char *)Fr->Octet;

	/* offset to destination MAC address (Category and Action field)*/
    Ptr += 2;

    /* get DA from payload and advance the pointer*/
    memmove(pDA, Ptr, ETH_ALEN);
    Ptr += ETH_ALEN;

    /* get SA from payload and advance the pointer*/
    memmove(pSA, Ptr, ETH_ALEN);
    Ptr += ETH_ALEN;

	/* get reason code from payload and advance the pointer*/
    memmove(pReason, Ptr, 2);
    Ptr += 2;

    return true;
}
#endif /* QOS_DLS_SUPPORT */

/*
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
 */
bool PeerProbeReqSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pAddr2,
    CHAR Ssid[],
    u8 *SsidLen,
    bool *bRssiRequested)
{
    PFRAME_802_11 Fr = (PFRAME_802_11)Msg;
    u8 	*Ptr;
    u8 	eid =0, eid_len = 0, *eid_data;
	unsigned int		total_ie_len = 0;

    /* to prevent caller from using garbage output value*/
    *SsidLen = 0;

    memcpy(pAddr2, &Fr->Hdr.Addr2, ETH_ALEN);

    if (Fr->Octet[0] != IE_SSID || Fr->Octet[1] > MAX_LEN_OF_SSID)
    {
        DBGPRINT(RT_DEBUG_TRACE, ("APPeerProbeReqSanity fail - wrong SSID IE\n"));
        return false;
    }

    *SsidLen = Fr->Octet[1];
    memmove(Ssid, &Fr->Octet[2], *SsidLen);


    Ptr = Fr->Octet;
    eid = Ptr[0];
    eid_len = Ptr[1];
	total_ie_len = eid_len + 2;
	eid_data = Ptr+2;

    /* get variable fields from payload and advance the pointer*/
	while((eid_data + eid_len) <= ((u8 *)Fr + MsgLen))
    {
        switch(eid)
        {
	        case IE_VENDOR_SPECIFIC:
				if (eid_len <= 4)
					break;
#ifdef RSSI_FEEDBACK
                if (bRssiRequested && memcmp(eid_data, RALINK_OUI, 3) == 0 && (eid_len == 7))
                {
					if (*(eid_data + 3/* skip RALINK_OUI */) & 0x8)
                    	*bRssiRequested = true;
                    break;
                }
#endif /* RSSI_FEEDBACK */

                if (memcmp(eid_data, WPS_OUI, 4) == 0) {

                    break;
                }

            default:
                break;
        }
		eid = Ptr[total_ie_len];
    	eid_len = Ptr[total_ie_len + 1];
		eid_data = Ptr + total_ie_len + 2;
		total_ie_len += (eid_len + 2);
	}


    return true;
}



