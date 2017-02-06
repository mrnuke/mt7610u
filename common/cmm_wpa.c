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

/* WPA OUI*/
u8 	OUI_WPA[3]				= {0x00, 0x50, 0xF2};
u8 	OUI_WPA_NONE_AKM[4]		= {0x00, 0x50, 0xF2, 0x00};
u8       OUI_WPA_VERSION[4]      = {0x00, 0x50, 0xF2, 0x01};
u8       OUI_WPA_WEP40[4]      = {0x00, 0x50, 0xF2, 0x01};
u8       OUI_WPA_TKIP[4]     = {0x00, 0x50, 0xF2, 0x02};
u8       OUI_WPA_CCMP[4]     = {0x00, 0x50, 0xF2, 0x04};
u8       OUI_WPA_WEP104[4]      = {0x00, 0x50, 0xF2, 0x05};
u8       OUI_WPA_8021X_AKM[4]	= {0x00, 0x50, 0xF2, 0x01};
u8       OUI_WPA_PSK_AKM[4]      = {0x00, 0x50, 0xF2, 0x02};
/* WPA2 OUI*/
u8 	OUI_WPA2[3]				= {0x00, 0x0F, 0xAC};
u8       OUI_WPA2_WEP40[4]   = {0x00, 0x0F, 0xAC, 0x01};
u8       OUI_WPA2_TKIP[4]        = {0x00, 0x0F, 0xAC, 0x02};
u8       OUI_WPA2_CCMP[4]        = {0x00, 0x0F, 0xAC, 0x04};
u8       OUI_WPA2_8021X_AKM[4]   = {0x00, 0x0F, 0xAC, 0x01};
u8       OUI_WPA2_PSK_AKM[4]   	= {0x00, 0x0F, 0xAC, 0x02};
u8       OUI_WPA2_WEP104[4]   = {0x00, 0x0F, 0xAC, 0x05};
u8       OUI_WPA2_1X_SHA256[4]   = {0x00, 0x0F, 0xAC, 0x05};
u8       OUI_WPA2_PSK_SHA256[4]   = {0x00, 0x0F, 0xAC, 0x06};



static void ConstructEapolKeyData(
	PMAC_TABLE_ENTRY	pEntry,
	u8 		GroupKeyWepStatus,
	u8 		keyDescVer,
	u8 		MsgType,
	u8 		DefaultKeyIdx,
	u8 		*GTK,
	u8 		*RSNIE,
	u8 		RSNIE_LEN,
	PEAPOL_PACKET   pMsg);

static void WpaEAPPacketAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

static void WpaEAPOLASFAlertAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

static void WpaEAPOLLogoffAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

static void WpaEAPOLStartAction(
    struct rtmp_adapter *   pAd,
    MLME_QUEUE_ELEM  *Elem);

static void WpaEAPOLKeyAction(
    struct rtmp_adapter *   pAd,
    MLME_QUEUE_ELEM  *Elem);

/*
    ==========================================================================
    Description:
        association state machine init, including state transition and timer init
    Parameters:
        S - pointer to the association state machine
    ==========================================================================
 */
void WpaStateMachineInit(
    struct rtmp_adapter *  pAd,
    STATE_MACHINE *S,
    STATE_MACHINE_FUNC Trans[])
{
    StateMachineInit(S, (STATE_MACHINE_FUNC *)Trans, MAX_WPA_PTK_STATE, MAX_WPA_MSG, (STATE_MACHINE_FUNC)Drop, WPA_PTK, WPA_MACHINE_BASE);

    StateMachineSetAction(S, WPA_PTK, MT2_EAPPacket, (STATE_MACHINE_FUNC)WpaEAPPacketAction);
    StateMachineSetAction(S, WPA_PTK, MT2_EAPOLStart, (STATE_MACHINE_FUNC)WpaEAPOLStartAction);
    StateMachineSetAction(S, WPA_PTK, MT2_EAPOLLogoff, (STATE_MACHINE_FUNC)WpaEAPOLLogoffAction);
    StateMachineSetAction(S, WPA_PTK, MT2_EAPOLKey, (STATE_MACHINE_FUNC)WpaEAPOLKeyAction);
    StateMachineSetAction(S, WPA_PTK, MT2_EAPOLASFAlert, (STATE_MACHINE_FUNC)WpaEAPOLASFAlertAction);
}

/*
    ==========================================================================
    Description:
        this is state machine function.
        When receiving EAP packets which is  for 802.1x authentication use.
        Not use in PSK case
    Return:
    ==========================================================================
*/
void WpaEAPPacketAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem)
{
}

void WpaEAPOLASFAlertAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem)
{
}

void WpaEAPOLLogoffAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem)
{
}

/*
    ==========================================================================
    Description:
       Start 4-way HS when rcv EAPOL_START which may create by our driver in assoc.c
    Return:
    ==========================================================================
*/
void WpaEAPOLStartAction(
    struct rtmp_adapter *   pAd,
    MLME_QUEUE_ELEM  *Elem)
{
    MAC_TABLE_ENTRY     *pEntry;
    PHEADER_802_11      pHeader;

#ifdef CONFIG_STA_SUPPORT
#endif /* CONFIG_STA_SUPPORT */

    DBGPRINT(RT_DEBUG_TRACE, ("WpaEAPOLStartAction ===> \n"));

    pHeader = (PHEADER_802_11)Elem->Msg;

    /*For normaol PSK, we enqueue an EAPOL-Start command to trigger the process.*/
    if (Elem->MsgLen == 6)
        pEntry = MacTableLookup(pAd, Elem->Msg);
    else
    {
        pEntry = MacTableLookup(pAd, pHeader->Addr2);
    }

    if (pEntry)
    {
		DBGPRINT(RT_DEBUG_TRACE, (" PortSecured(%d), WpaState(%d), AuthMode(%d), PMKID_CacheIdx(%d) \n", pEntry->PortSecured, pEntry->WpaState, pEntry->AuthMode, pEntry->PMKID_CacheIdx));

        if ((pEntry->PortSecured == WPA_802_1X_PORT_NOT_SECURED)
			&& (pEntry->WpaState < AS_PTKSTART)
            && ((pEntry->AuthMode == Ndis802_11AuthModeWPAPSK) || (pEntry->AuthMode == Ndis802_11AuthModeWPA2PSK) || ((pEntry->AuthMode == Ndis802_11AuthModeWPA2) && (pEntry->PMKID_CacheIdx != ENTRY_NOT_FOUND))))
        {
            pEntry->PrivacyFilter = Ndis802_11PrivFilter8021xWEP;
            pEntry->WpaState = AS_INITPSK;
            pEntry->PortSecured = WPA_802_1X_PORT_NOT_SECURED;
            memset(pEntry->R_Counter, 0, sizeof(pEntry->R_Counter));
            pEntry->ReTryCounter = PEER_MSG1_RETRY_TIMER_CTR;

            WPAStart4WayHS(pAd, pEntry, PEER_MSG1_RETRY_EXEC_INTV);
        }
    }
}

/*
    ==========================================================================
    Description:
        This is state machine function.
        When receiving EAPOL packets which is  for 802.1x key management.
        Use both in WPA, and WPAPSK case.
        In this function, further dispatch to different functions according to the received packet.  3 categories are :
          1.  normal 4-way pairwisekey and 2-way groupkey handshake
          2.  MIC error (Countermeasures attack)  report packet from STA.
          3.  Request for pairwise/group key update from STA
    Return:
    ==========================================================================
*/
void WpaEAPOLKeyAction(
    struct rtmp_adapter *   pAd,
    MLME_QUEUE_ELEM  *Elem)
{
    MAC_TABLE_ENTRY     *pEntry;
    PHEADER_802_11      pHeader;
    PEAPOL_PACKET       pEapol_packet;
	KEY_INFO			peerKeyInfo;
	UINT				eapol_len;

#ifdef CONFIG_STA_SUPPORT
#endif /* CONFIG_STA_SUPPORT */

    DBGPRINT(RT_DEBUG_TRACE, ("WpaEAPOLKeyAction ===>\n"));

    pHeader = (PHEADER_802_11)Elem->Msg;
    pEapol_packet = (PEAPOL_PACKET)&Elem->Msg[LENGTH_802_11 + LENGTH_802_1_H];
	eapol_len = CONV_ARRARY_TO_UINT16(pEapol_packet->Body_Len) + LENGTH_EAPOL_H;

	memset((u8 *)&peerKeyInfo, 0, sizeof(peerKeyInfo));
	memmove((u8 *)&peerKeyInfo, (u8 *)&pEapol_packet->KeyDesc.KeyInfo, sizeof(KEY_INFO));


	*((USHORT *)&peerKeyInfo) = cpu2le16(*((USHORT *)&peerKeyInfo));

    do
    {
        pEntry = MacTableLookup(pAd, pHeader->Addr2);

		if (!pEntry || (!IS_ENTRY_CLIENT(pEntry) && !IS_ENTRY_APCLI(pEntry)))
            break;

		if (pEntry->AuthMode < Ndis802_11AuthModeWPA)
				break;

		DBGPRINT(RT_DEBUG_TRACE, ("Receive EAPoL-Key frame from STA %02X-%02X-%02X-%02X-%02X-%02X\n", PRINT_MAC(pEntry->Addr)));

		if (eapol_len > Elem->MsgLen - LENGTH_802_11 - LENGTH_802_1_H)
		{
            DBGPRINT(RT_DEBUG_ERROR, ("The length of EAPoL packet is invalid \n"));
            break;
        }

        if (((pEapol_packet->ProVer != EAPOL_VER) && (pEapol_packet->ProVer != EAPOL_VER2)) ||
			((pEapol_packet->KeyDesc.Type != WPA1_KEY_DESC) && (pEapol_packet->KeyDesc.Type != WPA2_KEY_DESC)))
        {
            DBGPRINT(RT_DEBUG_ERROR, ("Key descripter does not match with WPA rule\n"));
            break;
        }

		/* The value 1 shall be used for all EAPOL-Key frames to and from a STA when */
		/* neither the group nor pairwise ciphers are CCMP for Key Descriptor 1.*/
		if ((pEntry->WepStatus == Ndis802_11Encryption2Enabled) && (peerKeyInfo.KeyDescVer != KEY_DESC_TKIP))
        {
	        DBGPRINT(RT_DEBUG_ERROR, ("Key descripter version not match(TKIP) \n"));
    	    break;
    	}
		/* The value 2 shall be used for all EAPOL-Key frames to and from a STA when */
		/* either the pairwise or the group cipher is AES-CCMP for Key Descriptor 2 or 3.*/
                else if ((pEntry->WepStatus == Ndis802_11Encryption3Enabled)
                        && (peerKeyInfo.KeyDescVer != KEY_DESC_AES)
                        && (peerKeyInfo.KeyDescVer != KEY_DESC_EXT))
    	{
                        DBGPRINT(RT_DEBUG_ERROR, ("Key descripter version not match(AES) pEntry->WepStatus=%d, peerKeyInfo.KeyDescVer=%d\n", pEntry->WepStatus, peerKeyInfo.KeyDescVer));
        	break;
    	}

		/* Check if this STA is in class 3 state and the WPA state is started 						*/
        if ((pEntry->Sst == SST_ASSOC) && (pEntry->WpaState >= AS_INITPSK))
        {
			/* Check the Key Ack (bit 7) of the Key Information to determine the Authenticator */
			/* or not.*/
			/* An EAPOL-Key frame that is sent by the Supplicant in response to an EAPOL-*/
			/* Key frame from the Authenticator must not have the Ack bit set.*/
			if (peerKeyInfo.KeyAck == 1)
			{
				/* The frame is snet by Authenticator. */
				/* So the Supplicant side shall handle this.*/

				if ((peerKeyInfo.Secure == 0) && (peerKeyInfo.Request == 0) &&
					(peerKeyInfo.Error == 0) && (peerKeyInfo.KeyType == PAIRWISEKEY))
				{
					/*
						Process
							1. the message 1 of 4-way HS in WPA or WPA2
									EAPOL-Key(0,0,1,0,P,0,0,ANonce,0,DataKD_M1)
							2. the message 3 of 4-way HS in WPA
									EAPOL-Key(0,1,1,1,P,0,KeyRSC,ANonce,MIC,DataKD_M3)
					*/
					if (peerKeyInfo.KeyMic == 0)
                    	PeerPairMsg1Action(pAd, pEntry, Elem);
	                else
    	                PeerPairMsg3Action(pAd, pEntry, Elem);
				}
				else if ((peerKeyInfo.Secure == 1) &&
						 (peerKeyInfo.KeyMic == 1) &&
						 (peerKeyInfo.Request == 0) &&
						 (peerKeyInfo.Error == 0))
				{
					/*
						Process
							1. the message 3 of 4-way HS in WPA2
								EAPOL-Key(1,1,1,1,P,0,KeyRSC,ANonce,MIC,DataKD_M3)
							2. the message 1 of group KS in WPA or WPA2
								EAPOL-Key(1,1,1,0,G,0,Key RSC,0, MIC,GTK[N])
					*/
					if (peerKeyInfo.KeyType == PAIRWISEKEY)
						PeerPairMsg3Action(pAd, pEntry, Elem);
					else
						PeerGroupMsg1Action(pAd, pEntry, Elem);
				}
			}
			else
			{
				/*
					The frame is snet by Supplicant.So the Authenticator
					side shall handle this.
				*/
				if ((peerKeyInfo.Request == 0) &&
					 	 (peerKeyInfo.Error == 0) &&
					 	 (peerKeyInfo.KeyMic == 1))
				{
					if (peerKeyInfo.Secure == 0 && peerKeyInfo.KeyType == PAIRWISEKEY)
					{
						/* EAPOL-Key(0,1,0,0,P,0,0,SNonce,MIC,Data)*/
						/* Process 1. message 2 of 4-way HS in WPA or WPA2 */
						/*		   2. message 4 of 4-way HS in WPA	*/
						if (CONV_ARRARY_TO_UINT16(pEapol_packet->KeyDesc.KeyDataLen) == 0)
						{
							PeerPairMsg4Action(pAd, pEntry, Elem);
    	            	}
						else
						{
							PeerPairMsg2Action(pAd, pEntry, Elem);
						}
					}
					else if (peerKeyInfo.Secure == 1 && peerKeyInfo.KeyType == PAIRWISEKEY)
					{
						/* EAPOL-Key(1,1,0,0,P,0,0,0,MIC,0)						*/
						/* Process message 4 of 4-way HS in WPA2*/
						PeerPairMsg4Action(pAd, pEntry, Elem);
					}
					else if (peerKeyInfo.Secure == 1 && peerKeyInfo.KeyType == GROUPKEY)
					{
						/* EAPOL-Key(1,1,0,0,G,0,0,0,MIC,0)*/
						/* Process message 2 of Group key HS in WPA or WPA2 */
						PeerGroupMsg2Action(pAd, pEntry, &Elem->Msg[LENGTH_802_11], (Elem->MsgLen - LENGTH_802_11));
					}
				}
			}
        }
    }while(false);
}

/*
	========================================================================

	Routine	Description:
		Copy frame from waiting queue into relative ring buffer and set
	appropriate ASIC register to kick hardware encryption before really
	sent out to air.

	Arguments:
		pAd		Pointer	to our adapter
		struct sk_buff *	Pointer to outgoing Ndis frame
		NumberOfFrag	Number of fragment required

	Return Value:
		None

	Note:

	========================================================================
*/
void RTMPToWirelessSta(
    struct rtmp_adapter *  	pAd,
    PMAC_TABLE_ENTRY 	pEntry,
    u8 *         	pHeader802_3,
    UINT            	HdrLen,
    u8 *         	pData,
    UINT            	DataLen,
    bool 			bClearFrame)
{
    struct sk_buff *    pPacket;
    int     Status;

	if ((!pEntry) || (!IS_ENTRY_CLIENT(pEntry) && !IS_ENTRY_APCLI(pEntry)
	))
		return;

	do {
        	/* build a NDIS packet*/
        	Status = RTMPAllocateNdisPacket(pAd, &pPacket, pHeader802_3, HdrLen, pData, DataLen);
        	if (Status != NDIS_STATUS_SUCCESS)
            	break;


			if (bClearFrame)
				RTMP_SET_PACKET_CLEAR_EAP_FRAME(pPacket, 1);
			else
				RTMP_SET_PACKET_CLEAR_EAP_FRAME(pPacket, 0);
		{
			RTMP_SET_PACKET_NET_DEVICE_MBSSID(pPacket, MAIN_MBSSID);	/* set a default value*/
			if(pEntry->apidx != 0)
        		RTMP_SET_PACKET_NET_DEVICE_MBSSID(pPacket, pEntry->apidx);

        	RTMP_SET_PACKET_WCID(pPacket, (u8)pEntry->Aid);
			RTMP_SET_PACKET_MOREDATA(pPacket, false);
		}

#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
			/* send out the packet*/
			Status = STASendPacket(pAd, pPacket);
			if (Status == NDIS_STATUS_SUCCESS)
			{
				u8   Index;

				/* Dequeue one frame from TxSwQueue0..3 queue and process it*/
				/* There are three place calling dequeue for TX ring.*/
				/* 1. Here, right after queueing the frame.*/
				/* 2. At the end of TxRingTxDone service routine.*/
				/* 3. Upon NDIS call RTMPSendPackets*/
				if((!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS)) &&
					(!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_RESET_IN_PROGRESS)))
				{
					for(Index = 0; Index < 5; Index ++)
						if(pAd->TxSwQueue[Index].Number > 0)
							RTMPDeQueuePacket(pAd, false, Index, MAX_TX_PROCESS);
				}
			}
		}
#endif /* CONFIG_STA_SUPPORT */

    } while (false);
}

/*
    ==========================================================================
    Description:
        Check the validity of the received EAPoL frame
    Return:
        true if all parameters are OK,
        false otherwise
    ==========================================================================
 */
bool PeerWpaMessageSanity(
    struct rtmp_adapter *		pAd,
    PEAPOL_PACKET 		pMsg,
    unsigned long 				MsgLen,
    u8 			MsgType,
    MAC_TABLE_ENTRY  	*pEntry)
{
	u8 		mic[LEN_KEY_DESC_MIC], digest[80]; /*, KEYDATA[MAX_LEN_OF_RSNIE];*/
	u8 		*KEYDATA = NULL;
	bool 		bReplayDiff = false;
	bool 		bWPA2 = false;
	KEY_INFO		EapolKeyInfo;
	u8 		GroupKeyIndex = 0;


	/* allocate memory */
	KEYDATA = kmalloc(MAX_LEN_OF_RSNIE, GFP_ATOMIC);
	if (KEYDATA == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: Allocate memory fail!!!\n", __FUNCTION__));
		return false;
	}

	memset(mic, 0, sizeof(mic));
	memset(digest, 0, sizeof(digest));
	memset(KEYDATA, 0, MAX_LEN_OF_RSNIE);
	memset((u8 *)&EapolKeyInfo, 0, sizeof(EapolKeyInfo));

	memmove((u8 *)&EapolKeyInfo, (u8 *)&pMsg->KeyDesc.KeyInfo, sizeof(KEY_INFO));

	*((USHORT *)&EapolKeyInfo) = cpu2le16(*((USHORT *)&EapolKeyInfo));

	/* Choose WPA2 or not*/
	if ((pEntry->AuthMode == Ndis802_11AuthModeWPA2) || (pEntry->AuthMode == Ndis802_11AuthModeWPA2PSK))
		bWPA2 = true;

	/* 0. Check MsgType*/
	if ((MsgType > EAPOL_GROUP_MSG_2) || (MsgType < EAPOL_PAIR_MSG_1))
	{
		DBGPRINT(RT_DEBUG_ERROR, ("The message type is invalid(%d)! \n", MsgType));
		goto LabelErr;
	}

	/* 1. Replay counter check	*/
 	if (MsgType == EAPOL_PAIR_MSG_1 || MsgType == EAPOL_PAIR_MSG_3 || MsgType == EAPOL_GROUP_MSG_1)	/* For supplicant*/
    {
    	/* First validate replay counter, only accept message with larger replay counter.*/
		/* Let equal pass, some AP start with all zero replay counter*/
		u8 ZeroReplay[LEN_KEY_DESC_REPLAY];

        memset(ZeroReplay, 0, LEN_KEY_DESC_REPLAY);
		if ((RTMPCompareMemory(pMsg->KeyDesc.ReplayCounter, pEntry->R_Counter, LEN_KEY_DESC_REPLAY) != 1) &&
			(RTMPCompareMemory(pMsg->KeyDesc.ReplayCounter, ZeroReplay, LEN_KEY_DESC_REPLAY) != 0))
    	{
			bReplayDiff = true;
    	}
 	}
	else if (MsgType == EAPOL_PAIR_MSG_2 || MsgType == EAPOL_PAIR_MSG_4 || MsgType == EAPOL_GROUP_MSG_2)	/* For authenticator*/
	{
		/* check Replay Counter coresponds to MSG from authenticator, otherwise discard*/
	if (memcmp(pMsg->KeyDesc.ReplayCounter, pEntry->R_Counter, LEN_KEY_DESC_REPLAY) != 0)
    	{
			bReplayDiff = true;
    	}
	}

	/* Replay Counter different condition*/
	if (bReplayDiff)
	{
		if (MsgType < EAPOL_GROUP_MSG_1)
		{
           	DBGPRINT(RT_DEBUG_ERROR, ("Replay Counter Different in pairwise msg %d of 4-way handshake!\n", MsgType));
		}
		else
		{
			DBGPRINT(RT_DEBUG_ERROR, ("Replay Counter Different in group msg %d of 2-way handshake!\n", (MsgType - EAPOL_PAIR_MSG_4)));
		}

        goto LabelErr;
	}

	/* 2. Verify MIC except Pairwise Msg1*/
	if (MsgType != EAPOL_PAIR_MSG_1)
	{
		u8 		rcvd_mic[LEN_KEY_DESC_MIC];
		UINT			eapol_len = CONV_ARRARY_TO_UINT16(pMsg->Body_Len) + 4;

		/* Record the received MIC for check later*/
		memmove(rcvd_mic, pMsg->KeyDesc.KeyMic, LEN_KEY_DESC_MIC);
		memset(pMsg->KeyDesc.KeyMic, 0, LEN_KEY_DESC_MIC);

        if (EapolKeyInfo.KeyDescVer == KEY_DESC_TKIP)	/* TKIP*/
        {
            RT_HMAC_MD5(pEntry->PTK, LEN_PTK_KCK, (u8 *)pMsg, eapol_len, mic, MD5_DIGEST_SIZE);
        }
        else if (EapolKeyInfo.KeyDescVer == KEY_DESC_AES)	/* AES        */
        {
            RT_HMAC_SHA1(pEntry->PTK, LEN_PTK_KCK, (u8 *)pMsg, eapol_len, digest, SHA1_DIGEST_SIZE);
            memmove(mic, digest, LEN_KEY_DESC_MIC);
        }
                else if (EapolKeyInfo.KeyDescVer == KEY_DESC_EXT)	/* AES-128 */
                {
                        UINT mlen = AES_KEY128_LENGTH;
                        AES_CMAC((u8 *)pMsg, eapol_len, pEntry->PTK, LEN_PTK_KCK, mic, &mlen);
                }


        if (memcmp(rcvd_mic, mic, LEN_KEY_DESC_MIC) != 0)
        {
			if (MsgType < EAPOL_GROUP_MSG_1)
			{
            	DBGPRINT(RT_DEBUG_ERROR, ("MIC Different in pairwise msg %d of 4-way handshake!\n", MsgType));
			}
			else
			{
				DBGPRINT(RT_DEBUG_ERROR, ("MIC Different in group msg %d of 2-way handshake!\n", (MsgType - EAPOL_PAIR_MSG_4)));
			}

			goto LabelErr;
        }
	}

	/* 1. Decrypt the Key Data field if GTK is included.*/
	/* 2. Extract the context of the Key Data field if it exist.	 */
	/* The field in pairwise_msg_2_WPA1(WPA2) & pairwise_msg_3_WPA1 is clear.*/
	/* The field in group_msg_1_WPA1(WPA2) & pairwise_msg_3_WPA2 is encrypted.*/
	if (CONV_ARRARY_TO_UINT16(pMsg->KeyDesc.KeyDataLen) > 0)
	{
		/* Decrypt this field		*/
		if ((MsgType == EAPOL_PAIR_MSG_3 && bWPA2) || (MsgType == EAPOL_GROUP_MSG_1))
		{
			if((EapolKeyInfo.KeyDescVer == KEY_DESC_EXT) || (EapolKeyInfo.KeyDescVer == KEY_DESC_AES))
			{
				UINT aes_unwrap_len = 0;

				/* AES */
				AES_Key_Unwrap(pMsg->KeyDesc.KeyData,
									CONV_ARRARY_TO_UINT16(pMsg->KeyDesc.KeyDataLen),
							   &pEntry->PTK[LEN_PTK_KCK], LEN_PTK_KEK,
							   KEYDATA, &aes_unwrap_len);
				SET_UINT16_TO_ARRARY(pMsg->KeyDesc.KeyDataLen, aes_unwrap_len);
			}
			else
			{
				TKIP_GTK_KEY_UNWRAP(&pEntry->PTK[LEN_PTK_KCK],
									pMsg->KeyDesc.KeyIv,
									pMsg->KeyDesc.KeyData,
									CONV_ARRARY_TO_UINT16(pMsg->KeyDesc.KeyDataLen),
									KEYDATA);
			}

			if (!bWPA2 && (MsgType == EAPOL_GROUP_MSG_1))
				GroupKeyIndex = EapolKeyInfo.KeyIndex;

		}
		else if ((MsgType == EAPOL_PAIR_MSG_2) || (MsgType == EAPOL_PAIR_MSG_3 && !bWPA2))
		{
			memmove(KEYDATA, pMsg->KeyDesc.KeyData, CONV_ARRARY_TO_UINT16(pMsg->KeyDesc.KeyDataLen));
		}
		else
		{

			goto LabelOK;
		}

		/* Parse Key Data field to */
		/* 1. verify RSN IE for pairwise_msg_2_WPA1(WPA2) ,pairwise_msg_3_WPA1(WPA2)*/
		/* 2. verify KDE format for pairwise_msg_3_WPA2, group_msg_1_WPA2*/
		/* 3. update shared key for pairwise_msg_3_WPA2, group_msg_1_WPA1(WPA2)*/
		if (!RTMPParseEapolKeyData(pAd, KEYDATA,
								  CONV_ARRARY_TO_UINT16(pMsg->KeyDesc.KeyDataLen),
								  GroupKeyIndex, MsgType, bWPA2, pEntry))
		{
			goto LabelErr;
		}
	}

LabelOK:
	if (KEYDATA != NULL)
		kfree(KEYDATA);
	return true;

LabelErr:
	if (KEYDATA != NULL)
		kfree(KEYDATA);
	return false;
}


/*
    ==========================================================================
    Description:
        This is a function to initilize 4-way handshake

    Return:

    ==========================================================================
*/
void WPAStart4WayHS(
    struct rtmp_adapter *   pAd,
    MAC_TABLE_ENTRY  *pEntry,
    unsigned long			TimeInterval)
{
    u8           Header802_3[14];
	u8   		*mpool;
    PEAPOL_PACKET	pEapolFrame;
	u8 *			pBssid = NULL;
	u8 		group_cipher = Ndis802_11WEPDisabled;

#ifdef CONFIG_STA_SUPPORT
#endif /* CONFIG_STA_SUPPORT */

    DBGPRINT(RT_DEBUG_TRACE, ("===> WPAStart4WayHS\n"));

	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_RESET_IN_PROGRESS | fRTMP_ADAPTER_HALT_IN_PROGRESS))
	{
		DBGPRINT(RT_DEBUG_ERROR, ("[ERROR]WPAStart4WayHS : The interface is closed...\n"));
		return;
	}


	if (pBssid == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("[ERROR]WPAStart4WayHS : No corresponding Authenticator.\n"));
		return;
    }

	/* Check the status*/
    if ((pEntry->WpaState > AS_PTKSTART) || (pEntry->WpaState < AS_INITPMK))
    {
        DBGPRINT(RT_DEBUG_ERROR, ("[ERROR]WPAStart4WayHS : Not expect calling\n"));
        return;
    }


	/* Increment replay counter by 1*/
	ADD_ONE_To_64BIT_VAR(pEntry->R_Counter);

	/* Randomly generate ANonce		*/
	GenRandom(pAd, (u8 *)pBssid, pEntry->ANonce);

	/* Allocate memory for output*/
	mpool = kmalloc(TX_EAPOL_BUFFER, GFP_ATOMIC);
	if (mpool == NULL) {
		DBGPRINT(RT_DEBUG_ERROR, ("!!!%s : no memory!!!\n", __FUNCTION__));
		return;
	}

	pEapolFrame = (PEAPOL_PACKET)mpool;
	memset(pEapolFrame, 0, TX_EAPOL_BUFFER);

	/* Construct EAPoL message - Pairwise Msg 1*/
	/* EAPOL-Key(0,0,1,0,P,0,0,ANonce,0,DataKD_M1)		*/
	ConstructEapolMsg(pEntry,
					  group_cipher,
					  EAPOL_PAIR_MSG_1,
					  0,					/* Default key index*/
					  pEntry->ANonce,
					  NULL,					/* TxRSC*/
					  NULL,					/* GTK*/
					  NULL,					/* RSNIE*/
					  0,					/* RSNIE length	*/
					  pEapolFrame);


	/* Make outgoing frame*/
    MAKE_802_3_HEADER(Header802_3, pEntry->Addr, pBssid, EAPOL);
    RTMPToWirelessSta(pAd, pEntry, Header802_3,
					  LENGTH_802_3, (u8 *)pEapolFrame,
					  CONV_ARRARY_TO_UINT16(pEapolFrame->Body_Len) + 4,
					  (pEntry->PortSecured == WPA_802_1X_PORT_SECURED) ? false : true);

	/* Trigger Retry Timer*/
    RTMPModTimer(&pEntry->RetryTimer, TimeInterval);

	/* Update State*/
    pEntry->WpaState = AS_PTKSTART;

	kfree(mpool);

	DBGPRINT(RT_DEBUG_TRACE, ("<=== WPAStart4WayHS: send Msg1 of 4-way \n"));

}

/*
	========================================================================

	Routine Description:
		Process Pairwise key Msg-1 of 4-way handshaking and send Msg-2

	Arguments:
		pAd			Pointer	to our adapter
		Elem		Message body

	Return Value:
		None

	Note:

	========================================================================
*/
void PeerPairMsg1Action(
	struct rtmp_adapter *   pAd,
    MAC_TABLE_ENTRY  *pEntry,
    MLME_QUEUE_ELEM  *Elem)
{
	u8 			PTK[80];
	u8               Header802_3[14];
	PEAPOL_PACKET		pMsg1;
	UINT            	MsgLen;
	u8   			*mpool;
    PEAPOL_PACKET		pEapolFrame;
	u8 *				pCurrentAddr = NULL;
	u8 *				pmk_ptr = NULL;
	u8 			group_cipher = Ndis802_11WEPDisabled;
	u8 *				rsnie_ptr = NULL;
	u8 			rsnie_len = 0;

	DBGPRINT(RT_DEBUG_TRACE, ("===> PeerPairMsg1Action \n"));

	if ((!pEntry) || (!IS_ENTRY_CLIENT(pEntry) && !IS_ENTRY_APCLI(pEntry)))
		return;

    if (Elem->MsgLen < (LENGTH_802_11 + LENGTH_802_1_H + LENGTH_EAPOL_H + MIN_LEN_OF_EAPOL_KEY_MSG))
        return;

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		{
		pCurrentAddr = pAd->CurrentAddress;
		pmk_ptr = pAd->StaCfg.PMK;
		group_cipher = pAd->StaCfg.GroupCipher;
		rsnie_ptr = pAd->StaCfg.RSN_IE;
		rsnie_len = pAd->StaCfg.RSNIE_Len;
	}
	}
#endif /* CONFIG_STA_SUPPORT */

	if (pCurrentAddr == NULL)
		return;

	/* Store the received frame*/
	pMsg1 = (PEAPOL_PACKET) &Elem->Msg[LENGTH_802_11 + LENGTH_802_1_H];
	MsgLen = Elem->MsgLen - LENGTH_802_11 - LENGTH_802_1_H;

	/* Sanity Check peer Pairwise message 1 - Replay Counter*/
	if (PeerWpaMessageSanity(pAd, pMsg1, MsgLen, EAPOL_PAIR_MSG_1, pEntry) == false)
		return;

	/* Store Replay counter, it will use to verify message 3 and construct message 2*/
	memmove(pEntry->R_Counter, pMsg1->KeyDesc.ReplayCounter, LEN_KEY_DESC_REPLAY);

	/* Store ANonce*/
	memmove(pEntry->ANonce, pMsg1->KeyDesc.KeyNonce, LEN_KEY_DESC_NONCE);

	/* Generate random SNonce*/
	GenRandom(pAd, (u8 *)pCurrentAddr, pEntry->SNonce);

	{
	    /* Calculate PTK(ANonce, SNonce)*/
	    WpaDerivePTK(pAd,
	    			pmk_ptr,
			     	pEntry->ANonce,
				 	pEntry->Addr,
				 	pEntry->SNonce,
				 	pCurrentAddr,
				    PTK,
				    LEN_PTK);

		/* Save key to PTK entry*/
		memmove(pEntry->PTK, PTK, LEN_PTK);
	}

	/* Update WpaState*/
	pEntry->WpaState = AS_PTKINIT_NEGOTIATING;

	/* Allocate memory for output*/
	mpool = kmalloc(TX_EAPOL_BUFFER, GFP_ATOMIC);
	if (mpool == NULL) {
		DBGPRINT(RT_DEBUG_ERROR, ("!!!%s : no memory!!!\n", __FUNCTION__));
		return;
	}

	pEapolFrame = (PEAPOL_PACKET)mpool;
	memset(pEapolFrame, 0, TX_EAPOL_BUFFER);

	/* Construct EAPoL message - Pairwise Msg 2*/
	/*  EAPOL-Key(0,1,0,0,P,0,0,SNonce,MIC,DataKD_M2)*/
	ConstructEapolMsg(pEntry,
					  group_cipher,
					  EAPOL_PAIR_MSG_2,
					  0,				/* DefaultKeyIdx*/
					  pEntry->SNonce,
					  NULL,				/* TxRsc*/
					  NULL,				/* GTK*/
					  (u8 *)rsnie_ptr,
					  rsnie_len,
					  pEapolFrame);

	/* Make outgoing frame*/
	MAKE_802_3_HEADER(Header802_3, pEntry->Addr, pCurrentAddr, EAPOL);

	RTMPToWirelessSta(pAd, pEntry,
					  Header802_3, sizeof(Header802_3), (u8 *)pEapolFrame,
					  CONV_ARRARY_TO_UINT16(pEapolFrame->Body_Len) + 4, true);

	kfree(mpool);

	DBGPRINT(RT_DEBUG_TRACE, ("<=== PeerPairMsg1Action: send Msg2 of 4-way \n"));
}


/*
    ==========================================================================
    Description:
        When receiving the second packet of 4-way pairwisekey handshake.
    Return:
    ==========================================================================
*/
void PeerPairMsg2Action(
    struct rtmp_adapter *   pAd,
    MAC_TABLE_ENTRY  *pEntry,
    MLME_QUEUE_ELEM  *Elem)
{
	u8 			PTK[80];
    bool             Cancelled;
    PHEADER_802_11      pHeader;
	u8   			*mpool;
	PEAPOL_PACKET		pEapolFrame;
	PEAPOL_PACKET       pMsg2;
	UINT            	MsgLen;
    u8               Header802_3[LENGTH_802_3];
	u8 				TxTsc[6];
	u8 *				pBssid = NULL;
	u8 *				pmk_ptr = NULL;
	u8 *				gtk_ptr = NULL;
	u8 			default_key = 0;
	u8 			group_cipher = Ndis802_11WEPDisabled;
	u8 *				rsnie_ptr = NULL;
	u8 			rsnie_len = 0;

    DBGPRINT(RT_DEBUG_TRACE, ("===> PeerPairMsg2Action \n"));

    if ((!pEntry) || !IS_ENTRY_CLIENT(pEntry))
        return;

    if (Elem->MsgLen < (LENGTH_802_11 + LENGTH_802_1_H + LENGTH_EAPOL_H + MIN_LEN_OF_EAPOL_KEY_MSG))
        return;

    /* check Entry in valid State*/
    if (pEntry->WpaState < AS_PTKSTART)
        return;



    /* pointer to 802.11 header*/
	pHeader = (PHEADER_802_11)Elem->Msg;

	/* skip 802.11_header(24-byte) and LLC_header(8) */
	pMsg2 = (PEAPOL_PACKET)&Elem->Msg[LENGTH_802_11 + LENGTH_802_1_H];
	MsgLen = Elem->MsgLen - LENGTH_802_11 - LENGTH_802_1_H;

	/* Store SNonce*/
	memmove(pEntry->SNonce, pMsg2->KeyDesc.KeyNonce, LEN_KEY_DESC_NONCE);

	{
		/* Derive PTK*/
		if ((pmk_ptr == NULL) || (pBssid == NULL))
		{
			DBGPRINT(RT_DEBUG_ERROR,
					("%s: pmk_ptr or pBssid == NULL!\n", __FUNCTION__));
			return;
		}

		WpaDerivePTK(pAd,
					(u8 *)pmk_ptr,
					pEntry->ANonce, 		/* ANONCE*/
					(u8 *)pBssid,
					pEntry->SNonce, 		/* SNONCE*/
					pEntry->Addr,
					PTK,
					LEN_PTK);

    	memmove(pEntry->PTK, PTK, LEN_PTK);
	}

	/* Sanity Check peer Pairwise message 2 - Replay Counter, MIC, RSNIE*/
	if (PeerWpaMessageSanity(pAd, pMsg2, MsgLen, EAPOL_PAIR_MSG_2, pEntry) == false)
		return;

    do
    {
		/* Allocate memory for input*/
		mpool = kmalloc(TX_EAPOL_BUFFER, GFP_ATOMIC);
		if (mpool == NULL)
	    {
	        DBGPRINT(RT_DEBUG_ERROR, ("!!!%s : no memory!!!\n", __FUNCTION__));
	        return;
	    }

		pEapolFrame = (PEAPOL_PACKET)mpool;
		memset(pEapolFrame, 0, TX_EAPOL_BUFFER);

        /* delete retry timer*/
		RTMPCancelTimer(&pEntry->RetryTimer, &Cancelled);

		/* Change state*/
        pEntry->WpaState = AS_PTKINIT_NEGOTIATING;

		/* Increment replay counter by 1*/
		ADD_ONE_To_64BIT_VAR(pEntry->R_Counter);

		/* Construct EAPoL message - Pairwise Msg 3*/
		ConstructEapolMsg(pEntry,
						  group_cipher,
						  EAPOL_PAIR_MSG_3,
						  default_key,
						  pEntry->ANonce,
						  TxTsc,
						  (u8 *)gtk_ptr,
						  (u8 *)rsnie_ptr,
						  rsnie_len,
						  pEapolFrame);

        /* Make outgoing frame*/
        MAKE_802_3_HEADER(Header802_3, pEntry->Addr, pBssid, EAPOL);
        RTMPToWirelessSta(pAd, pEntry, Header802_3, LENGTH_802_3,
						  (u8 *)pEapolFrame,
						  CONV_ARRARY_TO_UINT16(pEapolFrame->Body_Len) + 4,
						  (pEntry->PortSecured == WPA_802_1X_PORT_SECURED) ? false : true);

        pEntry->ReTryCounter = PEER_MSG3_RETRY_TIMER_CTR;
		RTMPSetTimer(&pEntry->RetryTimer, PEER_MSG3_RETRY_EXEC_INTV);

		/* Update State*/
        pEntry->WpaState = AS_PTKINIT_NEGOTIATING;

		kfree(mpool);

    }while(false);

	DBGPRINT(RT_DEBUG_TRACE, ("<=== PeerPairMsg2Action: send Msg3 of 4-way \n"));
}

/*
	========================================================================

	Routine Description:
		Process Pairwise key Msg 3 of 4-way handshaking and send Msg 4

	Arguments:
		pAd	Pointer	to our adapter
		Elem		Message body

	Return Value:
		None

	Note:

	========================================================================
*/
void PeerPairMsg3Action(
    struct rtmp_adapter *   pAd,
    MAC_TABLE_ENTRY  *pEntry,
    MLME_QUEUE_ELEM  *Elem)
{
	PHEADER_802_11		pHeader;
	u8               Header802_3[14];
	u8 			*mpool;
	PEAPOL_PACKET		pEapolFrame;
	PEAPOL_PACKET		pMsg3;
	UINT            	MsgLen;
	u8 *				pCurrentAddr = NULL;
	u8 			group_cipher = Ndis802_11WEPDisabled;

	DBGPRINT(RT_DEBUG_TRACE, ("===> PeerPairMsg3Action \n"));

	if ((!pEntry) || (!IS_ENTRY_CLIENT(pEntry) && !IS_ENTRY_APCLI(pEntry)))
		return;

    if (Elem->MsgLen < (LENGTH_802_11 + LENGTH_802_1_H + LENGTH_EAPOL_H + MIN_LEN_OF_EAPOL_KEY_MSG))
		return;

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		{
		pCurrentAddr = pAd->CurrentAddress;
		group_cipher = pAd->StaCfg.GroupCipher;

	}
	}
#endif /* CONFIG_STA_SUPPORT */

	if (pCurrentAddr == NULL)
		return;

	/* Record 802.11 header & the received EAPOL packet Msg3*/
	pHeader	= (PHEADER_802_11) Elem->Msg;
	pMsg3 = (PEAPOL_PACKET) &Elem->Msg[LENGTH_802_11 + LENGTH_802_1_H];
	MsgLen = Elem->MsgLen - LENGTH_802_11 - LENGTH_802_1_H;

	/* Sanity Check peer Pairwise message 3 - Replay Counter, MIC, RSNIE*/
	if (PeerWpaMessageSanity(pAd, pMsg3, MsgLen, EAPOL_PAIR_MSG_3, pEntry) == false)
		return;

	/* Save Replay counter, it will use construct message 4*/
	memmove(pEntry->R_Counter, pMsg3->KeyDesc.ReplayCounter, LEN_KEY_DESC_REPLAY);

	/* Double check ANonce*/
	if (memcmp(pEntry->ANonce, pMsg3->KeyDesc.KeyNonce, LEN_KEY_DESC_NONCE) != 0)
	{
		return;
	}

	/* Allocate memory for output*/
	mpool = kmalloc(TX_EAPOL_BUFFER, GFP_ATOMIC);
	if (mpool == NULL) {
		DBGPRINT(RT_DEBUG_ERROR, ("!!!%s : no memory!!!\n", __FUNCTION__));
		return;
	}

	pEapolFrame = (PEAPOL_PACKET)mpool;
	memset(pEapolFrame, 0, TX_EAPOL_BUFFER);

	/* Construct EAPoL message - Pairwise Msg 4*/
	ConstructEapolMsg(pEntry,
					  group_cipher,
					  EAPOL_PAIR_MSG_4,
					  0,					/* group key index not used in message 4*/
					  NULL,					/* Nonce not used in message 4*/
					  NULL,					/* TxRSC not used in message 4*/
					  NULL,					/* GTK not used in message 4*/
					  NULL,					/* RSN IE not used in message 4*/
					  0,
					  pEapolFrame);

	/* Update WpaState*/
	pEntry->WpaState = AS_PTKINITDONE;
	/* Update pairwise key		*/
#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		{
		memmove(pAd->StaCfg.PTK, pEntry->PTK, LEN_PTK);
		WPAInstallPairwiseKey(pAd,
							  BSS0,
							  pEntry,
							  false);
		memmove(&pAd->SharedKey[BSS0][0], &pEntry->PairwiseKey, sizeof(CIPHER_KEY));
	}
	}
#endif /* CONFIG_STA_SUPPORT */

	/* open 802.1x port control and privacy filter*/
	if (pEntry->AuthMode == Ndis802_11AuthModeWPA2PSK ||
		pEntry->AuthMode == Ndis802_11AuthModeWPA2)
	{
		pEntry->PortSecured = WPA_802_1X_PORT_SECURED;
		pEntry->PrivacyFilter = Ndis802_11PrivFilterAcceptAll;

#ifdef CONFIG_STA_SUPPORT
		STA_PORT_SECURED(pAd);
#endif /* CONFIG_STA_SUPPORT */
		DBGPRINT(RT_DEBUG_TRACE, ("PeerPairMsg3Action: AuthMode(%s) PairwiseCipher(%s) GroupCipher(%s) \n",
									GetAuthMode(pEntry->AuthMode),
									GetEncryptType(pEntry->WepStatus),
									GetEncryptType(group_cipher)));
	}
	else
	{
	}

	/* Init 802.3 header and send out*/
	MAKE_802_3_HEADER(Header802_3, pEntry->Addr, pCurrentAddr, EAPOL);
	RTMPToWirelessSta(pAd, pEntry,
					  Header802_3, sizeof(Header802_3),
					  (u8 *)pEapolFrame,
					  CONV_ARRARY_TO_UINT16(pEapolFrame->Body_Len) + 4, true);

	kfree(mpool);


	DBGPRINT(RT_DEBUG_TRACE, ("<=== PeerPairMsg3Action: send Msg4 of 4-way \n"));
}

/*
    ==========================================================================
    Description:
        When receiving the last packet of 4-way pairwisekey handshake.
        Initilize 2-way groupkey handshake following.
    Return:
    ==========================================================================
*/
void PeerPairMsg4Action(
    struct rtmp_adapter *   pAd,
    MAC_TABLE_ENTRY  *pEntry,
    MLME_QUEUE_ELEM  *Elem)
{
	PEAPOL_PACKET   	pMsg4;
    PHEADER_802_11      pHeader;
    UINT            	MsgLen;
    bool             Cancelled;
	u8 			group_cipher = Ndis802_11WEPDisabled;

    DBGPRINT(RT_DEBUG_TRACE, ("===> PeerPairMsg4Action\n"));

    do
    {
        if ((!pEntry) || !IS_ENTRY_CLIENT(pEntry))
            break;

        if (Elem->MsgLen < (LENGTH_802_11 + LENGTH_802_1_H + LENGTH_EAPOL_H + MIN_LEN_OF_EAPOL_KEY_MSG ) )
            break;

        if (pEntry->WpaState < AS_PTKINIT_NEGOTIATING)
            break;


        /* pointer to 802.11 header*/
        pHeader = (PHEADER_802_11)Elem->Msg;

		/* skip 802.11_header(24-byte) and LLC_header(8) */
		pMsg4 = (PEAPOL_PACKET)&Elem->Msg[LENGTH_802_11 + LENGTH_802_1_H];
		MsgLen = Elem->MsgLen - LENGTH_802_11 - LENGTH_802_1_H;

        /* Sanity Check peer Pairwise message 4 - Replay Counter, MIC*/
		if (PeerWpaMessageSanity(pAd, pMsg4, MsgLen, EAPOL_PAIR_MSG_4, pEntry) == false)
			break;

        /* 3. Install pairwise key */
		WPAInstallPairwiseKey(pAd, pEntry->apidx, pEntry, true);

        /* 4. upgrade state */
        pEntry->PrivacyFilter = Ndis802_11PrivFilterAcceptAll;
        pEntry->WpaState = AS_PTKINITDONE;
		pEntry->PortSecured = WPA_802_1X_PORT_SECURED;


		if (pEntry->AuthMode == Ndis802_11AuthModeWPA2 ||
			pEntry->AuthMode == Ndis802_11AuthModeWPA2PSK)
		{
			pEntry->GTKState = REKEY_ESTABLISHED;
			RTMPCancelTimer(&pEntry->RetryTimer, &Cancelled);

	        DBGPRINT(RT_DEBUG_OFF, ("AP SETKEYS DONE - WPA2, AuthMode(%d)=%s, WepStatus(%d)=%s, GroupWepStatus(%d)=%s\n\n",
									pEntry->AuthMode, GetAuthMode(pEntry->AuthMode),
									pEntry->WepStatus, GetEncryptType(pEntry->WepStatus),
									group_cipher,
									GetEncryptType(group_cipher)));
		}
		else
		{
        	/* 5. init Group 2-way handshake if necessary.*/
	        WPAStart2WayGroupHS(pAd, pEntry);

        	pEntry->ReTryCounter = GROUP_MSG1_RETRY_TIMER_CTR;
			RTMPModTimer(&pEntry->RetryTimer, PEER_MSG3_RETRY_EXEC_INTV);
		}
    }while(false);

}

/*
    ==========================================================================
    Description:
        This is a function to send the first packet of 2-way groupkey handshake
    Return:

    ==========================================================================
*/
void WPAStart2WayGroupHS(
    struct rtmp_adapter *   pAd,
    MAC_TABLE_ENTRY  *pEntry)
{
    u8               Header802_3[14];
	u8   			TxTsc[6];
	u8   			*mpool;
	PEAPOL_PACKET		pEapolFrame;
	u8 			group_cipher = Ndis802_11WEPDisabled;
	u8 			default_key = 0;
	u8 *				gnonce_ptr = NULL;
	u8 *				gtk_ptr = NULL;
	u8 *				pBssid = NULL;

	DBGPRINT(RT_DEBUG_TRACE, ("===> WPAStart2WayGroupHS\n"));

    if ((!pEntry) || !IS_ENTRY_CLIENT(pEntry))
        return;


	/* Allocate memory for output*/
	mpool = kmalloc(TX_EAPOL_BUFFER, GFP_ATOMIC);
	if (mpool == NULL) {
		DBGPRINT(RT_DEBUG_ERROR, ("!!!%s : no memory!!!\n", __FUNCTION__));
		return;
	}

	pEapolFrame = (PEAPOL_PACKET)mpool;
	memset(pEapolFrame, 0, TX_EAPOL_BUFFER);

    /* Increment replay counter by 1*/
	ADD_ONE_To_64BIT_VAR(pEntry->R_Counter);

	/* Construct EAPoL message - Group Msg 1*/
	ConstructEapolMsg(pEntry,
					  group_cipher,
					  EAPOL_GROUP_MSG_1,
					  default_key,
					  (u8 *)gnonce_ptr,
					  TxTsc,
					  (u8 *)gtk_ptr,
					  NULL,
					  0,
				  	  pEapolFrame);

	/* Make outgoing frame*/
	if (pBssid == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: pBssid == NULL!\n", __FUNCTION__));
		return;
	}

    MAKE_802_3_HEADER(Header802_3, pEntry->Addr, pBssid, EAPOL);
    RTMPToWirelessSta(pAd, pEntry,
					  Header802_3, LENGTH_802_3,
					  (u8 *)pEapolFrame,
					  CONV_ARRARY_TO_UINT16(pEapolFrame->Body_Len) + 4, false);

	kfree(mpool);

    DBGPRINT(RT_DEBUG_TRACE, ("<=== WPAStart2WayGroupHS : send out Group Message 1 \n"));

    return;
}

/*
	========================================================================

	Routine Description:
		Process Group key 2-way handshaking

	Arguments:
		pAd	Pointer	to our adapter
		Elem		Message body

	Return Value:
		None

	Note:

	========================================================================
*/
void PeerGroupMsg1Action(
	struct rtmp_adapter *   pAd,
    MAC_TABLE_ENTRY  *pEntry,
    MLME_QUEUE_ELEM  *Elem)
{
    u8               Header802_3[14];
	u8 			*mpool;
	PEAPOL_PACKET		pEapolFrame;
	PEAPOL_PACKET		pGroup;
	UINT            	MsgLen;
	u8 			default_key = 0;
	u8 			group_cipher = Ndis802_11WEPDisabled;
	u8 *				pCurrentAddr = NULL;
#ifdef APCLI_SUPPORT
	bool             Cancelled;
#endif /* APCLI_SUPPORT */

	DBGPRINT(RT_DEBUG_TRACE, ("===> PeerGroupMsg1Action \n"));

	if ((!pEntry) || (!IS_ENTRY_CLIENT(pEntry) && !IS_ENTRY_APCLI(pEntry)))
        return;

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		pCurrentAddr = pAd->CurrentAddress;
		group_cipher = pAd->StaCfg.GroupCipher;
		default_key = pAd->StaCfg.DefaultKeyId;
	}
#endif /* CONFIG_STA_SUPPORT */

	if (pCurrentAddr == NULL)
		return;

	/* Process Group Message 1 frame. skip 802.11 header(24) & LLC_SNAP header(8)*/
	pGroup = (PEAPOL_PACKET) &Elem->Msg[LENGTH_802_11 + LENGTH_802_1_H];
	MsgLen = Elem->MsgLen - LENGTH_802_11 - LENGTH_802_1_H;

	/* Sanity Check peer group message 1 - Replay Counter, MIC, RSNIE*/
	if (PeerWpaMessageSanity(pAd, pGroup, MsgLen, EAPOL_GROUP_MSG_1, pEntry) == false)
		return;

	/* delete retry timer*/

	/* Save Replay counter, it will use to construct message 2*/
	memmove(pEntry->R_Counter, pGroup->KeyDesc.ReplayCounter, LEN_KEY_DESC_REPLAY);

	/* Allocate memory for output*/
	mpool = kmalloc(TX_EAPOL_BUFFER, GFP_ATOMIC);
	if (mpool == NULL) {
		DBGPRINT(RT_DEBUG_ERROR, ("!!!%s : no memory!!!\n", __FUNCTION__));
		return;
	}

	pEapolFrame = (PEAPOL_PACKET)mpool;
	memset(pEapolFrame, 0, TX_EAPOL_BUFFER);


	/* Construct EAPoL message - Group Msg 2*/
	ConstructEapolMsg(pEntry,
					  group_cipher,
					  EAPOL_GROUP_MSG_2,
					  default_key,
					  NULL,					/* Nonce not used*/
					  NULL,					/* TxRSC not used*/
					  NULL,					/* GTK not used*/
					  NULL,					/* RSN IE not used*/
					  0,
					  pEapolFrame);

    /* open 802.1x port control and privacy filter*/
	pEntry->PortSecured = WPA_802_1X_PORT_SECURED;
	pEntry->PrivacyFilter = Ndis802_11PrivFilterAcceptAll;

#ifdef CONFIG_STA_SUPPORT
	STA_PORT_SECURED(pAd);
#endif /* CONFIG_STA_SUPPORT */

	DBGPRINT(RT_DEBUG_TRACE, ("PeerGroupMsg1Action: AuthMode(%s) PairwiseCipher(%s) GroupCipher(%s) \n",
									GetAuthMode(pEntry->AuthMode),
									GetEncryptType(pEntry->WepStatus),
									GetEncryptType(group_cipher)));

	/* init header and Fill Packet and send Msg 2 to authenticator	*/
	MAKE_802_3_HEADER(Header802_3, pEntry->Addr, pCurrentAddr, EAPOL);

#ifdef CONFIG_STA_SUPPORT
	if ((pAd->OpMode == OPMODE_STA) && INFRA_ON(pAd) &&
		OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED) &&
		RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS) &&
		(pAd->MlmeAux.Channel == pAd->CommonCfg.Channel)
		)
	{
		/* Now stop the scanning and need to send the rekey packet out */
		pAd->MlmeAux.Channel = 0;
	}
#endif /* CONFIG_STA_SUPPORT */

	RTMPToWirelessSta(pAd, pEntry,
					  Header802_3, sizeof(Header802_3),
					  (u8 *)pEapolFrame,
					  CONV_ARRARY_TO_UINT16(pEapolFrame->Body_Len) + 4, false);

	kfree(mpool);


	DBGPRINT(RT_DEBUG_TRACE, ("<=== PeerGroupMsg1Action: send group message 2\n"));
}


void EnqueueStartForPSKExec(
    void *SystemSpecific1,
    void *FunctionContext,
    void *SystemSpecific2,
    void *SystemSpecific3)
{
	MAC_TABLE_ENTRY     *pEntry = (PMAC_TABLE_ENTRY) FunctionContext;

	if ((pEntry) && IS_ENTRY_CLIENT(pEntry) && (pEntry->WpaState < AS_PTKSTART))
	{
		struct rtmp_adapter *pAd = (struct rtmp_adapter *)pEntry->pAd;

		switch (pEntry->EnqueueEapolStartTimerRunning)
		{
			case EAPOL_START_PSK:
				DBGPRINT(RT_DEBUG_TRACE, ("Enqueue EAPoL-Start-PSK for sta(%02x:%02x:%02x:%02x:%02x:%02x) \n", PRINT_MAC(pEntry->Addr)));

				MlmeEnqueue(pAd, WPA_STATE_MACHINE, MT2_EAPOLStart, 6, &pEntry->Addr, 0);
				break;
			default:
				break;

		}
	}
		pEntry->EnqueueEapolStartTimerRunning = EAPOL_START_DISABLE;

}


void MlmeDeAuthAction(
    struct rtmp_adapter *   pAd,
    MAC_TABLE_ENTRY  *pEntry,
	USHORT           Reason,
	bool          bDataFrameFirst)
{
    u8 *         pOutBuffer = NULL;
    unsigned long           FrameLen = 0;
    HEADER_802_11   DeAuthHdr;

    if (pEntry)
    {
        /* Send out a Deauthentication request frame*/
        pOutBuffer = kmalloc(MGMT_DMA_BUFFER_SIZE, GFP_ATOMIC);
        if (pOutBuffer == NULL)
            return;

        DBGPRINT(RT_DEBUG_TRACE, ("Send DEAUTH frame with ReasonCode(%d) to %02x:%02x:%02x:%02x:%02x:%02x \n",Reason, PRINT_MAC(pEntry->Addr)));

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
        MgtMacHeaderInit(pAd, &DeAuthHdr, SUBTYPE_DEAUTH, 0, pEntry->Addr, pAd->CommonCfg.Bssid);
	}
#endif /* CONFIG_STA_SUPPORT */
        MakeOutgoingFrame(pOutBuffer,               &FrameLen,
                          sizeof(HEADER_802_11),    &DeAuthHdr,
                          2,                        &Reason,
                          END_OF_ARGS);



		if (bDataFrameFirst)
            MiniportMMRequest(pAd, MGMT_USE_QUEUE_FLAG, pOutBuffer, FrameLen);
        else
            MiniportMMRequest(pAd, 0, pOutBuffer, FrameLen);
        kfree(pOutBuffer);

        /* ApLogEvent(pAd, pEntry->Addr, EVENT_DISASSOCIATED);*/
        MacTableDeleteEntry(pAd, pEntry->Aid, pEntry->Addr);
    }
}


/*
    ==========================================================================
    Description:
        When receiving the last packet of 2-way groupkey handshake.
    Return:
    ==========================================================================
*/
void PeerGroupMsg2Action(
    struct rtmp_adapter *   pAd,
    MAC_TABLE_ENTRY  *pEntry,
    void             *Msg,
    UINT             MsgLen)
{
    UINT            	Len;
    u8 *         	pData;
    bool         	Cancelled;
	PEAPOL_PACKET       pMsg2;
	u8 			group_cipher = Ndis802_11WEPDisabled;

	DBGPRINT(RT_DEBUG_TRACE, ("===> PeerGroupMsg2Action \n"));

    if ((!pEntry) || !IS_ENTRY_CLIENT(pEntry))
        return;

    if (MsgLen < (LENGTH_802_1_H + LENGTH_EAPOL_H + MIN_LEN_OF_EAPOL_KEY_MSG))
        return;

    if (pEntry->WpaState != AS_PTKINITDONE)
        return;


    do
    {


        pData = (u8 *)Msg;
		pMsg2 = (PEAPOL_PACKET) (pData + LENGTH_802_1_H);
        Len = MsgLen - LENGTH_802_1_H;

		/* Sanity Check peer group message 2 - Replay Counter, MIC*/
		if (PeerWpaMessageSanity(pAd, pMsg2, Len, EAPOL_GROUP_MSG_2, pEntry) == false)
            break;

        /* 3.  upgrade state*/

		RTMPCancelTimer(&pEntry->RetryTimer, &Cancelled);
        pEntry->GTKState = REKEY_ESTABLISHED;

		if ((pEntry->AuthMode == Ndis802_11AuthModeWPA2) || (pEntry->AuthMode == Ndis802_11AuthModeWPA2PSK))
		{
			DBGPRINT(RT_DEBUG_OFF, ("AP SETKEYS DONE - WPA2, AuthMode(%d)=%s, WepStatus(%d)=%s, GroupWepStatus(%d)=%s\n\n",
										pEntry->AuthMode, GetAuthMode(pEntry->AuthMode),
										pEntry->WepStatus, GetEncryptType(pEntry->WepStatus),
										group_cipher, GetEncryptType(group_cipher)));
		}
		else
		{
        	DBGPRINT(RT_DEBUG_OFF, ("AP SETKEYS DONE - WPA1, AuthMode(%d)=%s, WepStatus(%d)=%s, GroupWepStatus(%d)=%s\n\n",
										pEntry->AuthMode, GetAuthMode(pEntry->AuthMode),
										pEntry->WepStatus, GetEncryptType(pEntry->WepStatus),
										group_cipher, GetEncryptType(group_cipher)));
		}
    }while(false);
}

/*
	========================================================================

	Routine Description:
		Classify WPA EAP message type

	Arguments:
		EAPType		Value of EAP message type
		MsgType		Internal Message definition for MLME state machine

	Return Value:
		true		Found appropriate message type
		false		No appropriate message type

	IRQL = DISPATCH_LEVEL

	Note:
		All these constants are defined in wpa_cmm.h
		For supplicant, there is only EAPOL Key message avaliable

	========================================================================
*/
bool WpaMsgTypeSubst(
	u8 EAPType,
	INT		*MsgType)
{
	switch (EAPType)
	{
		case EAPPacket:
			*MsgType = MT2_EAPPacket;
			break;
		case EAPOLStart:
			*MsgType = MT2_EAPOLStart;
			break;
		case EAPOLLogoff:
			*MsgType = MT2_EAPOLLogoff;
			break;
		case EAPOLKey:
			*MsgType = MT2_EAPOLKey;
			break;
		case EAPOLASFAlert:
			*MsgType = MT2_EAPOLASFAlert;
			break;
		default:
			return false;
	}
	return true;
}

/**
 * inc_iv_byte - Increment arbitrary length byte array
 * @counter: Pointer to byte array
 * @len: Length of the counter in bytes
 *
 * This function increments the least byte of the counter by one and continues
 * rolling over to more significant bytes if the byte was incremented from
 * 0xff to 0x00.
 */
void inc_iv_byte(u8 *iv, UINT len, UINT cnt)
{
	int 	pos = 0;
	int 	carry = 0;
	u8 pre_iv;

	while (pos < len)
	{
		pre_iv = iv[pos];

		if (carry == 1)
			iv[pos] ++;
		else
			iv[pos] += cnt;

		if (iv[pos] > pre_iv)
			break;

		carry = 1;
		pos++;
	}

	if (pos >= len)
		DBGPRINT(RT_DEBUG_WARN, ("!!! inc_iv_byte overflow !!!\n"));
}



/*
	========================================================================

	Routine Description:
		The pseudo-random function(PRF) that hashes various inputs to
		derive a pseudo-random value. To add liveness to the pseudo-random
		value, a nonce should be one of the inputs.

		It is used to generate PTK, GTK or some specific random value.

	Arguments:
		u8 *key,		-	the key material for HMAC_SHA1 use
		INT		key_len		-	the length of key
		u8 *prefix		-	a prefix label
		INT		prefix_len	-	the length of the label
		u8 *data		-	a specific data with variable length
		INT		data_len	-	the length of a specific data
		INT		len			-	the output lenght

	Return Value:
		u8 *output		-	the calculated result

	Note:
		802.11i-2004	Annex H.3

	========================================================================
*/
void PRF(
	u8 *key,
	INT		key_len,
	u8 *prefix,
	INT		prefix_len,
	u8 *data,
	INT		data_len,
	u8 *output,
	INT		len)
{
	INT		i;
    u8   *input;
	INT		currentindex = 0;
	INT		total_len;

	/* Allocate memory for input*/
	/* ULLI : need check return value ? */
	input = kmalloc(1024, GFP_ATOMIC);

	if (input == NULL) {
		DBGPRINT(RT_DEBUG_ERROR, ("!!!PRF: no memory!!!\n"));
		return;
	}

	/* Generate concatenation input*/
	memmove(input, prefix, prefix_len);

	/* Concatenate a single octet containing 0*/
	input[prefix_len] =	0;

	/* Concatenate specific data*/
	memmove(&input[prefix_len + 1], data, data_len);
	total_len =	prefix_len + 1 + data_len;

	/* Concatenate a single octet containing 0*/
	/* This octet shall be update later*/
	input[total_len] = 0;
	total_len++;

	/* Iterate to calculate the result by hmac-sha-1*/
	/* Then concatenate to last result*/
	for	(i = 0;	i <	(len + 19) / 20; i++)
	{
		RT_HMAC_SHA1(key, key_len, input, total_len, &output[currentindex], SHA1_DIGEST_SIZE);
		currentindex +=	20;

		/* update the last octet */
		input[total_len - 1]++;
	}
    kfree(input);
}

/*
* F(P, S, c, i) = U1 xor U2 xor ... Uc
* U1 = PRF(P, S || Int(i))
* U2 = PRF(P, U1)
* Uc = PRF(P, Uc-1)
*/

static void F(char *password, unsigned char *ssid, int ssidlength, int iterations, int count, unsigned char *output)
{
    unsigned char digest[36], digest1[SHA1_DIGEST_SIZE];
    int i, j, len;

	len = strlen(password);

    /* U1 = PRF(P, S || int(i)) */
    memcpy(digest, ssid, ssidlength);
    digest[ssidlength] = (unsigned char)((count>>24) & 0xff);
    digest[ssidlength+1] = (unsigned char)((count>>16) & 0xff);
    digest[ssidlength+2] = (unsigned char)((count>>8) & 0xff);
    digest[ssidlength+3] = (unsigned char)(count & 0xff);
    RT_HMAC_SHA1((unsigned char*) password, len, digest, ssidlength+4, digest1, SHA1_DIGEST_SIZE); /* for WPA update*/

    /* output = U1 */
    memcpy(output, digest1, SHA1_DIGEST_SIZE);
    for (i = 1; i < iterations; i++)
    {
        /* Un = PRF(P, Un-1) */
        RT_HMAC_SHA1((unsigned char*) password, len, digest1, SHA1_DIGEST_SIZE, digest, SHA1_DIGEST_SIZE); /* for WPA update*/
        memcpy(digest1, digest, SHA1_DIGEST_SIZE);

        /* output = output xor Un */
        for (j = 0; j < SHA1_DIGEST_SIZE; j++)
        {
            output[j] ^= digest[j];
        }
    }
}

/*
* password - ascii string up to 63 characters in length
* ssid - octet string up to 32 octets
* ssidlength - length of ssid in octets
* output must be 40 octets in length and outputs 256 bits of key
*/
int RtmpPasswordHash(char *password, u8 *ssid, INT ssidlength, u8 *output)
{
    if ((strlen(password) > 63) || (ssidlength > 32))
        return 0;

    F(password, ssid, ssidlength, 4096, 1, output);
    F(password, ssid, ssidlength, 4096, 2, &output[SHA1_DIGEST_SIZE]);
    return 1;
}

/*
	========================================================================

	Routine Description:
		The key derivation function(KDF) is defined in IEEE 802.11r/D9.0, 8.5.1.5.2

	Arguments:

	Return Value:

	Note:
		Output \A1\F6 KDF-Length (K, label, Context) where
		Input:    K, a 256-bit key derivation key
				  label, a string identifying the purpose of the keys derived using this KDF
				  Context, a bit string that provides context to identify the derived key
				  Length, the length of the derived key in bits
		Output: a Length-bit derived key

		result \A1\F6 ""
		iterations \A1\F6 (Length+255)/256
		do i = 1 to iterations
			result \A1\F6 result || HMAC-SHA256(K, i || label || Context || Length)
		od
		return first Length bits of result, and securely delete all unused bits

		In this algorithm, i and Length are encoded as 16-bit unsigned integers.

	========================================================================
*/
void KDF(
	u8 *	key,
	INT		key_len,
	u8 *	label,
	INT		label_len,
	u8 *	data,
	INT		data_len,
	u8 *	output,
	USHORT	len)
{
	USHORT	i;
    u8   *input;
	INT		currentindex = 0;
	INT		total_len;
	UINT	len_in_bits = (len << 3);

	input = kmalloc(1024, GFP_ATOMIC);

	if (input == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("!!!KDF: no memory!!!\n"));
		return;
	}

	memset(input, 0, 1024);

	/* Initial concatenated value (i || label || Context || Length)*/
	/* concatenate 16-bit unsigned integer, its initial value is 1.	*/
	input[0] = 1;
	input[1] = 0;
	total_len = 2;

	/* concatenate a prefix string*/
	memmove(&input[total_len], label, label_len);
	total_len += label_len;

	/* concatenate the context*/
	memmove(&input[total_len], data, data_len);
	total_len += data_len;

	/* concatenate the length in bits (16-bit unsigned integer)*/
	input[total_len] = (len_in_bits & 0xFF);
	input[total_len + 1] = (len_in_bits & 0xFF00) >> 8;
	total_len += 2;

	for	(i = 1;	i <= ((len_in_bits + 255) / 256); i++)
	{
		/* HMAC-SHA256 derives output */
		RT_HMAC_SHA256((u8 *)key, key_len, input, total_len, (u8 *)&output[currentindex], 32);

		currentindex +=	32; /* next concatenation location*/
		input[0]++;			/* increment octet count*/

	}
    kfree(input);
}


/*
	========================================================================

	Routine Description:

	Arguments:

	Return Value:

	Note:

	========================================================================
*/
void RTMPDerivePMKID(
	u8 *			pAaddr,
	u8 *			pSpaddr,
	u8 *			pKey,
	u8 *			pAkm_oui,
	u8 *			pPMKID)
{
	u8 digest[80], text_buf[20];
	u8	text_len;

	/* Concatenate the text for PMKID calculation*/
	memmove(&text_buf[0], "PMK Name", 8);
	memmove(&text_buf[8], pAaddr, ETH_ALEN);
	memmove(&text_buf[14], pSpaddr, ETH_ALEN);
	text_len = 20;

	{
		RT_HMAC_SHA1(pKey, PMK_LEN, text_buf, text_len, digest, SHA1_DIGEST_SIZE);
	}

	/* Truncate the first 128-bit of output result */
	memmove(pPMKID, digest, LEN_PMKID);

}



/*
	========================================================================

	Routine Description:
		It utilizes PRF-384 or PRF-512 to derive session-specific keys from a PMK.
		It shall be called by 4-way handshake processing.

	Arguments:
		pAd 	-	pointer to our pAdapter context
		PMK		-	pointer to PMK
		ANonce	-	pointer to ANonce
		AA		-	pointer to Authenticator Address
		SNonce	-	pointer to SNonce
		SA		-	pointer to Supplicant Address
		len		-	indicate the length of PTK (octet)

	Return Value:
		Output		pointer to the PTK

	Note:
		Refer to IEEE 802.11i-2004 8.5.1.2

	========================================================================
*/
void WpaDerivePTK(
	struct rtmp_adapter *pAd,
	u8 *PMK,
	u8 *ANonce,
	u8 *AA,
	u8 *SNonce,
	u8 *SA,
	u8 *output,
	UINT	len)
{
	u8 concatenation[76];
	UINT	CurrPos = 0;
	u8 temp[32];
	u8 Prefix[] = {'P', 'a', 'i', 'r', 'w', 'i', 's', 'e', ' ', 'k', 'e', 'y', ' ',
						'e', 'x', 'p', 'a', 'n', 's', 'i', 'o', 'n'};

	/* initiate the concatenation input*/
	memset(temp, 0, sizeof(temp));
	memset(concatenation, 0, 76);

	/* Get smaller address*/
	if (RTMPCompareMemory(SA, AA, 6) == 1)
		memmove(concatenation, AA, 6);
	else
		memmove(concatenation, SA, 6);
	CurrPos += 6;

	/* Get larger address*/
	if (RTMPCompareMemory(SA, AA, 6) == 1)
		memmove(&concatenation[CurrPos], SA, 6);
	else
		memmove(&concatenation[CurrPos], AA, 6);

	/* store the larger mac address for backward compatible of */
	/* ralink proprietary STA-key issue		*/
	memmove(temp, &concatenation[CurrPos], ETH_ALEN);
	CurrPos += 6;

	/* Get smaller Nonce*/
	if (RTMPCompareMemory(ANonce, SNonce, 32) == 0)
		memmove(&concatenation[CurrPos], temp, 32);	/* patch for ralink proprietary STA-key issue*/
	else if (RTMPCompareMemory(ANonce, SNonce, 32) == 1)
		memmove(&concatenation[CurrPos], SNonce, 32);
	else
		memmove(&concatenation[CurrPos], ANonce, 32);
	CurrPos += 32;

	/* Get larger Nonce*/
	if (RTMPCompareMemory(ANonce, SNonce, 32) == 0)
		memmove(&concatenation[CurrPos], temp, 32);	/* patch for ralink proprietary STA-key issue*/
	else if (RTMPCompareMemory(ANonce, SNonce, 32) == 1)
		memmove(&concatenation[CurrPos], ANonce, 32);
	else
		memmove(&concatenation[CurrPos], SNonce, 32);
	CurrPos += 32;

	/* Use PRF to generate PTK*/
	PRF(PMK, LEN_PMK, Prefix, 22, concatenation, 76, output, len);

}

void WpaDeriveGTK(
    u8   *GMK,
    u8   *GNonce,
    u8   *AA,
    u8   *output,
    UINT    len)
{
    u8   concatenation[76];
    UINT    CurrPos=0;
    u8   Prefix[19];
    u8   temp[80];

    memmove(&concatenation[CurrPos], AA, 6);
    CurrPos += 6;

    memmove(&concatenation[CurrPos], GNonce , 32);
    CurrPos += 32;

    Prefix[0] = 'G';
    Prefix[1] = 'r';
    Prefix[2] = 'o';
    Prefix[3] = 'u';
    Prefix[4] = 'p';
    Prefix[5] = ' ';
    Prefix[6] = 'k';
    Prefix[7] = 'e';
    Prefix[8] = 'y';
    Prefix[9] = ' ';
    Prefix[10] = 'e';
    Prefix[11] = 'x';
    Prefix[12] = 'p';
    Prefix[13] = 'a';
    Prefix[14] = 'n';
    Prefix[15] = 's';
    Prefix[16] = 'i';
    Prefix[17] = 'o';
    Prefix[18] = 'n';

    PRF(GMK, PMK_LEN, Prefix,  19, concatenation, 38 , temp, len);
    memmove(output, temp, len);
}

/*
	========================================================================

	Routine Description:
		Generate random number by software.

	Arguments:
		pAd		-	pointer to our pAdapter context
		macAddr	-	pointer to local MAC address

	Return Value:

	Note:
		802.1ii-2004  Annex H.5

	========================================================================
*/
void GenRandom(
	struct rtmp_adapter *pAd,
	u8 		*macAddr,
	u8 		*random)
{
	INT		i, curr;
	u8 local[80], KeyCounter[32];
	u8 result[80];
	unsigned long	CurrentTime;
	u8 prefix[] = {'I', 'n', 'i', 't', ' ', 'C', 'o', 'u', 'n', 't', 'e', 'r'};

	/* Zero the related information*/
	memset(result, 0, 80);
	memset(local, 0, 80);
	memset(KeyCounter, 0, 32);

	for	(i = 0;	i <	32;	i++)
	{
		/* copy the local MAC address*/
		memcpy(local, macAddr, ETH_ALEN);
		curr =	ETH_ALEN;

		/* concatenate the current time*/
		NdisGetSystemUpTime(&CurrentTime);
		memmove(&local[curr],  &CurrentTime,	sizeof(CurrentTime));
		curr +=	sizeof(CurrentTime);

		/* concatenate the last result*/
		memmove(&local[curr],  result, 32);
		curr +=	32;

		/* concatenate a variable */
		memmove(&local[curr],  &i,  2);
		curr +=	2;

		/* calculate the result*/
		PRF(KeyCounter, 32, prefix,12, local, curr, result, 32);
	}

	memmove(random, result,	32);
}

/*
	========================================================================

	Routine Description:
		Build cipher suite in RSN-IE.
		It only shall be called by RTMPMakeRSNIE.

	Arguments:
		pAd			-	pointer to our pAdapter context
    	ElementID	-	indicate the WPA1 or WPA2
    	WepStatus	-	indicate the encryption type
		bMixCipher	-	a boolean to indicate the pairwise cipher and group
						cipher are the same or not

	Return Value:

	Note:

	========================================================================
*/
static void RTMPMakeRsnIeCipher(
	struct rtmp_adapter *  pAd,
	u8 		ElementID,
	UINT			WepStatus,
	u8 		apidx,
	bool 		bMixCipher,
	u8 		FlexibleCipher,
	u8 *		pRsnIe,
	u8 		*rsn_len)
{
	u8 PairwiseCnt;

	*rsn_len = 0;

	/* decide WPA2 or WPA1	*/
	if (ElementID == Wpa2Ie)
	{
		RSNIE2	*pRsnie_cipher = (RSNIE2*)pRsnIe;

		/* Assign the verson as 1*/
		pRsnie_cipher->version = 1;

        switch (WepStatus)
        {
        	/* TKIP mode*/
            case Ndis802_11Encryption2Enabled:
                memmove(pRsnie_cipher->mcast, OUI_WPA2_TKIP, 4);
                pRsnie_cipher->ucount = 1;
                memmove(pRsnie_cipher->ucast[0].oui, OUI_WPA2_TKIP, 4);
                *rsn_len = sizeof(RSNIE2);
                break;

			/* AES mode*/
            case Ndis802_11Encryption3Enabled:
				if (bMixCipher)
					memmove(pRsnie_cipher->mcast, OUI_WPA2_TKIP, 4);
				else
					memmove(pRsnie_cipher->mcast, OUI_WPA2_CCMP, 4);
                pRsnie_cipher->ucount = 1;
                memmove(pRsnie_cipher->ucast[0].oui, OUI_WPA2_CCMP, 4);
                *rsn_len = sizeof(RSNIE2);
                break;

			/* TKIP-AES mix mode*/
            case Ndis802_11Encryption4Enabled:
                memmove(pRsnie_cipher->mcast, OUI_WPA2_TKIP, 4);

				PairwiseCnt = 1;
				/* Insert WPA2 TKIP as the first pairwise cipher */
				if (MIX_CIPHER_WPA2_TKIP_ON(FlexibleCipher))
				{
                	memmove(pRsnie_cipher->ucast[0].oui, OUI_WPA2_TKIP, 4);
					/* Insert WPA2 AES as the secondary pairwise cipher*/
					if (MIX_CIPHER_WPA2_AES_ON(FlexibleCipher))
					{
						memmove(pRsnIe + sizeof(RSNIE2), OUI_WPA2_CCMP, 4);
						PairwiseCnt = 2;
					}
				}
				else
				{
					/* Insert WPA2 AES as the first pairwise cipher */
					memmove(pRsnie_cipher->ucast[0].oui, OUI_WPA2_CCMP, 4);
				}

                pRsnie_cipher->ucount = PairwiseCnt;
                *rsn_len = sizeof(RSNIE2) + (4 * (PairwiseCnt - 1));
                break;
        }

#ifdef CONFIG_STA_SUPPORT
		if ((pAd->OpMode == OPMODE_STA) &&
			(pAd->StaCfg.GroupCipher != Ndis802_11Encryption2Enabled) &&
			(pAd->StaCfg.GroupCipher != Ndis802_11Encryption3Enabled)
			)
		{
			UINT	GroupCipher = pAd->StaCfg.GroupCipher;
			switch(GroupCipher)
			{
				case Ndis802_11GroupWEP40Enabled:
					memmove(pRsnie_cipher->mcast, OUI_WPA2_WEP40, 4);
					break;
				case Ndis802_11GroupWEP104Enabled:
					memmove(pRsnie_cipher->mcast, OUI_WPA2_WEP104, 4);
					break;
			}
		}
#endif /* CONFIG_STA_SUPPORT */

		/* swap for big-endian platform*/
		pRsnie_cipher->version = cpu2le16(pRsnie_cipher->version);
	    pRsnie_cipher->ucount = cpu2le16(pRsnie_cipher->ucount);
	}
	else
	{
		RSNIE	*pRsnie_cipher = (RSNIE*)pRsnIe;

		/* Assign OUI and version*/
		memmove(pRsnie_cipher->oui, OUI_WPA_VERSION, 4);
        pRsnie_cipher->version = 1;

		switch (WepStatus)
		{
			/* TKIP mode*/
            case Ndis802_11Encryption2Enabled:
                memmove(pRsnie_cipher->mcast, OUI_WPA_TKIP, 4);
                pRsnie_cipher->ucount = 1;
                memmove(pRsnie_cipher->ucast[0].oui, OUI_WPA_TKIP, 4);
                *rsn_len = sizeof(RSNIE);
                break;

			/* AES mode*/
            case Ndis802_11Encryption3Enabled:
				if (bMixCipher)
					memmove(pRsnie_cipher->mcast, OUI_WPA_TKIP, 4);
				else
					memmove(pRsnie_cipher->mcast, OUI_WPA_CCMP, 4);
                pRsnie_cipher->ucount = 1;
                memmove(pRsnie_cipher->ucast[0].oui, OUI_WPA_CCMP, 4);
                *rsn_len = sizeof(RSNIE);
                break;

			/* TKIP-AES mix mode*/
            case Ndis802_11Encryption4Enabled:
                memmove(pRsnie_cipher->mcast, OUI_WPA_TKIP, 4);

				PairwiseCnt = 1;
				/* Insert WPA TKIP as the first pairwise cipher */
				if (MIX_CIPHER_WPA_TKIP_ON(FlexibleCipher))
				{
                	memmove(pRsnie_cipher->ucast[0].oui, OUI_WPA_TKIP, 4);
					/* Insert WPA AES as the secondary pairwise cipher*/
					if (MIX_CIPHER_WPA_AES_ON(FlexibleCipher))
					{
						memmove(pRsnIe + sizeof(RSNIE), OUI_WPA_CCMP, 4);
						PairwiseCnt = 2;
					}
				}
				else
				{
					/* Insert WPA AES as the first pairwise cipher */
					memmove(pRsnie_cipher->ucast[0].oui, OUI_WPA_CCMP, 4);
				}

                pRsnie_cipher->ucount = PairwiseCnt;
                *rsn_len = sizeof(RSNIE) + (4 * (PairwiseCnt - 1));
                break;
        }

#ifdef CONFIG_STA_SUPPORT
		if ((pAd->OpMode == OPMODE_STA) &&
			(pAd->StaCfg.GroupCipher != Ndis802_11Encryption2Enabled) &&
			(pAd->StaCfg.GroupCipher != Ndis802_11Encryption3Enabled)
			)
		{
			UINT	GroupCipher = pAd->StaCfg.GroupCipher;
			switch(GroupCipher)
			{
				case Ndis802_11GroupWEP40Enabled:
					memmove(pRsnie_cipher->mcast, OUI_WPA_WEP40, 4);
					break;
				case Ndis802_11GroupWEP104Enabled:
					memmove(pRsnie_cipher->mcast, OUI_WPA_WEP104, 4);
					break;
			}
		}
#endif /* CONFIG_STA_SUPPORT */

		/* swap for big-endian platform*/
		pRsnie_cipher->version = cpu2le16(pRsnie_cipher->version);
	    pRsnie_cipher->ucount = cpu2le16(pRsnie_cipher->ucount);
	}
}

/*
	========================================================================

	Routine Description:
		Build AKM suite in RSN-IE.
		It only shall be called by RTMPMakeRSNIE.

	Arguments:
		pAd			-	pointer to our pAdapter context
    	ElementID	-	indicate the WPA1 or WPA2
    	AuthMode	-	indicate the authentication mode
		apidx		-	indicate the interface index

	Return Value:

	Note:

	========================================================================
*/
static void RTMPMakeRsnIeAKM(
	struct rtmp_adapter *  pAd,
	u8 		ElementID,
	UINT			AuthMode,
	u8 		apidx,
	u8 *		pRsnIe,
	u8 		*rsn_len)
{
	RSNIE_AUTH		*pRsnie_auth;
	u8 		AkmCnt = 1;		/* default as 1*/

	pRsnie_auth = (RSNIE_AUTH*)(pRsnIe + (*rsn_len));

	/* decide WPA2 or WPA1	 */
	if (ElementID == Wpa2Ie)
	{

		switch (AuthMode)
        {
            case Ndis802_11AuthModeWPA2:
            case Ndis802_11AuthModeWPA1WPA2:
                	memmove(pRsnie_auth->auth[0].oui, OUI_WPA2_8021X_AKM, 4);

                break;

            case Ndis802_11AuthModeWPA2PSK:
            case Ndis802_11AuthModeWPA1PSKWPA2PSK:
                	memmove(pRsnie_auth->auth[0].oui, OUI_WPA2_PSK_AKM, 4);

                break;
			default:
				AkmCnt = 0;
				break;

        }
	}
	else
	{
		switch (AuthMode)
        {
            case Ndis802_11AuthModeWPA:
            case Ndis802_11AuthModeWPA1WPA2:
                memmove(pRsnie_auth->auth[0].oui, OUI_WPA_8021X_AKM, 4);
                break;

            case Ndis802_11AuthModeWPAPSK:
            case Ndis802_11AuthModeWPA1PSKWPA2PSK:
                memmove(pRsnie_auth->auth[0].oui, OUI_WPA_PSK_AKM, 4);
                break;

			case Ndis802_11AuthModeWPANone:
                memmove(pRsnie_auth->auth[0].oui, OUI_WPA_NONE_AKM, 4);
                break;
			default:
				AkmCnt = 0;
				break;
        }
	}

	pRsnie_auth->acount = AkmCnt;
	pRsnie_auth->acount = cpu2le16(pRsnie_auth->acount);

	/* update current RSNIE length*/
	(*rsn_len) += (sizeof(RSNIE_AUTH) + (4 * (AkmCnt - 1)));

}

/*
	========================================================================

	Routine Description:
		Build capability in RSN-IE.
		It only shall be called by RTMPMakeRSNIE.

	Arguments:
		pAd			-	pointer to our pAdapter context
    	ElementID	-	indicate the WPA1 or WPA2
		apidx		-	indicate the interface index

	Return Value:

	Note:

	========================================================================
*/
static void RTMPMakeRsnIeCap(
	struct rtmp_adapter *  pAd,
	u8 		ElementID,
	u8 		apidx,
	u8 *		pRsnIe,
	u8 		*rsn_len)
{
	RSN_CAPABILITIES    *pRSN_Cap;

	/* it could be ignored in WPA1 mode*/
	if (ElementID == WpaIe)
		return;

	pRSN_Cap = (RSN_CAPABILITIES*)(pRsnIe + (*rsn_len));


#ifdef CONFIG_STA_SUPPORT

#endif /* CONFIG_STA_SUPPORT */

	pRSN_Cap->word = cpu2le16(pRSN_Cap->word);

	(*rsn_len) += sizeof(RSN_CAPABILITIES);	/* update current RSNIE length*/

}

/*
	========================================================================

	Routine Description:
		Build PMKID in RSN-IE.
		It only shall be called by RTMPMakeRSNIE.

	Arguments:
		pAd			-	pointer to our pAdapter context
    	ElementID	-	indicate the WPA1 or WPA2
		apidx		-	indicate the interface index

	Return Value:

	Note:

	========================================================================
*/

/*
	========================================================================

	Routine Description:
		Build RSN IE context. It is not included element-ID and length.

	Arguments:
		pAd			-	pointer to our pAdapter context
    	AuthMode	-	indicate the authentication mode
    	WepStatus	-	indicate the encryption type
		apidx		-	indicate the interface index

	Return Value:

	Note:

	========================================================================
*/
void RTMPMakeRSNIE(
    struct rtmp_adapter *  pAd,
    UINT            AuthMode,
    UINT            WepStatus,
	u8 		apidx)
{
	u8 *	pRsnIe = NULL;			/* primary RSNIE*/
	u8 		*rsnielen_cur_p = 0;	/* the length of the primary RSNIE 		*/
	u8 	*rsnielen_ex_cur_p = 0;	/* the length of the secondary RSNIE	  	*/
	u8 	PrimaryRsnie;
	bool 	bMixCipher = false;	/* indicate the pairwise and group cipher are different*/
	u8 	p_offset;
	WPA_MIX_PAIR_CIPHER FlexibleCipher = WPA_TKIPAES_WPA2_TKIPAES;	/* it provide the more flexible cipher combination in WPA-WPA2 and TKIPAES mode*/

	rsnielen_cur_p = NULL;
	rsnielen_ex_cur_p = NULL;

	do
	{

#ifdef APCLI_SUPPORT
		if (apidx >= MIN_NET_DEVICE_FOR_APCLI)
		{
			UINT	apcliIfidx = 0;

			/* Only support WPAPSK or WPA2PSK for AP-Client mode */
#ifdef APCLI_WPA_SUPPLICANT_SUPPORT
			if (pAd->ApCfg.ApCliTab[apcliIfidx].WpaSupplicantUP != WPA_SUPPLICANT_DISABLE)
			{
				if (AuthMode < Ndis802_11AuthModeWPA)
					return;
			}
			else
#endif /* APCLI_WPA_SUPPLICANT_SUPPORT */
			{

				if ((AuthMode != Ndis802_11AuthModeWPAPSK) &&
					(AuthMode != Ndis802_11AuthModeWPA2PSK))
			    	return;

			}

			DBGPRINT(RT_DEBUG_TRACE,("==> RTMPMakeRSNIE(ApCli)\n"));

			apcliIfidx = apidx - MIN_NET_DEVICE_FOR_APCLI;

			/* Initiate some related information */
				if (apcliIfidx < MAX_APCLI_NUM)
				{
			pAd->ApCfg.ApCliTab[apcliIfidx].RSNIE_Len = 0;
			memset(pAd->ApCfg.ApCliTab[apcliIfidx].RSN_IE, 0, MAX_LEN_OF_RSNIE);
			rsnielen_cur_p = &pAd->ApCfg.ApCliTab[apcliIfidx].RSNIE_Len;
			pRsnIe = pAd->ApCfg.ApCliTab[apcliIfidx].RSN_IE;

			bMixCipher = pAd->ApCfg.ApCliTab[apcliIfidx].bMixCipher;
			break;
				}
				else
				{
					DBGPRINT(RT_DEBUG_ERROR, ("RTMPMakeRSNIE: invalid apcliIfidx(%d)\n", apcliIfidx));
					return;
				}
	}
#endif /* APCLI_SUPPORT */


#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
#ifdef WPA_SUPPLICANT_SUPPORT
			if (pAd->StaCfg.WpaSupplicantUP != WPA_SUPPLICANT_DISABLE)
			{
				if (AuthMode < Ndis802_11AuthModeWPA)
					return;
			}
			else
#endif /* WPA_SUPPLICANT_SUPPORT */
			{
				/* Support WPAPSK or WPA2PSK in STA-Infra mode */
				/* Support WPANone in STA-Adhoc mode */
				if ((AuthMode != Ndis802_11AuthModeWPAPSK) &&
					(AuthMode != Ndis802_11AuthModeWPA2PSK) &&
					(AuthMode != Ndis802_11AuthModeWPANone)
					)
					return;
			}

			DBGPRINT(RT_DEBUG_TRACE,("==> RTMPMakeRSNIE(STA)\n"));

			/* Zero RSNIE context */
			pAd->StaCfg.RSNIE_Len = 0;
			memset(pAd->StaCfg.RSN_IE, 0, MAX_LEN_OF_RSNIE);

			/* Pointer to RSNIE */
			rsnielen_cur_p = &pAd->StaCfg.RSNIE_Len;
			pRsnIe = pAd->StaCfg.RSN_IE;

			bMixCipher = pAd->StaCfg.bMixCipher;
			break;
		}
#endif /* CONFIG_STA_SUPPORT */
	} while(false);

	/* indicate primary RSNIE as WPA or WPA2*/
	if ((AuthMode == Ndis802_11AuthModeWPA) ||
		(AuthMode == Ndis802_11AuthModeWPAPSK) ||
		(AuthMode == Ndis802_11AuthModeWPANone) ||
		(AuthMode == Ndis802_11AuthModeWPA1WPA2) ||
		(AuthMode == Ndis802_11AuthModeWPA1PSKWPA2PSK))
		PrimaryRsnie = WpaIe;
	else
		PrimaryRsnie = Wpa2Ie;

	{
		/* Build the primary RSNIE*/
		/* 1. insert cipher suite*/
		RTMPMakeRsnIeCipher(pAd, PrimaryRsnie, WepStatus, apidx, bMixCipher, FlexibleCipher, pRsnIe, &p_offset);

		/* 2. insert AKM*/
		RTMPMakeRsnIeAKM(pAd, PrimaryRsnie, AuthMode, apidx, pRsnIe, &p_offset);

		/* 3. insert capability*/
		RTMPMakeRsnIeCap(pAd, PrimaryRsnie, apidx, pRsnIe, &p_offset);

	}

	/* 4. update the RSNIE length*/
	if (rsnielen_cur_p == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: rsnielen_cur_p == NULL!\n", __FUNCTION__));
		return;
	}

	*rsnielen_cur_p = p_offset;
}

/*
    ==========================================================================
    Description:
		Check whether the received frame is EAP frame.

	Arguments:
		pAd				-	pointer to our pAdapter context
		pEntry			-	pointer to active entry
		pData			-	the received frame
		DataByteCount 	-	the received frame's length
		FromWhichBSSID	-	indicate the interface index

    Return:
         true 			-	This frame is EAP frame
         false 			-	otherwise
    ==========================================================================
*/
bool RTMPCheckWPAframe(
    struct rtmp_adapter *   pAd,
    PMAC_TABLE_ENTRY	pEntry,
    u8 *          pData,
    unsigned long            DataByteCount,
	u8 		FromWhichBSSID)
{
	unsigned long	Body_len;
	bool Cancelled;

	do
	{
	} while (false);

    if(DataByteCount < (LENGTH_802_1_H + LENGTH_EAPOL_H))
        return false;


	/* Skip LLC header	*/
    if (memcmp(SNAP_802_1H, pData, 6) == 0 ||
        /* Cisco 1200 AP may send packet with SNAP_BRIDGE_TUNNEL*/
        memcmp(SNAP_BRIDGE_TUNNEL, pData, 6) == 0)
    {
        pData += 6;
    }
	/* Skip 2-bytes EAPoL type */
    if (memcmp(EAPOL, pData, 2) == 0)
/*	if (*(uint16_t *)EAPOL == *(uint16_t *)pData)*/
    {
        pData += 2;
    }
    else
        return false;

    switch (*(pData+1))
    {
        case EAPPacket:
			Body_len = (*(pData+2)<<8) | (*(pData+3));
            DBGPRINT(RT_DEBUG_TRACE, ("Receive EAP-Packet frame, TYPE = 0, Length = %ld\n", Body_len));
            break;
        case EAPOLStart:
            DBGPRINT(RT_DEBUG_TRACE, ("Receive EAPOL-Start frame, TYPE = 1 \n"));
			if (pEntry->EnqueueEapolStartTimerRunning != EAPOL_START_DISABLE)
            {
            	DBGPRINT(RT_DEBUG_TRACE, ("Cancel the EnqueueEapolStartTimerRunning \n"));
                RTMPCancelTimer(&pEntry->EnqueueStartForPSKTimer, &Cancelled);
                pEntry->EnqueueEapolStartTimerRunning = EAPOL_START_DISABLE;
            }
            break;
        case EAPOLLogoff:
            DBGPRINT(RT_DEBUG_TRACE, ("Receive EAPOLLogoff frame, TYPE = 2 \n"));
            break;
        case EAPOLKey:
			Body_len = (*(pData+2)<<8) | (*(pData+3));
            DBGPRINT(RT_DEBUG_TRACE, ("Receive EAPOL-Key frame, TYPE = 3, Length = %ld\n", Body_len));
            break;
        case EAPOLASFAlert:
            DBGPRINT(RT_DEBUG_TRACE, ("Receive EAPOLASFAlert frame, TYPE = 4 \n"));
            break;
        default:
            return false;

    }
    return true;
}

/*
    ==========================================================================
    Description:
		Report the EAP message type

	Arguments:
		msg		-	EAPOL_PAIR_MSG_1
					EAPOL_PAIR_MSG_2
					EAPOL_PAIR_MSG_3
					EAPOL_PAIR_MSG_4
					EAPOL_GROUP_MSG_1
					EAPOL_GROUP_MSG_2

    Return:
         message type string

    ==========================================================================
*/
char *GetEapolMsgType(CHAR msg)
{
    if(msg == EAPOL_PAIR_MSG_1)
        return "Pairwise Message 1";
    else if(msg == EAPOL_PAIR_MSG_2)
        return "Pairwise Message 2";
	else if(msg == EAPOL_PAIR_MSG_3)
        return "Pairwise Message 3";
	else if(msg == EAPOL_PAIR_MSG_4)
        return "Pairwise Message 4";
	else if(msg == EAPOL_GROUP_MSG_1)
        return "Group Message 1";
	else if(msg == EAPOL_GROUP_MSG_2)
        return "Group Message 2";
    else
    	return "Invalid Message";
}


/*
    ========================================================================

    Routine Description:
    Check Sanity RSN IE of EAPoL message

    Arguments:

    Return Value:


    ========================================================================
*/
bool RTMPCheckRSNIE(
	struct rtmp_adapter *  pAd,
	u8 *         pData,
	u8           DataLen,
	MAC_TABLE_ENTRY *pEntry,
	u8 		*Offset)
{
	u8 *             pVIE;
	u8               len;
	PEID_STRUCT         pEid;
	bool 			result = false;

	pVIE = pData;
	len	 = DataLen;
	*Offset = 0;

	while (len > sizeof(RSNIE2))
	{
		pEid = (PEID_STRUCT) pVIE;
		/* WPA RSN IE*/
		if ((pEid->Eid == IE_WPA) && (memcmp(pEid->Octet, WPA_OUI, 4) == 0))
		{
			if ((pEntry->AuthMode == Ndis802_11AuthModeWPA || pEntry->AuthMode == Ndis802_11AuthModeWPAPSK) &&
				(memcmp(pVIE, pEntry->RSN_IE, pEntry->RSNIE_Len) == 0) &&
				(pEntry->RSNIE_Len == (pEid->Len + 2)))
			{
					result = true;
			}

			*Offset += (pEid->Len + 2);
		}
		/* WPA2 RSN IE, doesn't need to check RSNIE Capabilities field        */
		else if ((pEid->Eid == IE_RSN) && (memcmp(pEid->Octet + 2, RSN_OUI, 3) == 0))
		{
			if ((pEntry->AuthMode == Ndis802_11AuthModeWPA2 || pEntry->AuthMode == Ndis802_11AuthModeWPA2PSK) &&
				(pEid->Eid == pEntry->RSN_IE[0]) &&
				((pEid->Len + 2) >= pEntry->RSNIE_Len) &&
				(memcmp(pEid->Octet, &pEntry->RSN_IE[2], pEntry->RSNIE_Len - 4) == 0))
			{

					result = true;
			}

			*Offset += (pEid->Len + 2);
		}
		else
		{
			break;
		}

		pVIE += (pEid->Len + 2);
		len  -= (pEid->Len + 2);
	}


	return result;

}


/*
    ========================================================================

    Routine Description:
    Parse KEYDATA field.  KEYDATA[] May contain 2 RSN IE and optionally GTK.
    GTK  is encaptulated in KDE format at  p.83 802.11i D10

    Arguments:

    Return Value:

    Note:
        802.11i D10

    ========================================================================
*/
bool RTMPParseEapolKeyData(
	struct rtmp_adapter *  pAd,
	u8 *         pKeyData,
	u8           KeyDataLen,
	u8 		GroupKeyIndex,
	u8 		MsgType,
	bool 		bWPA2,
	MAC_TABLE_ENTRY *pEntry)
{
    u8 *             pMyKeyData = pKeyData;
    u8               KeyDataLength = KeyDataLen;
	u8 			GTK[MAX_LEN_GTK];
    u8               GTKLEN = 0;
	u8 			DefaultIdx = 0;
	u8 			skip_offset = 0;


	memset(GTK, 0, MAX_LEN_GTK);

	/* Verify The RSN IE contained in pairewise_msg_2 && pairewise_msg_3 and skip it*/
	if (MsgType == EAPOL_PAIR_MSG_2 || MsgType == EAPOL_PAIR_MSG_3)
    {
		{
			if (bWPA2 && MsgType == EAPOL_PAIR_MSG_3)
			{
				/*WpaShowAllsuite(pMyKeyData, skip_offset);*/

				/* skip RSN IE*/
				pMyKeyData += skip_offset;
				KeyDataLength -= skip_offset;
				DBGPRINT(RT_DEBUG_TRACE, ("RTMPParseEapolKeyData ==> WPA2/WPA2PSK RSN IE matched in Msg 3, Length(%d) \n", skip_offset));
			}
			else
				return true;
		}
	}

	DBGPRINT(RT_DEBUG_TRACE,("RTMPParseEapolKeyData ==> KeyDataLength %d without RSN_IE \n", KeyDataLength));

	/* Parse KDE format in pairwise_msg_3_WPA2 && group_msg_1_WPA2*/
	if (bWPA2 && (MsgType == EAPOL_PAIR_MSG_3 || MsgType == EAPOL_GROUP_MSG_1))
	{
		PEID_STRUCT     pEid;

		pEid = (PEID_STRUCT) pMyKeyData;
		skip_offset = 0;
		while ((skip_offset + 2 + pEid->Len) <= KeyDataLength)
		{
			switch(pEid->Eid)
			{
				case WPA_KDE_TYPE:
					{
						PKDE_HDR	pKDE;

						pKDE = (PKDE_HDR)pEid;
						if (memcmp(pKDE->OUI, OUI_WPA2, 3) == 0)
    					{
							if (pKDE->DataType == KDE_GTK)
							{
								PGTK_KDE pKdeGtk;

								pKdeGtk = (PGTK_KDE) &pKDE->octet[0];
								DefaultIdx = pKdeGtk->Kid;

								/* Get GTK length - refer to IEEE 802.11i-2004 p.82 */
								GTKLEN = pKDE->Len -6;
								if (GTKLEN < LEN_WEP64)
								{
									DBGPRINT(RT_DEBUG_ERROR, ("ERROR: GTK Key length is too short (%d) \n", GTKLEN));
        							return false;
								}
								memmove(GTK, pKdeGtk->GTK, GTKLEN);
								DBGPRINT(RT_DEBUG_TRACE, ("GTK in KDE format ,DefaultKeyID=%d, KeyLen=%d \n", DefaultIdx, GTKLEN));
    						}
						}
					}
					break;
			}
			skip_offset = skip_offset + 2 + pEid->Len;
	        pEid = (PEID_STRUCT)((u8 *)pEid + 2 + pEid->Len);
		}

		/* skip KDE Info*/
		pMyKeyData += skip_offset;
		KeyDataLength -= skip_offset;
	}
	else if (!bWPA2 && MsgType == EAPOL_GROUP_MSG_1)
	{
		DefaultIdx = GroupKeyIndex;
		GTKLEN = KeyDataLength;
		memmove(GTK, pMyKeyData, KeyDataLength);
		DBGPRINT(RT_DEBUG_TRACE, ("GTK without KDE, DefaultKeyID=%d, KeyLen=%d \n", DefaultIdx, GTKLEN));
	}

	/* Sanity check - shared key index must be 0 ~ 3*/
	if (DefaultIdx > 3)
    {
     	DBGPRINT(RT_DEBUG_ERROR, ("ERROR: GTK Key index(%d) is invalid in %s %s \n", DefaultIdx, ((bWPA2) ? "WPA2" : "WPA"), GetEapolMsgType(MsgType)));
        return false;
    }


#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
       {
        {
    		/* set key material, TxMic and RxMic		*/
    		memmove(pAd->StaCfg.GTK, GTK, GTKLEN);
    		pAd->StaCfg.DefaultKeyId = DefaultIdx;

    		WPAInstallSharedKey(pAd,
    							pAd->StaCfg.GroupCipher,
    							BSS0,
    							pAd->StaCfg.DefaultKeyId,
    							MCAST_WCID,
    							false,
    							pAd->StaCfg.GTK,
    							GTKLEN);
			}
        }
	}
#endif /* CONFIG_STA_SUPPORT */

	return true;

}

/*
	========================================================================

	Routine Description:
		Construct KDE common format
		Its format is below,

		+--------------------+
		| Type (0xdd)		 |  1 octet
		+--------------------+
		| Length			 |	1 octet
		+--------------------+
		| OUI				 |  3 octets
		+--------------------+
		| Data Type			 |	1 octet
		+--------------------+

	Arguments:

	Return Value:

	Note:
		It's defined in IEEE 802.11-2007 Figure 8-25.

	========================================================================
*/
void WPA_ConstructKdeHdr(
	u8	data_type,
	u8 	data_len,
	u8 *	pBuf)
{
	PKDE_HDR	pHdr;

	pHdr = (PKDE_HDR)pBuf;

	memset(pHdr, 0, sizeof(KDE_HDR));

    pHdr->Type = WPA_KDE_TYPE;

	/* The Length field specifies the number of octets in the OUI, Data
	   Type, and Data fields. */
	pHdr->Len = 4 + data_len;

	memmove(pHdr->OUI, OUI_WPA2, 3);
	pHdr->DataType = data_type;

}


/*
	========================================================================

	Routine Description:
		Construct EAPoL message for WPA handshaking
		Its format is below,

		+--------------------+
		| Protocol Version	 |  1 octet
		+--------------------+
		| Protocol Type		 |	1 octet
		+--------------------+
		| Body Length		 |  2 octets
		+--------------------+
		| Descriptor Type	 |	1 octet
		+--------------------+
		| Key Information    |	2 octets
		+--------------------+
		| Key Length	     |  1 octet
		+--------------------+
		| Key Repaly Counter |	8 octets
		+--------------------+
		| Key Nonce		     |  32 octets
		+--------------------+
		| Key IV			 |  16 octets
		+--------------------+
		| Key RSC			 |  8 octets
		+--------------------+
		| Key ID or Reserved |	8 octets
		+--------------------+
		| Key MIC			 |	16 octets
		+--------------------+
		| Key Data Length	 |	2 octets
		+--------------------+
		| Key Data			 |	n octets
		+--------------------+


	Arguments:
		pAd			Pointer	to our adapter

	Return Value:
		None

	Note:

	========================================================================
*/
void ConstructEapolMsg(
	PMAC_TABLE_ENTRY	pEntry,
    u8 			GroupKeyWepStatus,
    u8 			MsgType,
    u8 			DefaultKeyIdx,
	u8 			*KeyNonce,
	u8 			*TxRSC,
	u8 			*GTK,
	u8 			*RSNIE,
	u8 			RSNIE_Len,
    PEAPOL_PACKET       pMsg)
{
	bool bWPA2 = false;
	u8 KeyDescVer;

	/* Choose WPA2 or not*/
	if ((pEntry->AuthMode == Ndis802_11AuthModeWPA2) ||
		(pEntry->AuthMode == Ndis802_11AuthModeWPA2PSK))
		bWPA2 = true;

    /* Init Packet and Fill header    */
    pMsg->ProVer = EAPOL_VER;
    pMsg->ProType = EAPOLKey;

	/* Default 95 bytes, the EAPoL-Key descriptor exclude Key-data field*/
	SET_UINT16_TO_ARRARY(pMsg->Body_Len, MIN_LEN_OF_EAPOL_KEY_MSG);

	/* Fill in EAPoL descriptor*/
	if (bWPA2)
		pMsg->KeyDesc.Type = WPA2_KEY_DESC;
	else
		pMsg->KeyDesc.Type = WPA1_KEY_DESC;

	/* Key Descriptor Version (bits 0-2) specifies the key descriptor version type*/
	{
		/* Fill in Key information, refer to IEEE Std 802.11i-2004 page 78 */
		/* When either the pairwise or the group cipher is AES, the KEY_DESC_AES shall be used.*/
		KeyDescVer = (((pEntry->WepStatus == Ndis802_11Encryption3Enabled) ||
		        		(GroupKeyWepStatus == Ndis802_11Encryption3Enabled)) ? (KEY_DESC_AES) : (KEY_DESC_TKIP));
	}

	pMsg->KeyDesc.KeyInfo.KeyDescVer = KeyDescVer;

	/* Specify Key Type as Group(0) or Pairwise(1)*/
	if (MsgType >= EAPOL_GROUP_MSG_1)
		pMsg->KeyDesc.KeyInfo.KeyType = GROUPKEY;
	else
		pMsg->KeyDesc.KeyInfo.KeyType = PAIRWISEKEY;

	/* Specify Key Index, only group_msg1_WPA1*/
	if (!bWPA2 && (MsgType >= EAPOL_GROUP_MSG_1))
		pMsg->KeyDesc.KeyInfo.KeyIndex = DefaultKeyIdx;

	if (MsgType == EAPOL_PAIR_MSG_3)
		pMsg->KeyDesc.KeyInfo.Install = 1;

	if ((MsgType == EAPOL_PAIR_MSG_1) || (MsgType == EAPOL_PAIR_MSG_3) || (MsgType == EAPOL_GROUP_MSG_1))
		pMsg->KeyDesc.KeyInfo.KeyAck = 1;

	if (MsgType != EAPOL_PAIR_MSG_1)
		pMsg->KeyDesc.KeyInfo.KeyMic = 1;

	if ((bWPA2 && (MsgType >= EAPOL_PAIR_MSG_3)) ||
		(!bWPA2 && (MsgType >= EAPOL_GROUP_MSG_1)))
    {
       	pMsg->KeyDesc.KeyInfo.Secure = 1;
    }

	/* This subfield shall be set, and the Key Data field shall be encrypted, if
	   any key material (e.g., GTK or SMK) is included in the frame. */
	if (bWPA2 && ((MsgType == EAPOL_PAIR_MSG_3) ||
		(MsgType == EAPOL_GROUP_MSG_1)))
    {
        pMsg->KeyDesc.KeyInfo.EKD_DL = 1;
    }

	/* key Information element has done. */
	*(USHORT *)(&pMsg->KeyDesc.KeyInfo) = cpu2le16(*(USHORT *)(&pMsg->KeyDesc.KeyInfo));

	/* Fill in Key Length*/
	if (bWPA2)
	{
		/* In WPA2 mode, the field indicates the length of pairwise key cipher, */
		/* so only pairwise_msg_1 and pairwise_msg_3 need to fill. */
		if ((MsgType == EAPOL_PAIR_MSG_1) || (MsgType == EAPOL_PAIR_MSG_3))
			pMsg->KeyDesc.KeyLength[1] = ((pEntry->WepStatus == Ndis802_11Encryption2Enabled) ? LEN_TKIP_TK : LEN_AES_TK);
	}
	else if (!bWPA2)
	{
		if (MsgType >= EAPOL_GROUP_MSG_1)
		{
			/* the length of group key cipher*/
			pMsg->KeyDesc.KeyLength[1] = ((GroupKeyWepStatus == Ndis802_11Encryption2Enabled) ? LEN_TKIP_GTK : LEN_AES_GTK);
		}
		else
		{
			/* the length of pairwise key cipher*/
			pMsg->KeyDesc.KeyLength[1] = ((pEntry->WepStatus == Ndis802_11Encryption2Enabled) ? LEN_TKIP_TK : LEN_AES_TK);
		}
	}

 	/* Fill in replay counter        		*/
    memmove(pMsg->KeyDesc.ReplayCounter, pEntry->R_Counter, LEN_KEY_DESC_REPLAY);

	/* Fill Key Nonce field		  */
	/* ANonce : pairwise_msg1 & pairwise_msg3*/
	/* SNonce : pairwise_msg2*/
	/* GNonce : group_msg1_wpa1	*/
	if ((MsgType <= EAPOL_PAIR_MSG_3) || ((!bWPA2 && (MsgType == EAPOL_GROUP_MSG_1))))
    	memmove(pMsg->KeyDesc.KeyNonce, KeyNonce, LEN_KEY_DESC_NONCE);

	/* Fill key IV - WPA2 as 0, WPA1 as random*/
	if (!bWPA2 && (MsgType == EAPOL_GROUP_MSG_1))
	{
		/* Suggest IV be random number plus some number,*/
		memmove(pMsg->KeyDesc.KeyIv, &KeyNonce[16], LEN_KEY_DESC_IV);
        pMsg->KeyDesc.KeyIv[15] += 2;
	}

    /* Fill Key RSC field        */
    /* It contains the RSC for the GTK being installed.*/
	if ((MsgType == EAPOL_PAIR_MSG_3 && bWPA2) || (MsgType == EAPOL_GROUP_MSG_1))
	{
        memmove(pMsg->KeyDesc.KeyRsc, TxRSC, 6);
	}

	/* Clear Key MIC field for MIC calculation later   */
    memset(pMsg->KeyDesc.KeyMic, 0, LEN_KEY_DESC_MIC);

	ConstructEapolKeyData(pEntry,
						  GroupKeyWepStatus,
						  KeyDescVer,
						  MsgType,
						  DefaultKeyIdx,
						  GTK,
						  RSNIE,
						  RSNIE_Len,
						  pMsg);

	/* Calculate MIC and fill in KeyMic Field except Pairwise Msg 1.*/
	if (MsgType != EAPOL_PAIR_MSG_1)
	{
		CalculateMIC(KeyDescVer, pEntry->PTK, pMsg);
	}

	DBGPRINT(RT_DEBUG_TRACE, ("===> ConstructEapolMsg for %s %s\n", ((bWPA2) ? "WPA2" : "WPA"), GetEapolMsgType(MsgType)));
	DBGPRINT(RT_DEBUG_TRACE, ("	     Body length = %d \n", CONV_ARRARY_TO_UINT16(pMsg->Body_Len)));
	DBGPRINT(RT_DEBUG_TRACE, ("	     Key length  = %d \n", CONV_ARRARY_TO_UINT16(pMsg->KeyDesc.KeyLength)));


}

/*
	========================================================================

	Routine Description:
		Construct the Key Data field of EAPoL message

	Arguments:
		pAd			Pointer	to our adapter
		Elem		Message body

	Return Value:
		None

	Note:

	========================================================================
*/
void ConstructEapolKeyData(
	PMAC_TABLE_ENTRY	pEntry,
	u8 		GroupKeyWepStatus,
	u8 		keyDescVer,
	u8 		MsgType,
	u8 		DefaultKeyIdx,
	u8 		*GTK,
	u8 		*RSNIE,
	u8 		RSNIE_LEN,
	PEAPOL_PACKET   pMsg)
{
	u8 	*mpool, *Key_Data, *eGTK;
	unsigned long		data_offset;
	bool 	bWPA2Capable = false;
	bool 	GTK_Included = false;

	/* Choose WPA2 or not*/
	if ((pEntry->AuthMode == Ndis802_11AuthModeWPA2) ||
		(pEntry->AuthMode == Ndis802_11AuthModeWPA2PSK))
		bWPA2Capable = true;

	if (MsgType == EAPOL_PAIR_MSG_1 ||
		MsgType == EAPOL_PAIR_MSG_4 ||
		MsgType == EAPOL_GROUP_MSG_2)
		return;

	/* allocate memory pool*/
	mpool = kmalloc(1500, GFP_ATOMIC);

    if (mpool == NULL)
		return;

	/* eGTK Len = 512 */
	eGTK = (u8 *) ROUND_UP(mpool, 4);
	/* Key_Data Len = 512 */
	Key_Data = (u8 *) ROUND_UP(eGTK + 512, 4);

	memset(Key_Data, 0, 512);
	SET_UINT16_TO_ARRARY(pMsg->KeyDesc.KeyDataLen, 0);
	data_offset = 0;

	/* Encapsulate RSNIE in pairwise_msg2 & pairwise_msg3		*/
	if (RSNIE_LEN && ((MsgType == EAPOL_PAIR_MSG_2) || (MsgType == EAPOL_PAIR_MSG_3)))
	{
		u8 *	pmkid_ptr = NULL;
		u8 	pmkid_len = 0;


		RTMPInsertRSNIE(&Key_Data[data_offset],
						&data_offset,
						RSNIE,
						RSNIE_LEN,
						pmkid_ptr,
						pmkid_len);
	}


	/* Encapsulate GTK 		*/
	/* Only for pairwise_msg3_WPA2 and group_msg1*/
	if ((MsgType == EAPOL_PAIR_MSG_3 && bWPA2Capable) || (MsgType == EAPOL_GROUP_MSG_1))
	{
		u8	gtk_len;

		/* Decide the GTK length */
		if (GroupKeyWepStatus == Ndis802_11Encryption3Enabled)
			gtk_len = LEN_AES_GTK;
		else
			gtk_len = LEN_TKIP_GTK;

		/* Insert GTK KDE format in WAP2 mode */
		if (bWPA2Capable)
		{
			/* Construct the common KDE format */
			WPA_ConstructKdeHdr(KDE_GTK, 2 + gtk_len, &Key_Data[data_offset]);
			data_offset += sizeof(KDE_HDR);

			/* GTK KDE format - 802.11i-2004  Figure-43x*/
	        Key_Data[data_offset] = (DefaultKeyIdx & 0x03);
	        Key_Data[data_offset + 1] = 0x00;	/* Reserved Byte*/
	        data_offset += 2;
		}

		/* Fill in GTK */
		memmove(&Key_Data[data_offset], GTK, gtk_len);
		data_offset += gtk_len;


		GTK_Included = true;
	}



	/* If the Encrypted Key Data subfield (of the Key Information field)
	   is set, the entire Key Data field shall be encrypted. */
	/* This whole key-data field shall be encrypted if a GTK is included.*/
	/* Encrypt the data material in key data field with KEK*/
	if (GTK_Included)
	{
		if (
			(keyDescVer == KEY_DESC_AES))
		{
			u8 	remainder = 0;
			u8 pad_len = 0;
			UINT	wrap_len =0;

			/* Key Descriptor Version 2 or 3: AES key wrap, defined in IETF RFC 3394, */
			/* shall be used to encrypt the Key Data field using the KEK field from */
			/* the derived PTK.*/

			/* If the Key Data field uses the NIST AES key wrap, then the Key Data field */
			/* shall be padded before encrypting if the key data length is less than 16 */
			/* octets or if it is not a multiple of 8. The padding consists of appending*/
			/* a single octet 0xdd followed by zero or more 0x00 octets. */
			if ((remainder = data_offset & 0x07) != 0)
			{
				INT		i;

				pad_len = (8 - remainder);
				Key_Data[data_offset] = 0xDD;
				for (i = 1; i < pad_len; i++)
					Key_Data[data_offset + i] = 0;

				data_offset += pad_len;
			}

			AES_Key_Wrap(Key_Data, (UINT) data_offset,
						 &pEntry->PTK[LEN_PTK_KCK], LEN_PTK_KEK,
						 eGTK, &wrap_len);
			data_offset = wrap_len;

		}
		else
		{
			TKIP_GTK_KEY_WRAP(&pEntry->PTK[LEN_PTK_KCK],
								pMsg->KeyDesc.KeyIv,
								Key_Data,
								data_offset,
								eGTK);
		}

		memmove(pMsg->KeyDesc.KeyData, eGTK, data_offset);
	}
	else
	{
		memmove(pMsg->KeyDesc.KeyData, Key_Data, data_offset);
	}

	/* Update key data length field and total body length*/
	SET_UINT16_TO_ARRARY(pMsg->KeyDesc.KeyDataLen, data_offset);
	INC_UINT16_TO_ARRARY(pMsg->Body_Len, data_offset);

	kfree(mpool);

}

/*
	========================================================================

	Routine Description:
		Calcaulate MIC. It is used during 4-ways handsharking.

	Arguments:
		pAd				-	pointer to our pAdapter context
    	PeerWepStatus	-	indicate the encryption type

	Return Value:

	Note:
	 The EAPOL-Key MIC is a MIC of the EAPOL-Key frames,
	 from and including the EAPOL protocol version field
	 to and including the Key Data field, calculated with
	 the Key MIC field set to 0.

	========================================================================
*/
void CalculateMIC(
	u8 		KeyDescVer,
	u8 		*PTK,
	PEAPOL_PACKET   pMsg)
{
    u8   *OutBuffer;
	unsigned long	FrameLen = 0;
	u8 mic[LEN_KEY_DESC_MIC];
	u8 digest[80];

	/* allocate memory for MIC calculation*/
	OutBuffer = kmalloc(512, GFP_ATOMIC);

    if (OutBuffer == NULL)
    {
		DBGPRINT(RT_DEBUG_ERROR, ("!!!CalculateMIC: no memory!!!\n"));
		return;
    }

	/* make a frame for calculating MIC.*/
    MakeOutgoingFrame(OutBuffer,            	&FrameLen,
                      CONV_ARRARY_TO_UINT16(pMsg->Body_Len) + 4,  	pMsg,
                      END_OF_ARGS);

	memset(mic, 0, sizeof(mic));

	/* Calculate MIC*/
    if (KeyDescVer == KEY_DESC_AES)
 	{
		RT_HMAC_SHA1(PTK, LEN_PTK_KCK, OutBuffer,  FrameLen, digest, SHA1_DIGEST_SIZE);
		memmove(mic, digest, LEN_KEY_DESC_MIC);
	}
	else if (KeyDescVer == KEY_DESC_TKIP)
	{
		RT_HMAC_MD5(PTK, LEN_PTK_KCK, OutBuffer, FrameLen, mic, MD5_DIGEST_SIZE);
	}
	else if (KeyDescVer == KEY_DESC_EXT)
	{
		UINT	mlen = AES_KEY128_LENGTH;
		AES_CMAC(OutBuffer, FrameLen, PTK, LEN_PTK_KCK, mic, &mlen);
	}

	/* store the calculated MIC*/
	memmove(pMsg->KeyDesc.KeyMic, mic, LEN_KEY_DESC_MIC);

	kfree(OutBuffer);
}

u8 RTMPExtractKeyIdxFromIVHdr(
	u8 *		pIV,
	u8			CipherAlg)
{
	u8 keyIdx = 0xFF;

	/* extract the key index from IV header */
	switch (CipherAlg)
	{
		case Ndis802_11Encryption1Enabled:
		case Ndis802_11Encryption2Enabled:
		case Ndis802_11Encryption3Enabled:
		case Ndis802_11GroupWEP40Enabled:
		case Ndis802_11GroupWEP104Enabled:
			keyIdx = (*(pIV + 3) & 0xc0) >> 6;
			break;

	}

	return keyIdx;

}

PCIPHER_KEY RTMPSwCipherKeySelection(
	struct rtmp_adapter*pAd,
	u8 *pIV,
	RX_BLK *pRxBlk,
	MAC_TABLE_ENTRY *pEntry)
{
	PCIPHER_KEY pKey = NULL;
	u8 keyIdx = 0;
	u8 CipherAlg = Ndis802_11EncryptionDisabled;

	if ((pEntry == NULL) ||
		(RX_BLK_TEST_FLAG(pRxBlk, fRX_APCLI)) ||
		(RX_BLK_TEST_FLAG(pRxBlk, fRX_WDS)) ||
		(RX_BLK_TEST_FLAG(pRxBlk, fRX_MESH)))
		return NULL;

	if (pRxBlk->pRxInfo->U2M)
	{
		CipherAlg = pEntry->WepStatus;
	}
	else
	{
#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
			CipherAlg = pAd->StaCfg.GroupCipher;
		}
#endif /* CONFIG_STA_SUPPORT */
	}

	if ((keyIdx = RTMPExtractKeyIdxFromIVHdr(pIV, CipherAlg)) > 3)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s : Invalid key index(%d) !!!\n",
								  __FUNCTION__, keyIdx));
		return NULL;
	}

	if (CipherAlg == Ndis802_11Encryption1Enabled)
	{
		pKey = &pAd->SharedKey[pEntry->apidx][keyIdx];
	}
	else if ((CipherAlg == Ndis802_11Encryption2Enabled) ||
  			 (CipherAlg == Ndis802_11Encryption3Enabled))
	{
		if (pRxBlk->pRxInfo->U2M)
			pKey = &pEntry->PairwiseKey;
		else {
#ifdef CONFIG_STA_SUPPORT
#endif /* CONFIG_STA_SUPPORT */
		    	pKey = &pAd->SharedKey[pEntry->apidx][keyIdx];
        }
	}

	return pKey;

}

/*
	========================================================================

	Routine Description:
		Some received frames can't decrypt by Asic, so decrypt them by software.

	Arguments:
		pAd				-	pointer to our pAdapter context
    	PeerWepStatus	-	indicate the encryption type

	Return Value:
		NDIS_STATUS_SUCCESS		-	decryption successful
		NDIS_STATUS_FAILURE		-	decryption failure

	========================================================================
*/
int	RTMPSoftDecryptionAction(
	struct rtmp_adapter *	pAd,
	u8 *		pHdr,
	u8    		UserPriority,
	PCIPHER_KEY		pKey,
	u8 *		pData,
	uint16_t			*DataByteCnt)
{
	switch (pKey->CipherAlg)
    {
		case CIPHER_WEP64:
		case CIPHER_WEP128:
			/* handle WEP decryption */
			if (RTMPSoftDecryptWEP(pAd, pKey, pData, &(*DataByteCnt)) == false)
			{
				DBGPRINT(RT_DEBUG_ERROR, ("ERROR : SW decrypt WEP data fails.\n"));
				/* give up this frame*/
				return NDIS_STATUS_FAILURE;
			}
			break;

		case CIPHER_TKIP:
			/* handle TKIP decryption */
			if (RTMPSoftDecryptTKIP(pAd, pHdr, UserPriority,
								pKey, pData, &(*DataByteCnt)) == false)
			{
				DBGPRINT(RT_DEBUG_ERROR, ("ERROR : SW decrypt TKIP data fails.\n"));
				/* give up this frame*/
				return NDIS_STATUS_FAILURE;
			}
			break;

		case CIPHER_AES:
			/* handle AES decryption */
			if (RTMPSoftDecryptCCMP(pAd, pHdr, pKey, pData, &(*DataByteCnt)) == false)
			{
				DBGPRINT(RT_DEBUG_ERROR, ("ERROR : SW decrypt AES data fails.\n"));
				/* give up this frame*/
				return NDIS_STATUS_FAILURE;
        	}
			break;
		default:
			/* give up this frame*/
			return NDIS_STATUS_FAILURE;
			break;
	}

	return NDIS_STATUS_SUCCESS;

}

void RTMPSoftConstructIVHdr(
	u8 		CipherAlg,
	u8 		key_id,
	u8 *		pTxIv,
	u8 *			pHdrIv,
	u8			*hdr_iv_len)
{
	*hdr_iv_len = 0;

	if ((CipherAlg == CIPHER_WEP64) || (CipherAlg == CIPHER_WEP128))
	{
		/* Construct and insert 4-bytes WEP IV header to MPDU header */
		RTMPConstructWEPIVHdr(key_id, pTxIv, pHdrIv);
		*hdr_iv_len = LEN_WEP_IV_HDR;
	}
	else if (CipherAlg == CIPHER_TKIP)
		;
	else if (CipherAlg == CIPHER_AES)
	{
		/* Construct and insert 8-bytes CCMP header to MPDU header */
		RTMPConstructCCMPHdr(key_id, pTxIv, pHdrIv);
		*hdr_iv_len = LEN_CCMP_HDR;
	}

}

void RTMPSoftEncryptionAction(
	struct rtmp_adapter *pAd,
	u8 		CipherAlg,
	u8 *		pHdr,
	u8 *		pSrcBufData,
	u32			SrcBufLen,
	u8 		KeyIdx,
	PCIPHER_KEY		pKey,
	u8			*ext_len)
{
	*ext_len = 0;

	if ((CipherAlg == CIPHER_WEP64) || (CipherAlg == CIPHER_WEP128))
	{
		/* Encrypt the MPDU data by software*/
		RTMPSoftEncryptWEP(pAd,
						   pKey->TxTsc,
						   pKey,
						   pSrcBufData,
						   SrcBufLen);

		*ext_len = LEN_ICV;
	}
	else if (CipherAlg == CIPHER_TKIP)
		;
	else if (CipherAlg == CIPHER_AES)
	{
		/* Encrypt the MPDU data by software*/
		RTMPSoftEncryptCCMP(pAd,
							pHdr,
							pKey->TxTsc,
							pKey->Key,
							pSrcBufData,
							SrcBufLen);

		*ext_len = LEN_CCMP_MIC;
	}

}

u8 *	WPA_ExtractSuiteFromRSNIE(
		u8 *	rsnie,
		UINT	rsnie_len,
		u8	type,
		u8	*count)
{
	PEID_STRUCT pEid;
	INT			len;
	u8 *		pBuf;
	INT			offset = 0;

	pEid = (PEID_STRUCT)rsnie;
	len = rsnie_len - 2;	/* exclude IE and length*/
	pBuf = (u8 *)&pEid->Octet[0];

	/* set default value*/
	*count = 0;

	/* Check length*/
	if ((len <= 0) || (pEid->Len != len))
	{
		DBGPRINT_ERR(("%s : The length is invalid\n", __FUNCTION__));
		goto out;
	}

	/* Check WPA or WPA2*/
	if (pEid->Eid == IE_WPA)
	{
		/* Check the length */
		if (len < sizeof(RSNIE))
		{
			DBGPRINT(RT_DEBUG_ERROR, ("%s : The length is too short for WPA\n", __FUNCTION__));
			goto out;
		}
		else
		{
			PRSNIE	pRsnie;
			uint16_t 	u_cnt;

			pRsnie = (PRSNIE)pBuf;
			u_cnt = cpu2le16(pRsnie->ucount);
			offset = sizeof(RSNIE) + (LEN_OUI_SUITE * (u_cnt - 1));

			if (len < offset)
		{
				DBGPRINT(RT_DEBUG_ERROR, ("%s : The expected lenght(%d) exceed the remaining length(%d) for WPA-RSN \n",
											__FUNCTION__, offset, len));
				goto out;
		}
			else
			{
		/* Get the group cipher*/
		if (type == GROUP_SUITE)
		{
			*count = 1;
			return pRsnie->mcast;
		}
		/* Get the pairwise cipher suite*/
		else if (type == PAIRWISE_SUITE)
		{
			DBGPRINT(RT_DEBUG_TRACE, ("%s : The count of pairwise cipher is %d\n",
												__FUNCTION__, u_cnt));
						*count = u_cnt;
			return pRsnie->ucast[0].oui;
		}
			}
		}
	}
	else if (pEid->Eid == IE_RSN)
	{
		if (len < sizeof(RSNIE2))
		{
			DBGPRINT(RT_DEBUG_ERROR, ("%s : The length is too short for WPA2\n", __FUNCTION__));
			goto out;
		}
		else
		{
			PRSNIE2	pRsnie2;
			uint16_t 	u_cnt;

			pRsnie2 = (PRSNIE2)pBuf;
			u_cnt = cpu2le16(pRsnie2->ucount);
			offset = sizeof(RSNIE2) + (LEN_OUI_SUITE * (u_cnt - 1));

			if (len < offset)
		{
				DBGPRINT(RT_DEBUG_ERROR, ("%s : The expected lenght(%d) exceed the remaining length(%d) for WPA2-RSN \n",
											__FUNCTION__, offset, len));
				goto out;
		}
			else
			{
		/* Get the group cipher*/
		if (type == GROUP_SUITE)
		{
			*count = 1;
					return pRsnie2->mcast;
		}
		/* Get the pairwise cipher suite*/
		else if (type == PAIRWISE_SUITE)
		{
			DBGPRINT(RT_DEBUG_TRACE, ("%s : The count of pairwise cipher is %d\n",
										__FUNCTION__, u_cnt));
					*count = u_cnt;
					return pRsnie2->ucast[0].oui;
				}
			}
		}
	}
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s : Unknown IE (%d)\n", __FUNCTION__, pEid->Eid));
		goto out;
	}

	/* skip group cipher and pairwise cipher suite	*/
	pBuf += offset;
	len -= offset;

	/* Ready to extract the AKM information and its count */
	if (len < sizeof(RSNIE_AUTH))
	{
		DBGPRINT_ERR(("%s : The length of AKM of RSN is too short\n", __FUNCTION__));
		goto out;
	}
	else
	{
		PRSNIE_AUTH	pAkm;
		uint16_t 		a_cnt;

		/* pointer to AKM count */
	pAkm = (PRSNIE_AUTH)pBuf;
		a_cnt = cpu2le16(pAkm->acount);
		offset = sizeof(RSNIE_AUTH) + (LEN_OUI_SUITE * (a_cnt - 1));

		if (len < offset)
	{
			DBGPRINT(RT_DEBUG_ERROR, ("%s : The expected lenght(%d) exceed the remaining length(%d) for AKM \n",
										__FUNCTION__, offset, len));
			goto out;
	}
		else
		{
			/* Get the AKM suite */
	if (type == AKM_SUITE)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("%s : The count of AKM is %d\n",
											__FUNCTION__, a_cnt));
				*count = a_cnt;
		return pAkm->auth[0].oui;
	}
		}
	}

	/* For WPA1, the remaining shall be ignored. */
	if (pEid->Eid == IE_WPA)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("%s : The remaining shall be ignored in WPA mode\n",
									__FUNCTION__));
		goto out;
	}

	/* skip the AKM capability */
	pBuf += offset;
	len -= offset;

	/* Parse the RSN Capabilities */
	if (len < sizeof(RSN_CAPABILITIES))
	{
		DBGPRINT(RT_DEBUG_TRACE, ("%s : The peer RSNIE doesn't include RSN-Cap\n", __FUNCTION__));
		goto out;
	}
	else
	{
		/* Report the content of the RSN capabilities */
		if (type == RSN_CAP_INFO)
		{
			DBGPRINT(RT_DEBUG_TRACE, ("%s : Extract RSN Capabilities\n", __FUNCTION__));
			*count = 1;
			return pBuf;
		}

		/* skip RSN capability (2-bytes) */
		offset = sizeof(RSN_CAPABILITIES);
		pBuf += offset;
		len -= offset;
	}

	/* Extract PMKID-list field */
	if (len < sizeof(uint16_t))
	{
		DBGPRINT(RT_DEBUG_TRACE, ("%s : The peer RSNIE doesn't include PMKID list Count\n", __FUNCTION__));
		goto out;
	}
	else
	{
		uint16_t 	p_count;
		u8 *	pPmkidList = NULL;

		memmove(&p_count, pBuf, sizeof(uint16_t));
		p_count = cpu2le16(p_count);

		/* Get count of the PMKID list */
		if (p_count > 0)
		{
			PRSNIE_PMKID 	pRsnPmkid;

			/* the expected length of PMKID-List field */
			offset = sizeof(RSNIE_PMKID) + (LEN_PMKID * (p_count - 1));

			/* sanity check about the length of PMKID-List field */
			if (len < offset)
			{
				DBGPRINT(RT_DEBUG_ERROR, ("%s : The expected lenght(%d) exceed the remaining length(%d) in PMKID-field \n",
											__FUNCTION__, offset, len));
				goto out;
			}

			/* pointer to PMKID field */
			pRsnPmkid = (PRSNIE_PMKID)pBuf;
			pPmkidList = pRsnPmkid->pmkid[0].list;

		}
		else
		{
			/* The PMKID field shall be without PMKID-List */
			offset = sizeof(uint16_t);
			pPmkidList = NULL;
		}


		/* Extract PMKID list and its count */
		if (type == PMKID_LIST)
		{
			*count = p_count;
			return pPmkidList;
		}

		/* skip the PMKID field */
		pBuf += offset;
		len -= offset;

	}


out:
	*count = 0;
	return NULL;

}

void WpaShowAllsuite(
	u8 *	rsnie,
	UINT	rsnie_len)
{
	u8 * pSuite = NULL;
	u8 count;


}

void RTMPInsertRSNIE(
	u8 *pFrameBuf,
	unsigned long *pFrameLen,
	u8 * rsnie_ptr,
	u8  rsnie_len,
	u8 * pmkid_ptr,
	u8  pmkid_len)
{
	u8 *pTmpBuf;
	unsigned long 	TempLen = 0;
	u8 	extra_len = 0;
	uint16_t 	pmk_count = 0;
	u8 ie_num;
	u8 	total_len = 0;
    u8 WPA2_OUI[3]={0x00,0x0F,0xAC};

	pTmpBuf = pFrameBuf;

	/* PMKID-List Must larger than 0 and the multiple of 16. */
	if (pmkid_len > 0 && ((pmkid_len & 0x0f) == 0))
	{
		extra_len = sizeof(uint16_t) + pmkid_len;

		pmk_count = (pmkid_len >> 4);
		pmk_count = cpu2le16(pmk_count);
	}
	else
	{
		DBGPRINT(RT_DEBUG_TRACE, ("%s : no PMKID-List included(%d).\n", __FUNCTION__, pmkid_len));
	}

	if (rsnie_len != 0)
	{
		ie_num = IE_WPA;
		total_len = rsnie_len;

		if (memcmp(rsnie_ptr + 2, WPA2_OUI, sizeof(WPA2_OUI)) == 0)
		{
			ie_num = IE_RSN;
			total_len += extra_len;
		}

		/* construct RSNIE body */
		MakeOutgoingFrame(pTmpBuf,			&TempLen,
					  	  1,				&ie_num,
					  	  1,				&total_len,
					  	  rsnie_len,		rsnie_ptr,
					  	  END_OF_ARGS);

		pTmpBuf += TempLen;
		*pFrameLen = *pFrameLen + TempLen;

		if (ie_num == IE_RSN)
		{
			/* Insert PMKID-List field */
			if (extra_len > 0)
			{
				MakeOutgoingFrame(pTmpBuf,					&TempLen,
							  	  2,						&pmk_count,
							  	  pmkid_len,				pmkid_ptr,
							  	  END_OF_ARGS);

				pTmpBuf += TempLen;
				*pFrameLen = *pFrameLen + TempLen;
			}
		}
	}

	return;
}


void WPAInstallPairwiseKey(
	struct rtmp_adapter *	pAd,
	u8				BssIdx,
	PMAC_TABLE_ENTRY	pEntry,
	bool 			bAE)
{
    memset(&pEntry->PairwiseKey, 0, sizeof(CIPHER_KEY));

	/* Assign the pairwise cipher algorithm	*/
    if (pEntry->WepStatus == Ndis802_11Encryption2Enabled)
        pEntry->PairwiseKey.CipherAlg = CIPHER_TKIP;
    else if (pEntry->WepStatus == Ndis802_11Encryption3Enabled)
        pEntry->PairwiseKey.CipherAlg = CIPHER_AES;
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s : fails (wcid-%d)\n",
										__FUNCTION__, pEntry->Aid));
		return;
	}

	/* Assign key material and its length */
    pEntry->PairwiseKey.KeyLen = LEN_TK;
    memmove(pEntry->PairwiseKey.Key, &pEntry->PTK[OFFSET_OF_PTK_TK], LEN_TK);
	if (pEntry->PairwiseKey.CipherAlg == CIPHER_TKIP)
	{
		if (bAE)
		{
		    memmove(pEntry->PairwiseKey.TxMic, &pEntry->PTK[OFFSET_OF_AP_TKIP_TX_MIC], LEN_TKIP_MIC);
		    memmove(pEntry->PairwiseKey.RxMic, &pEntry->PTK[OFFSET_OF_AP_TKIP_RX_MIC], LEN_TKIP_MIC);
		}
		else
		{
		    memmove(pEntry->PairwiseKey.TxMic, &pEntry->PTK[OFFSET_OF_STA_TKIP_TX_MIC], LEN_TKIP_MIC);
		    memmove(pEntry->PairwiseKey.RxMic, &pEntry->PTK[OFFSET_OF_STA_TKIP_RX_MIC], LEN_TKIP_MIC);
		}
	}

#ifdef SOFT_ENCRYPT
	if (CLIENT_STATUS_TEST_FLAG(pEntry, fCLIENT_STATUS_SOFTWARE_ENCRYPT))
	{
		DBGPRINT(RT_DEBUG_TRACE, ("===> SW_ENC ON(wcid=%d) \n", pEntry->Aid));
		memset(pEntry->PairwiseKey.TxTsc, 0, LEN_WPA_TSC);
		memset(pEntry->PairwiseKey.RxTsc, 0, LEN_WPA_TSC);
	}
	else
#endif /* SOFT_ENCRYPT */
	{
		/* Add Pair-wise key to Asic */
	    AsicAddPairwiseKeyEntry(
	        pAd,
	        (u8)pEntry->Aid,
	        &pEntry->PairwiseKey);

		RTMPSetWcidSecurityInfo(pAd,
								BssIdx,
								0,
								pEntry->PairwiseKey.CipherAlg,
								(u8)pEntry->Aid,
								PAIRWISEKEYTABLE);
	}

}

void WPAInstallSharedKey(
	struct rtmp_adapter *	pAd,
	u8				GroupCipher,
	u8				BssIdx,
	u8				KeyIdx,
	u8				Wcid,
	bool 			bAE,
	u8 *				pGtk,
	u8				GtkLen)
{
	PCIPHER_KEY 	pSharedKey;

	if (BssIdx >= MAX_MBSSID_NUM(pAd))
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s : The BSS-index(%d) is out of range for MBSSID link. \n",
									__FUNCTION__, BssIdx));
		return;
	}

	pSharedKey = &pAd->SharedKey[BssIdx][KeyIdx];
	memset(pSharedKey, 0, sizeof(CIPHER_KEY));

	/* Set the group cipher */
	if (GroupCipher == Ndis802_11GroupWEP40Enabled)
		pSharedKey->CipherAlg = CIPHER_WEP64;
	else if (GroupCipher == Ndis802_11GroupWEP104Enabled)
		pSharedKey->CipherAlg = CIPHER_WEP128;
	else if (GroupCipher == Ndis802_11Encryption2Enabled)
		pSharedKey->CipherAlg = CIPHER_TKIP;
	else if (GroupCipher == Ndis802_11Encryption3Enabled)
		pSharedKey->CipherAlg = CIPHER_AES;
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s : fails (IF/ra%d) \n",
										__FUNCTION__, BssIdx));
		return;
	}

	/* Set the key material and its length */
	if (GroupCipher == Ndis802_11GroupWEP40Enabled ||
		GroupCipher == Ndis802_11GroupWEP104Enabled)
	{
		/* Sanity check the length */
		if ((GtkLen != LEN_WEP64) && (GtkLen != LEN_WEP128))
		{
			DBGPRINT(RT_DEBUG_ERROR, ("%s : (IF/ra%d) WEP key invlaid(%d) \n",
										__FUNCTION__, BssIdx, GtkLen));
			return;
		}

		pSharedKey->KeyLen = GtkLen;
		memmove(pSharedKey->Key, pGtk, GtkLen);
	}
	else
	{
		/* Sanity check the length */
		if (GtkLen < LEN_TK)
		{
			DBGPRINT(RT_DEBUG_ERROR, ("%s : (IF/ra%d) WPA key invlaid(%d) \n",
										__FUNCTION__, BssIdx, GtkLen));
			return;
		}

		pSharedKey->KeyLen = LEN_TK;
		memmove(pSharedKey->Key, pGtk, LEN_TK);
		if (pSharedKey->CipherAlg == CIPHER_TKIP)
		{
			if (bAE)
			{
				memmove(pSharedKey->TxMic, pGtk + 16, LEN_TKIP_MIC);
				memmove(pSharedKey->RxMic, pGtk + 24, LEN_TKIP_MIC);
			}
			else
			{
				memmove(pSharedKey->TxMic, pGtk + 24, LEN_TKIP_MIC);
				memmove(pSharedKey->RxMic, pGtk + 16, LEN_TKIP_MIC);
			}
		}
	}

	/* Update group key table(0x6C00) and group key mode(0x7000) */
    AsicAddSharedKeyEntry(
				pAd,
				BssIdx,
				KeyIdx,
				pSharedKey);

	/* When Wcid isn't zero, it means that this is a Authenticator Role.
	   Only Authenticator entity needs to set HW IE/EIV table (0x6000)
	   and WCID attribute table (0x6800) for group key. */
	if (Wcid != 0)
	{
		RTMPSetWcidSecurityInfo(pAd,
								BssIdx,
								KeyIdx,
								pSharedKey->CipherAlg,
								Wcid,
								SHAREDKEYTABLE);
	}
}

void RTMPSetWcidSecurityInfo(
	struct rtmp_adapter *	pAd,
	u8				BssIdx,
	u8				KeyIdx,
	u8				CipherAlg,
	u8				Wcid,
	u8				KeyTabFlag)
{
	u32			IV = 0;
	u8			IV_KEYID = 0;

	/* Prepare initial IV value */
	if (CipherAlg == CIPHER_WEP64 || CipherAlg == CIPHER_WEP128)
	{
		INT	i;
		u8 TxTsc[LEN_WEP_TSC];

		/* Generate 3-bytes IV randomly for encryption using */
		for(i = 0; i < LEN_WEP_TSC; i++)
			TxTsc[i] = RandomByte(pAd);

		/* Update HW IVEIV table */
		IV_KEYID = (KeyIdx << 6);
		IV = (IV_KEYID << 24) |
			 (TxTsc[2] << 16) |
			 (TxTsc[1] << 8) |
			 (TxTsc[0]);
	}
	else if (CipherAlg == CIPHER_TKIP || CipherAlg == CIPHER_AES)
	{
		/* Set IVEIV as 1 in Asic -
		In IEEE 802.11-2007 8.3.3.4.3 described :
		The PN shall be implemented as a 48-bit monotonically incrementing
		non-negative integer, initialized to 1 when the corresponding
		temporal key is initialized or refreshed. */
		IV_KEYID = (KeyIdx << 6) | 0x20;
		IV = (IV_KEYID << 24) | 1;
	}
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s : Unsupport cipher Alg (%d) for Wcid-%d \n",
										__FUNCTION__, CipherAlg, Wcid));
		return;
	}
	/* Update WCID IV/EIV table */
	AsicUpdateWCIDIVEIV(pAd, Wcid, IV, 0);

	/* Update WCID attribute entry */
	AsicUpdateWcidAttributeEntry(pAd,
							BssIdx,
							KeyIdx,
							CipherAlg,
							Wcid,
							KeyTabFlag);

}

