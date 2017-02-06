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


#include	"rt_config.h"



INT Set_AutoReconnect_Proc(
    struct rtmp_adapter *pAd,
    char *		arg);

INT Set_AdhocN_Proc(
    struct rtmp_adapter *pAd,
    char *		arg);

/*
    ==========================================================================
    Description:
        Set SSID
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_SSID_Proc(
    struct rtmp_adapter *  pAd,
    char *         arg)
{
    NDIS_802_11_SSID                    Ssid, *pSsid=NULL;
    bool                             StateMachineTouched = false;
    int                                 success = true;

	/*
		Set the AutoReconnectSsid to prevent it reconnect to old SSID
		Since calling this indicate user don't want to connect to that SSID anymore.
	*/
	pAd->MlmeAux.AutoReconnectSsidLen= 32;
	memset(pAd->MlmeAux.AutoReconnectSsid, 0, pAd->MlmeAux.AutoReconnectSsidLen);

    if( strlen(arg) <= MAX_LEN_OF_SSID)
    {
        memset(&Ssid, 0, sizeof(NDIS_802_11_SSID));
        if (strlen(arg) != 0)
        {
            memmove(Ssid.Ssid, arg, strlen(arg));
            Ssid.SsidLength = strlen(arg);
        }
        else   /*ANY ssid */
        {
            Ssid.SsidLength = 0;
	    	memcpy(Ssid.Ssid, "", 0);
			pAd->StaCfg.BssType = BSS_INFRA;
			pAd->StaCfg.AuthMode = Ndis802_11AuthModeOpen;
	        pAd->StaCfg.WepStatus  = Ndis802_11EncryptionDisabled;
	}
        pSsid = &Ssid;

        if (pAd->Mlme.CntlMachine.CurrState != CNTL_IDLE)
        {
            RTMP_MLME_RESET_STATE_MACHINE(pAd);
            DBGPRINT(RT_DEBUG_TRACE, ("!!! MLME busy, reset MLME state machine !!!\n"));
        }

		if ((pAd->StaCfg.WpaPassPhraseLen >= 8) &&
			(pAd->StaCfg.WpaPassPhraseLen <= 64))
		{
			u8 keyMaterial[40];

			memset(pAd->StaCfg.PMK, 0, 32);
			if (pAd->StaCfg.WpaPassPhraseLen == 64)
			{
			    AtoH((char *) pAd->StaCfg.WpaPassPhrase, pAd->StaCfg.PMK, 32);
			}
			else
			{
			    RtmpPasswordHash((char *) pAd->StaCfg.WpaPassPhrase, Ssid.Ssid, Ssid.SsidLength, keyMaterial);
			    memmove(pAd->StaCfg.PMK, keyMaterial, 32);
			}
		}

		/* Record the desired user settings to MlmeAux */
		memset(pAd->MlmeAux.Ssid, 0, MAX_LEN_OF_SSID);
		memmove(pAd->MlmeAux.Ssid, Ssid.Ssid, Ssid.SsidLength);
		pAd->MlmeAux.SsidLen = (u8)Ssid.SsidLength;

		memmove(pAd->MlmeAux.AutoReconnectSsid, Ssid.Ssid, Ssid.SsidLength);
		pAd->MlmeAux.AutoReconnectSsidLen = (u8)Ssid.SsidLength;

        pAd->MlmeAux.CurrReqIsFromNdis = true;
        pAd->StaCfg.bSkipAutoScanConn = false;
		pAd->bConfigChanged = true;
        pAd->StaCfg.bNotFirstScan = false;

        MlmeEnqueue(pAd,
                    MLME_CNTL_STATE_MACHINE,
                    OID_802_11_SSID,
                    sizeof(NDIS_802_11_SSID),
                    (void *)pSsid, 0);

        StateMachineTouched = true;
		if (Ssid.SsidLength == MAX_LEN_OF_SSID)
			;
		else
			DBGPRINT(RT_DEBUG_TRACE, ("Set_SSID_Proc::(Len=%d,Ssid=%s)\n", Ssid.SsidLength, Ssid.Ssid));
    }
    else
        success = false;

    if (StateMachineTouched) /* Upper layer sent a MLME-related operations */
    	RTMP_MLME_HANDLER(pAd);

    return success;
}

/*
    ==========================================================================
    Description:
        Set Network Type(Infrastructure/Adhoc mode)
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_NetworkType_Proc(
    struct rtmp_adapter *  pAd,
    char *         arg)
{
    u32	Value = 0;

    if (strcmp(arg, "Adhoc") == 0)
	{
		if (pAd->StaCfg.BssType != BSS_ADHOC)
		{
			/* Config has changed */
			pAd->bConfigChanged = true;
            if (MONITOR_ON(pAd))
            {
                mt7610u_write32(pAd, RX_FILTR_CFG, STANORMAL);
                Value = mt7610u_read32(pAd, MAC_SYS_CTRL);
		Value &= (~0x80);
		mt7610u_write32(pAd, MAC_SYS_CTRL, Value);
                OPSTATUS_CLEAR_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED);
                LinkDown(pAd, false);
            }
			if (INFRA_ON(pAd))
			{
				/*bool Cancelled; */
				/* Set the AutoReconnectSsid to prevent it reconnect to old SSID */
				/* Since calling this indicate user don't want to connect to that SSID anymore. */
				pAd->MlmeAux.AutoReconnectSsidLen= 32;
				memset(pAd->MlmeAux.AutoReconnectSsid, 0, pAd->MlmeAux.AutoReconnectSsidLen);

				LinkDown(pAd, false);

				DBGPRINT(RT_DEBUG_TRACE, ("NDIS_STATUS_MEDIA_DISCONNECT Event BB!\n"));
			}
#ifdef DOT11_N_SUPPORT
			SetCommonHT(pAd);
#endif /* DOT11_N_SUPPORT */
		}
		pAd->StaCfg.BssType = BSS_ADHOC;
		RTMP_OS_NETDEV_SET_TYPE(pAd->net_dev, pAd->StaCfg.OriDevType);

		DBGPRINT(RT_DEBUG_TRACE, ("===>Set_NetworkType_Proc::(AD-HOC)\n"));
	}
    else if (strcmp(arg, "Infra") == 0)
	{
		if (pAd->StaCfg.BssType != BSS_INFRA)
		{
			/* Config has changed */
			pAd->bConfigChanged = true;
            if (MONITOR_ON(pAd))
            {
                mt7610u_write32(pAd, RX_FILTR_CFG, STANORMAL);
                Value = mt7610u_read32(pAd, MAC_SYS_CTRL);
		Value &= (~0x80);
		mt7610u_write32(pAd, MAC_SYS_CTRL, Value);
                OPSTATUS_CLEAR_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED);
                LinkDown(pAd, false);
            }
			if (ADHOC_ON(pAd))
			{
				/* Set the AutoReconnectSsid to prevent it reconnect to old SSID */
				/* Since calling this indicate user don't want to connect to that SSID anymore. */
				pAd->MlmeAux.AutoReconnectSsidLen= 32;
				memset(pAd->MlmeAux.AutoReconnectSsid, 0, pAd->MlmeAux.AutoReconnectSsidLen);

				LinkDown(pAd, false);
			}
#ifdef DOT11_N_SUPPORT
			SetCommonHT(pAd);
#endif /* DOT11_N_SUPPORT */
		}
		pAd->StaCfg.BssType = BSS_INFRA;
		RTMP_OS_NETDEV_SET_TYPE(pAd->net_dev, pAd->StaCfg.OriDevType);
		DBGPRINT(RT_DEBUG_TRACE, ("===>Set_NetworkType_Proc::(INFRA)\n"));
	}
#ifdef MONITOR_FLAG_11N_SNIFFER_SUPPORT
	/*
		Monitor2 is for 3593 11n wireshark sniffer tool.
		The name, Monitor2, follows the command format in RT2883.
	*/
    else if ((strcmp(arg, "Monitor") == 0) || (strcmp(arg, "Monitor2") == 0))
#else
    else if (strcmp(arg, "Monitor") == 0)
#endif /* MONITOR_FLAG_11N_SNIFFER_SUPPORT */
	{
		BCN_TIME_CFG_STRUC csr;
		u8 rf_channel, rf_bw;
		INT ext_ch;

#ifdef MONITOR_FLAG_11N_SNIFFER_SUPPORT
		if (strcmp(arg, "Monitor2") == 0)
			pAd->StaCfg.BssMonitorFlag |= MONITOR_FLAG_11N_SNIFFER;
#endif /* MONITOR_FLAG_11N_SNIFFER_SUPPORT */

		OPSTATUS_CLEAR_FLAG(pAd, fOP_STATUS_INFRA_ON);
		OPSTATUS_CLEAR_FLAG(pAd, fOP_STATUS_ADHOC_ON);
		OPSTATUS_SET_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED);
		/* disable all periodic state machine */
		/* reset all mlme state machine */
		RTMP_MLME_RESET_STATE_MACHINE(pAd);
		DBGPRINT(RT_DEBUG_TRACE, ("fOP_STATUS_MEDIA_STATE_CONNECTED \n"));
		if (pAd->CommonCfg.CentralChannel == 0)
		{
#ifdef DOT11_N_SUPPORT
			if (WMODE_EQUAL(pAd->CommonCfg.PhyMode, WMODE_A | WMODE_AN))
				pAd->CommonCfg.CentralChannel = 36;
			else
#endif /* DOT11_N_SUPPORT */
				pAd->CommonCfg.CentralChannel = 6;
		}
#ifdef DOT11_N_SUPPORT
		else
			N_ChannelCheck(pAd);
#endif /* DOT11_N_SUPPORT */


		/* same procedure with window driver */
#ifdef DOT11_N_SUPPORT
		if (WMODE_CAP_N(pAd->CommonCfg.PhyMode) &&
			pAd->CommonCfg.RegTransmitSetting.field.BW == BW_40 &&
			pAd->CommonCfg.RegTransmitSetting.field.EXTCHA == EXTCHA_ABOVE)
		{
			/* 40MHz ,control channel at lower */
			pAd->CommonCfg.CentralChannel = pAd->CommonCfg.Channel + 2;
			ext_ch = EXTCHA_ABOVE;
			rf_bw = BW_40;
			rf_channel = pAd->CommonCfg.CentralChannel;
		}
		else if (WMODE_CAP_N(pAd->CommonCfg.PhyMode) &&
	                 pAd->CommonCfg.RegTransmitSetting.field.BW == BW_40 &&
		              pAd->CommonCfg.RegTransmitSetting.field.EXTCHA == EXTCHA_BELOW)
		{
			/* 40MHz ,control channel at upper */
			pAd->CommonCfg.CentralChannel = pAd->CommonCfg.Channel - 2;
			ext_ch = EXTCHA_BELOW;
			rf_bw = BW_40;
			rf_channel = pAd->CommonCfg.CentralChannel;
		}
		else
#endif /* DOT11_N_SUPPORT */
		{
			/* 20MHz */
			rf_bw = BW_20;
			ext_ch = EXTCHA_NONE;
			rf_channel = pAd->CommonCfg.Channel;
		}

		AsicSetChannel(pAd, rf_channel, rf_bw, ext_ch, false);
		DBGPRINT(RT_DEBUG_TRACE, ("%s():BW_%s, CtrlChannel(%d), CentralChannel(%d) \n",
					__FUNCTION__, (rf_bw == BW_40 ? "40" : "20"),
					pAd->CommonCfg.Channel,
					pAd->CommonCfg.CentralChannel));


		/* Enable Rx with promiscuous reception */
		mt7610u_write32(pAd, RX_FILTR_CFG, 0x3);
		/* ASIC supporsts sniffer function with replacing RSSI with timestamp. */
		/* Value = mt7610u_read32(pAdapter, MAC_SYS_CTRL); */
		/*Value |= (0x80); */
		/*mt7610u_write32(pAdapter, MAC_SYS_CTRL, Value); */

		/* disable sync */
		csr.word = mt7610u_read32(pAd, BCN_TIME_CFG);
		csr.field.bBeaconGen = 0;
		csr.field.bTBTTEnable = 0;
		csr.field.TsfSyncMode = 0;
		mt7610u_write32(pAd, BCN_TIME_CFG, csr.word);

		pAd->StaCfg.BssType = BSS_MONITOR;
		RTMP_OS_NETDEV_SET_TYPE_MONITOR(pAd->net_dev);
		DBGPRINT(RT_DEBUG_TRACE, ("===>Set_NetworkType_Proc::(MONITOR)\n"));
	}

    /* Reset Ralink supplicant to not use, it will be set to start when UI set PMK key */
    pAd->StaCfg.WpaState = SS_NOTUSE;

    DBGPRINT(RT_DEBUG_TRACE, ("Set_NetworkType_Proc::(NetworkType=%d)\n", pAd->StaCfg.BssType));

    return true;
}

/*
    ==========================================================================
    Description:
        Set Authentication mode
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_AuthMode_Proc(
    struct rtmp_adapter *  pAd,
    char *         arg)
{
    if ((strcmp(arg, "WEPAUTO") == 0) || (strcmp(arg, "wepauto") == 0))
        pAd->StaCfg.AuthMode = Ndis802_11AuthModeAutoSwitch;
    else if ((strcmp(arg, "OPEN") == 0) || (strcmp(arg, "open") == 0))
        pAd->StaCfg.AuthMode = Ndis802_11AuthModeOpen;
    else if ((strcmp(arg, "SHARED") == 0) || (strcmp(arg, "shared") == 0))
        pAd->StaCfg.AuthMode = Ndis802_11AuthModeShared;
    else if ((strcmp(arg, "WPAPSK") == 0) || (strcmp(arg, "wpapsk") == 0))
        pAd->StaCfg.AuthMode = Ndis802_11AuthModeWPAPSK;
    else if ((strcmp(arg, "WPANONE") == 0) || (strcmp(arg, "wpanone") == 0))
        pAd->StaCfg.AuthMode = Ndis802_11AuthModeWPANone;
    else if ((strcmp(arg, "WPA2PSK") == 0) || (strcmp(arg, "wpa2psk") == 0))
        pAd->StaCfg.AuthMode = Ndis802_11AuthModeWPA2PSK;
#ifdef WPA_SUPPLICANT_SUPPORT
    else if ((strcmp(arg, "WPA") == 0) || (strcmp(arg, "wpa") == 0))
        pAd->StaCfg.AuthMode = Ndis802_11AuthModeWPA;
    else if ((strcmp(arg, "WPA2") == 0) || (strcmp(arg, "wpa2") == 0))
        pAd->StaCfg.AuthMode = Ndis802_11AuthModeWPA2;
#endif /* WPA_SUPPLICANT_SUPPORT */
    else
        return false;

    pAd->StaCfg.PortSecured = WPA_802_1X_PORT_NOT_SECURED;

    DBGPRINT(RT_DEBUG_TRACE, ("Set_AuthMode_Proc::(AuthMode=%d)\n", pAd->StaCfg.AuthMode));

    return true;
}

/*
    ==========================================================================
    Description:
        Set Encryption Type
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_EncrypType_Proc(
    struct rtmp_adapter *  pAd,
    char *         arg)
{
    if ((strcmp(arg, "NONE") == 0) || (strcmp(arg, "none") == 0))
    {
        if (pAd->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
            return true;    /* do nothing */

        pAd->StaCfg.WepStatus     = Ndis802_11WEPDisabled;
        pAd->StaCfg.PairCipher    = Ndis802_11WEPDisabled;
	    pAd->StaCfg.GroupCipher   = Ndis802_11WEPDisabled;
    }
    else if ((strcmp(arg, "WEP") == 0) || (strcmp(arg, "wep") == 0))
    {
        if (pAd->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
            return true;    /* do nothing */

        pAd->StaCfg.WepStatus     = Ndis802_11WEPEnabled;
        pAd->StaCfg.PairCipher    = Ndis802_11WEPEnabled;
	    pAd->StaCfg.GroupCipher   = Ndis802_11WEPEnabled;
    }
    else if ((strcmp(arg, "TKIP") == 0) || (strcmp(arg, "tkip") == 0))
    {
        if (pAd->StaCfg.AuthMode < Ndis802_11AuthModeWPA)
            return true;    /* do nothing */

        pAd->StaCfg.WepStatus     = Ndis802_11Encryption2Enabled;
        pAd->StaCfg.PairCipher    = Ndis802_11Encryption2Enabled;
	    pAd->StaCfg.GroupCipher   = Ndis802_11Encryption2Enabled;
    }
    else if ((strcmp(arg, "AES") == 0) || (strcmp(arg, "aes") == 0))
    {
        if (pAd->StaCfg.AuthMode < Ndis802_11AuthModeWPA)
            return true;    /* do nothing */

        pAd->StaCfg.WepStatus     = Ndis802_11Encryption3Enabled;
        pAd->StaCfg.PairCipher    = Ndis802_11Encryption3Enabled;
	    pAd->StaCfg.GroupCipher   = Ndis802_11Encryption3Enabled;
    }
    else
        return false;

	if (pAd->StaCfg.BssType == BSS_ADHOC)
	{
		/* Build all corresponding channel information */
		RTMPSetPhyMode(pAd, pAd->CommonCfg.cfg_wmode);
	}

    DBGPRINT(RT_DEBUG_TRACE, ("Set_EncrypType_Proc::(EncrypType=%d)\n", pAd->StaCfg.WepStatus));

    return true;
}

/*
    ==========================================================================
    Description:
        Set Default Key ID
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_DefaultKeyID_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg)
{
    unsigned long                               KeyIdx;

    KeyIdx = simple_strtol(arg, 0, 10);
    if((KeyIdx >= 1 ) && (KeyIdx <= 4))
        pAdapter->StaCfg.DefaultKeyId = (u8) (KeyIdx - 1 );
    else
        return false;  /*Invalid argument */

    DBGPRINT(RT_DEBUG_TRACE, ("Set_DefaultKeyID_Proc::(DefaultKeyID=%d)\n", pAdapter->StaCfg.DefaultKeyId));

    return true;
}


INT Set_Wep_Key_Proc(
    struct rtmp_adapter *  pAdapter,
    char *        Key,
    INT             KeyLen,
    INT             KeyId)
{
    int    i;
    u8  CipherAlg = CIPHER_WEP64;
	struct wifi_dev *wdev = &pAdapter->StaCfg.wdev;

    if (wdev->AuthMode >= Ndis802_11AuthModeWPA)
        return true;    /* do nothing */

    if ((KeyId < 0) || (KeyId > 3))
    {
		DBGPRINT(RT_DEBUG_TRACE, ("Set_Wep_Key_Proc::Invalid KeyId (=%d)\n", KeyId));
		return false;
    }

    switch (KeyLen)
    {
        case 5: /* wep 40 Ascii type */
            pAdapter->SharedKey[BSS0][KeyId].KeyLen = KeyLen;
            memcpy(pAdapter->SharedKey[BSS0][KeyId].Key, Key, KeyLen);
            CipherAlg = CIPHER_WEP64;
            break;

        case 10: /* wep 40 Hex type */
            for(i=0; i < KeyLen; i++)
            {
                if( !isxdigit(*(Key+i)) )
                    return false;  /*Not Hex value; */
            }
            pAdapter->SharedKey[BSS0][KeyId].KeyLen = KeyLen / 2 ;
            AtoH(Key, pAdapter->SharedKey[BSS0][KeyId].Key, KeyLen / 2);
            CipherAlg = CIPHER_WEP64;
            break;

        case 13: /* wep 104 Ascii type */
            pAdapter->SharedKey[BSS0][KeyId].KeyLen = KeyLen;
            memcpy(pAdapter->SharedKey[BSS0][KeyId].Key, Key, KeyLen);
            CipherAlg = CIPHER_WEP128;
            break;

        case 26: /* wep 104 Hex type */
            for(i=0; i < KeyLen; i++)
            {
                if( !isxdigit(*(Key+i)) )
                    return false;  /*Not Hex value; */
            }
            pAdapter->SharedKey[BSS0][KeyId].KeyLen = KeyLen / 2 ;
            AtoH(Key, pAdapter->SharedKey[BSS0][KeyId].Key, KeyLen / 2);
            CipherAlg = CIPHER_WEP128;
            break;

        default: /* Invalid argument */
            DBGPRINT(RT_DEBUG_ERROR, ("Set_Wep_Key_Proc::Invalid argument (=%s)\n", Key));
            return false;
    }

    pAdapter->SharedKey[BSS0][KeyId].CipherAlg = CipherAlg;

    /* Set keys (into ASIC) */
    if (wdev->AuthMode >= Ndis802_11AuthModeWPA)
        ;   /* not support */
    else    /* Old WEP stuff */
    {
        AsicAddSharedKeyEntry(pAdapter,
                              0,
                              0,
                              &pAdapter->SharedKey[BSS0][KeyId]);
    }

    return true;
}



/*
    ==========================================================================
    Description:
        Set WEP KEY1
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_Key1_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg)
{
    int                                 KeyLen;
    int                                 i;
    u8                               CipherAlg=CIPHER_WEP64;

    if (pAdapter->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
        return true;    /* do nothing */

    KeyLen = strlen(arg);

    switch (KeyLen)
    {
        case 5: /*wep 40 Ascii type */
            pAdapter->SharedKey[BSS0][0].KeyLen = KeyLen;
            memcpy(pAdapter->SharedKey[BSS0][0].Key, arg, KeyLen);
            CipherAlg = CIPHER_WEP64;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key1_Proc::(Key1=%s and type=%s)\n", arg, "Ascii"));
            break;
        case 10: /*wep 40 Hex type */
            for(i=0; i < KeyLen; i++)
            {
                if( !isxdigit(*(arg+i)) )
                    return false;  /*Not Hex value; */
            }
            pAdapter->SharedKey[BSS0][0].KeyLen = KeyLen / 2 ;
            AtoH(arg, pAdapter->SharedKey[BSS0][0].Key, KeyLen / 2);
            CipherAlg = CIPHER_WEP64;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key1_Proc::(Key1=%s and type=%s)\n", arg, "Hex"));
            break;
        case 13: /*wep 104 Ascii type */
            pAdapter->SharedKey[BSS0][0].KeyLen = KeyLen;
            memcpy(pAdapter->SharedKey[BSS0][0].Key, arg, KeyLen);
            CipherAlg = CIPHER_WEP128;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key1_Proc::(Key1=%s and type=%s)\n", arg, "Ascii"));
            break;
        case 26: /*wep 104 Hex type */
            for(i=0; i < KeyLen; i++)
            {
                if( !isxdigit(*(arg+i)) )
                    return false;  /*Not Hex value; */
            }
            pAdapter->SharedKey[BSS0][0].KeyLen = KeyLen / 2 ;
            AtoH(arg, pAdapter->SharedKey[BSS0][0].Key, KeyLen / 2);
            CipherAlg = CIPHER_WEP128;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key1_Proc::(Key1=%s and type=%s)\n", arg, "Hex"));
            break;
        default: /*Invalid argument */
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key1_Proc::Invalid argument (=%s)\n", arg));
            return false;
    }

    pAdapter->SharedKey[BSS0][0].CipherAlg = CipherAlg;

    /* Set keys (into ASIC) */
    if (pAdapter->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
        ;   /* not support */
    else    /* Old WEP stuff */
    {
        AsicAddSharedKeyEntry(pAdapter,
                              0,
                              0,
                              &pAdapter->SharedKey[BSS0][0]);
    }

    return true;
}
/*
    ==========================================================================

    Description:
        Set WEP KEY2
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_Key2_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg)
{
    int                                 KeyLen;
    int                                 i;
    u8                               CipherAlg=CIPHER_WEP64;

    if (pAdapter->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
        return true;    /* do nothing */

    KeyLen = strlen(arg);

    switch (KeyLen)
    {
        case 5: /*wep 40 Ascii type */
            pAdapter->SharedKey[BSS0][1].KeyLen = KeyLen;
            memcpy(pAdapter->SharedKey[BSS0][1].Key, arg, KeyLen);
            CipherAlg = CIPHER_WEP64;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key2_Proc::(Key2=%s and type=%s)\n", arg, "Ascii"));
            break;
        case 10: /*wep 40 Hex type */
            for(i=0; i < KeyLen; i++)
            {
                if( !isxdigit(*(arg+i)) )
                    return false;  /*Not Hex value; */
            }
            pAdapter->SharedKey[BSS0][1].KeyLen = KeyLen / 2 ;
            AtoH(arg, pAdapter->SharedKey[BSS0][1].Key, KeyLen / 2);
            CipherAlg = CIPHER_WEP64;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key2_Proc::(Key2=%s and type=%s)\n", arg, "Hex"));
            break;
        case 13: /*wep 104 Ascii type */
            pAdapter->SharedKey[BSS0][1].KeyLen = KeyLen;
            memcpy(pAdapter->SharedKey[BSS0][1].Key, arg, KeyLen);
            CipherAlg = CIPHER_WEP128;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key2_Proc::(Key2=%s and type=%s)\n", arg, "Ascii"));
            break;
        case 26: /*wep 104 Hex type */
            for(i=0; i < KeyLen; i++)
            {
                if( !isxdigit(*(arg+i)) )
                    return false;  /*Not Hex value; */
            }
            pAdapter->SharedKey[BSS0][1].KeyLen = KeyLen / 2 ;
            AtoH(arg, pAdapter->SharedKey[BSS0][1].Key, KeyLen / 2);
            CipherAlg = CIPHER_WEP128;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key2_Proc::(Key2=%s and type=%s)\n", arg, "Hex"));
            break;
        default: /*Invalid argument */
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key2_Proc::Invalid argument (=%s)\n", arg));
            return false;
    }
    pAdapter->SharedKey[BSS0][1].CipherAlg = CipherAlg;

    /* Set keys (into ASIC) */
    if (pAdapter->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
        ;   /* not support */
    else    /* Old WEP stuff */
    {
        AsicAddSharedKeyEntry(pAdapter,
                              0,
                              1,
                              &pAdapter->SharedKey[BSS0][1]);
    }

    return true;
}
/*
    ==========================================================================
    Description:
        Set WEP KEY3
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_Key3_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg)
{
    int                                 KeyLen;
    int                                 i;
    u8                               CipherAlg=CIPHER_WEP64;

    if (pAdapter->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
        return true;    /* do nothing */

    KeyLen = strlen(arg);

    switch (KeyLen)
    {
        case 5: /*wep 40 Ascii type */
            pAdapter->SharedKey[BSS0][2].KeyLen = KeyLen;
            memcpy(pAdapter->SharedKey[BSS0][2].Key, arg, KeyLen);
            CipherAlg = CIPHER_WEP64;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key3_Proc::(Key3=%s and type=Ascii)\n", arg));
            break;
        case 10: /*wep 40 Hex type */
            for(i=0; i < KeyLen; i++)
            {
                if( !isxdigit(*(arg+i)) )
                    return false;  /*Not Hex value; */
            }
            pAdapter->SharedKey[BSS0][2].KeyLen = KeyLen / 2 ;
            AtoH(arg, pAdapter->SharedKey[BSS0][2].Key, KeyLen / 2);
            CipherAlg = CIPHER_WEP64;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key3_Proc::(Key3=%s and type=Hex)\n", arg));
            break;
        case 13: /*wep 104 Ascii type */
            pAdapter->SharedKey[BSS0][2].KeyLen = KeyLen;
            memcpy(pAdapter->SharedKey[BSS0][2].Key, arg, KeyLen);
            CipherAlg = CIPHER_WEP128;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key3_Proc::(Key3=%s and type=Ascii)\n", arg));
            break;
        case 26: /*wep 104 Hex type */
            for(i=0; i < KeyLen; i++)
            {
                if( !isxdigit(*(arg+i)) )
                    return false;  /*Not Hex value; */
            }
            pAdapter->SharedKey[BSS0][2].KeyLen = KeyLen / 2 ;
            AtoH(arg, pAdapter->SharedKey[BSS0][2].Key, KeyLen / 2);
            CipherAlg = CIPHER_WEP128;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key3_Proc::(Key3=%s and type=Hex)\n", arg));
            break;
        default: /*Invalid argument */
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key3_Proc::Invalid argument (=%s)\n", arg));
            return false;
    }
    pAdapter->SharedKey[BSS0][2].CipherAlg = CipherAlg;

    /* Set keys (into ASIC) */
    if (pAdapter->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
        ;   /* not support */
    else    /* Old WEP stuff */
    {
        AsicAddSharedKeyEntry(pAdapter,
                              0,
                              2,
                              &pAdapter->SharedKey[BSS0][2]);
    }

    return true;
}
/*
    ==========================================================================
    Description:
        Set WEP KEY4
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_Key4_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg)
{
    int                                 KeyLen;
    int                                 i;
    u8                               CipherAlg=CIPHER_WEP64;

    if (pAdapter->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
        return true;    /* do nothing */

    KeyLen = strlen(arg);

    switch (KeyLen)
    {
        case 5: /*wep 40 Ascii type */
            pAdapter->SharedKey[BSS0][3].KeyLen = KeyLen;
            memcpy(pAdapter->SharedKey[BSS0][3].Key, arg, KeyLen);
            CipherAlg = CIPHER_WEP64;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key4_Proc::(Key4=%s and type=%s)\n", arg, "Ascii"));
            break;
        case 10: /*wep 40 Hex type */
            for(i=0; i < KeyLen; i++)
            {
                if( !isxdigit(*(arg+i)) )
                    return false;  /*Not Hex value; */
            }
            pAdapter->SharedKey[BSS0][3].KeyLen = KeyLen / 2 ;
            AtoH(arg, pAdapter->SharedKey[BSS0][3].Key, KeyLen / 2);
            CipherAlg = CIPHER_WEP64;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key4_Proc::(Key4=%s and type=%s)\n", arg, "Hex"));
            break;
        case 13: /*wep 104 Ascii type */
            pAdapter->SharedKey[BSS0][3].KeyLen = KeyLen;
            memcpy(pAdapter->SharedKey[BSS0][3].Key, arg, KeyLen);
            CipherAlg = CIPHER_WEP128;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key4_Proc::(Key4=%s and type=%s)\n", arg, "Ascii"));
            break;
        case 26: /*wep 104 Hex type */
            for(i=0; i < KeyLen; i++)
            {
                if( !isxdigit(*(arg+i)) )
                    return false;  /*Not Hex value; */
            }
            pAdapter->SharedKey[BSS0][3].KeyLen = KeyLen / 2 ;
            AtoH(arg, pAdapter->SharedKey[BSS0][3].Key, KeyLen / 2);
            CipherAlg = CIPHER_WEP128;
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key4_Proc::(Key4=%s and type=%s)\n", arg, "Hex"));
            break;
        default: /*Invalid argument */
            DBGPRINT(RT_DEBUG_TRACE, ("Set_Key4_Proc::Invalid argument (=%s)\n", arg));
            return false;
    }
    pAdapter->SharedKey[BSS0][3].CipherAlg = CipherAlg;

    /* Set keys (into ASIC) */
    if (pAdapter->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
        ;   /* not support */
    else    /* Old WEP stuff */
    {
        AsicAddSharedKeyEntry(pAdapter,
                              0,
                              3,
                              &pAdapter->SharedKey[BSS0][3]);
    }

    return true;
}

/*
    ==========================================================================
    Description:
        Set WPA PSK key
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_WPAPSK_Proc(
    struct rtmp_adapter *  pAd,
    char *         arg)
{
    int status;

    if ((pAd->StaCfg.AuthMode != Ndis802_11AuthModeWPAPSK) &&
        (pAd->StaCfg.AuthMode != Ndis802_11AuthModeWPA2PSK) &&
	    (pAd->StaCfg.AuthMode != Ndis802_11AuthModeWPANone)
		)
        return true;    /* do nothing */

    DBGPRINT(RT_DEBUG_TRACE, ("Set_WPAPSK_Proc::(WPAPSK=%s)\n", arg));

	status = RT_CfgSetWPAPSKKey(pAd, arg, strlen(arg), pAd->MlmeAux.Ssid, pAd->MlmeAux.SsidLen, pAd->StaCfg.PMK);
	if (status == false)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("Set_WPAPSK_Proc(): Set key failed!\n"));
		return false;
	}
	memset(pAd->StaCfg.WpaPassPhrase, 0, 64);
    memmove(pAd->StaCfg.WpaPassPhrase, arg, strlen(arg));
    pAd->StaCfg.WpaPassPhraseLen = (unsigned int)strlen(arg);



    if(pAd->StaCfg.BssType == BSS_ADHOC &&
       pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPANone)
    {
        pAd->StaCfg.WpaState = SS_NOTUSE;
    }
    else
    {
        /* Start STA supplicant state machine */
        pAd->StaCfg.WpaState = SS_START;
    }

    return true;
}

/*
    ==========================================================================
    Description:
        Set Power Saving mode
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_PSMode_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg)
{
    if (pAdapter->StaCfg.BssType == BSS_INFRA)
    {
        if ((strcmp(arg, "Max_PSP") == 0) ||
			(strcmp(arg, "max_psp") == 0) ||
			(strcmp(arg, "MAX_PSP") == 0))
        {
            /* do NOT turn on PSM bit here, wait until MlmeCheckPsmChange() */
            /* to exclude certain situations. */
            if (pAdapter->StaCfg.bWindowsACCAMEnable == false)
                pAdapter->StaCfg.WindowsPowerMode = Ndis802_11PowerModeMAX_PSP;
            pAdapter->StaCfg.WindowsBatteryPowerMode = Ndis802_11PowerModeMAX_PSP;
            OPSTATUS_SET_FLAG(pAdapter, fOP_STATUS_RECEIVE_DTIM);
            pAdapter->StaCfg.DefaultListenCount = 5;

        }
        else if ((strcmp(arg, "Fast_PSP") == 0) ||
				 (strcmp(arg, "fast_psp") == 0) ||
                 (strcmp(arg, "FAST_PSP") == 0))
        {
            /* do NOT turn on PSM bit here, wait until MlmeCheckPsmChange() */
            /* to exclude certain situations. */
            OPSTATUS_SET_FLAG(pAdapter, fOP_STATUS_RECEIVE_DTIM);
            if (pAdapter->StaCfg.bWindowsACCAMEnable == false)
                pAdapter->StaCfg.WindowsPowerMode = Ndis802_11PowerModeFast_PSP;
            pAdapter->StaCfg.WindowsBatteryPowerMode = Ndis802_11PowerModeFast_PSP;
            pAdapter->StaCfg.DefaultListenCount = 3;
        }
        else if ((strcmp(arg, "Legacy_PSP") == 0) ||
                 (strcmp(arg, "legacy_psp") == 0) ||
                 (strcmp(arg, "LEGACY_PSP") == 0))
        {
            /* do NOT turn on PSM bit here, wait until MlmeCheckPsmChange() */
            /* to exclude certain situations. */
            OPSTATUS_SET_FLAG(pAdapter, fOP_STATUS_RECEIVE_DTIM);
            if (pAdapter->StaCfg.bWindowsACCAMEnable == false)
                pAdapter->StaCfg.WindowsPowerMode = Ndis802_11PowerModeLegacy_PSP;
            pAdapter->StaCfg.WindowsBatteryPowerMode = Ndis802_11PowerModeLegacy_PSP;
            pAdapter->StaCfg.DefaultListenCount = 3;
        }
        else
        {
            /*Default Ndis802_11PowerModeCAM */
            /* clear PSM bit immediately */
            RTMP_SET_PSM_BIT(pAdapter, PWR_ACTIVE);
            OPSTATUS_SET_FLAG(pAdapter, fOP_STATUS_RECEIVE_DTIM);
            if (pAdapter->StaCfg.bWindowsACCAMEnable == false)
                pAdapter->StaCfg.WindowsPowerMode = Ndis802_11PowerModeCAM;
            pAdapter->StaCfg.WindowsBatteryPowerMode = Ndis802_11PowerModeCAM;

        }

        DBGPRINT(RT_DEBUG_TRACE, ("Set_PSMode_Proc::(PSMode=%ld)\n", pAdapter->StaCfg.WindowsPowerMode));
    }
    else
        return false;


    return true;
}

#ifdef WPA_SUPPLICANT_SUPPORT
/*
    ==========================================================================
    Description:
        Set WpaSupport flag.
    Value:
        0: Driver ignore wpa_supplicant.
        1: wpa_supplicant initiates scanning and AP selection.
        2: driver takes care of scanning, AP selection, and IEEE 802.11 association parameters.
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT Set_Wpa_Support(
    struct rtmp_adapter *pAd,
	char *		arg)
{

    if ( simple_strtol(arg, 0, 10) == 0)
        pAd->StaCfg.WpaSupplicantUP = WPA_SUPPLICANT_DISABLE;
    else if ( simple_strtol(arg, 0, 10) == 1)
        pAd->StaCfg.WpaSupplicantUP = WPA_SUPPLICANT_ENABLE;
    else if ( simple_strtol(arg, 0, 10) == 2)
        pAd->StaCfg.WpaSupplicantUP = WPA_SUPPLICANT_ENABLE_WITH_WEB_UI;
    else
        pAd->StaCfg.WpaSupplicantUP = WPA_SUPPLICANT_DISABLE;

    DBGPRINT(RT_DEBUG_TRACE, ("Set_Wpa_Support::(WpaSupplicantUP=%d)\n", pAd->StaCfg.WpaSupplicantUP));

    return true;
}
#endif /* WPA_SUPPLICANT_SUPPORT */



INT Set_TGnWifiTest_Proc(
    struct rtmp_adapter *  pAd,
    char *         arg)
{
    if (simple_strtol(arg, 0, 10) == 0)
        pAd->StaCfg.bTGnWifiTest = false;
    else
        pAd->StaCfg.bTGnWifiTest = true;

    DBGPRINT(RT_DEBUG_TRACE, ("IF Set_TGnWifiTest_Proc::(bTGnWifiTest=%d)\n", pAd->StaCfg.bTGnWifiTest));
	return true;
}

#ifdef EXT_BUILD_CHANNEL_LIST
INT Set_Ieee80211dClientMode_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg)
{
    if (simple_strtol(arg, 0, 10) == 0)
        pAdapter->StaCfg.IEEE80211dClientMode = Rt802_11_D_None;
    else if (simple_strtol(arg, 0, 10) == 1)
        pAdapter->StaCfg.IEEE80211dClientMode = Rt802_11_D_Flexible;
    else if (simple_strtol(arg, 0, 10) == 2)
        pAdapter->StaCfg.IEEE80211dClientMode = Rt802_11_D_Strict;
    else
        return false;

    DBGPRINT(RT_DEBUG_TRACE, ("Set_Ieee802dMode_Proc::(IEEEE0211dMode=%d)\n", pAdapter->StaCfg.IEEE80211dClientMode));
    return true;
}
#endif /* EXT_BUILD_CHANNEL_LIST */

INT	Show_Adhoc_MacTable_Proc(
	struct rtmp_adapter *pAd,
	char *		extra,
	u32			size)
{
	INT i;

	sprintf(extra, "\n");

#ifdef DOT11_N_SUPPORT
	sprintf(extra, "%sHT Operating Mode : %d\n", extra, pAd->CommonCfg.AddHTInfo.AddHtInfo2.OperaionMode);
#endif /* DOT11_N_SUPPORT */

	sprintf(extra + strlen(extra), "\n%-19s%-4s%-4s%-7s%-7s%-7s%-10s%-6s%-6s%-6s%-6s\n",
			"MAC", "AID", "BSS", "RSSI0", "RSSI1", "RSSI2", "PhMd", "BW", "MCS", "SGI", "STBC");

	for (i=1; i<MAX_LEN_OF_MAC_TABLE; i++)
	{
		PMAC_TABLE_ENTRY pEntry = &pAd->MacTab.Content[i];

		if (strlen(extra) > (size - 30))
		    break;
		if ((IS_ENTRY_CLIENT(pEntry) || IS_ENTRY_APCLI(pEntry)) && (pEntry->Sst == SST_ASSOC))
		{
			sprintf(extra + strlen(extra), "%02X:%02X:%02X:%02X:%02X:%02X  ",
				pEntry->Addr[0], pEntry->Addr[1], pEntry->Addr[2],
				pEntry->Addr[3], pEntry->Addr[4], pEntry->Addr[5]);
			sprintf(extra + strlen(extra), "%-4d", (int)pEntry->Aid);
			sprintf(extra + strlen(extra), "%-4d", (int)pEntry->apidx);
			sprintf(extra + strlen(extra), "%-7d", pEntry->RssiSample.AvgRssi0);
			sprintf(extra + strlen(extra), "%-7d", pEntry->RssiSample.AvgRssi1);
			sprintf(extra + strlen(extra), "%-7d", pEntry->RssiSample.AvgRssi2);
			sprintf(extra + strlen(extra), "%-10s", get_phymode_str(pEntry->HTPhyMode.field.MODE));
			sprintf(extra + strlen(extra), "%-6s", get_bw_str(pEntry->HTPhyMode.field.BW));
			sprintf(extra + strlen(extra), "%-6d", pEntry->HTPhyMode.field.MCS);
			sprintf(extra + strlen(extra), "%-6d", pEntry->HTPhyMode.field.ShortGI);
			sprintf(extra + strlen(extra), "%-6d", pEntry->HTPhyMode.field.STBC);
			sprintf(extra + strlen(extra), "%-10d, %d, %d%%\n", pEntry->DebugFIFOCount, pEntry->DebugTxCount,
						(pEntry->DebugTxCount) ? ((pEntry->DebugTxCount-pEntry->DebugFIFOCount)*100/pEntry->DebugTxCount) : 0);
			sprintf(extra + strlen(extra), "\n");
		}
	}

	return true;
}


INT Set_BeaconLostTime_Proc(
    struct rtmp_adapter *  pAd,
    char *        arg)
{
	unsigned long ltmp = (unsigned long)simple_strtol(arg, 0, 10);

	if ((ltmp != 0) && (ltmp <= 60))
		pAd->StaCfg.BeaconLostTime = (ltmp * OS_HZ);

    DBGPRINT(RT_DEBUG_TRACE, ("IF Set_BeaconLostTime_Proc::(BeaconLostTime=%ld)\n", pAd->StaCfg.BeaconLostTime));
	return true;
}

INT Set_AutoRoaming_Proc(
    struct rtmp_adapter *  pAd,
    char *        arg)
{
    if (simple_strtol(arg, 0, 10) == 0)
        pAd->StaCfg.bAutoRoaming = false;
    else
        pAd->StaCfg.bAutoRoaming = true;

    DBGPRINT(RT_DEBUG_TRACE, ("IF Set_AutoRoaming_Proc::(bAutoRoaming=%d)\n", pAd->StaCfg.bAutoRoaming));
	return true;
}


/*
    ==========================================================================
    Description:
        Issue a site survey command to driver
	Arguments:
	    pAdapter                    Pointer to our adapter
	    wrq                         Pointer to the ioctl argument

    Return Value:
        None

    Note:
        Usage:
               1.) iwpriv ra0 set site_survey
    ==========================================================================
*/

INT Set_ForceTxBurst_Proc(
    struct rtmp_adapter *  pAd,
    char *        arg)
{
    if (simple_strtol(arg, 0, 10) == 0)
        pAd->StaCfg.bForceTxBurst = false;
    else
        pAd->StaCfg.bForceTxBurst = true;

    DBGPRINT(RT_DEBUG_TRACE, ("IF Set_ForceTxBurst_Proc::(bForceTxBurst=%d)\n", pAd->StaCfg.bForceTxBurst));
	return true;
}

void RTMPAddKey(
	struct rtmp_adapter *    pAd,
	PNDIS_802_11_KEY    pKey)
{
	unsigned long				KeyIdx;
	MAC_TABLE_ENTRY  	*pEntry;

    DBGPRINT(RT_DEBUG_TRACE, ("RTMPAddKey ------>\n"));

	if (pAd->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
	{
		if (pKey->KeyIndex & 0x80000000)
		{
		    if (pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPANone)
            {
                memset(pAd->StaCfg.PMK, 0, 32);
                memmove(pAd->StaCfg.PMK, pKey->KeyMaterial, pKey->KeyLength);
                goto end;
            }
		    /* Update PTK */
		    memset(&pAd->SharedKey[BSS0][0], 0, sizeof(CIPHER_KEY));
            pAd->SharedKey[BSS0][0].KeyLen = LEN_TK;
            memmove(pAd->SharedKey[BSS0][0].Key, pKey->KeyMaterial, LEN_TK);
#ifdef WPA_SUPPLICANT_SUPPORT
            if (pAd->StaCfg.PairCipher == Ndis802_11Encryption2Enabled)
            {
                memmove(pAd->SharedKey[BSS0][0].RxMic, pKey->KeyMaterial + LEN_TK, LEN_TKIP_MIC);
                memmove(pAd->SharedKey[BSS0][0].TxMic, pKey->KeyMaterial + LEN_TK + LEN_TKIP_MIC, LEN_TKIP_MIC);
            }
            else
#endif /* WPA_SUPPLICANT_SUPPORT */
            {
            	memmove(pAd->SharedKey[BSS0][0].TxMic, pKey->KeyMaterial + LEN_TK, LEN_TKIP_MIC);
                memmove(pAd->SharedKey[BSS0][0].RxMic, pKey->KeyMaterial + LEN_TK + LEN_TKIP_MIC, LEN_TKIP_MIC);
            }

            /* Decide its ChiperAlg */
        	if (pAd->StaCfg.PairCipher == Ndis802_11Encryption2Enabled)
        		pAd->SharedKey[BSS0][0].CipherAlg = CIPHER_TKIP;
        	else if (pAd->StaCfg.PairCipher == Ndis802_11Encryption3Enabled)
        		pAd->SharedKey[BSS0][0].CipherAlg = CIPHER_AES;
        	else
        		pAd->SharedKey[BSS0][0].CipherAlg = CIPHER_NONE;

            /* Update these related information to MAC_TABLE_ENTRY */
        	pEntry = &pAd->MacTab.Content[BSSID_WCID];
        	pEntry->PairwiseKey.KeyLen = LEN_TK;
        	memmove(pEntry->PairwiseKey.Key, pAd->SharedKey[BSS0][0].Key, LEN_TK);
        	memmove(pEntry->PairwiseKey.RxMic, pAd->SharedKey[BSS0][0].RxMic, LEN_TKIP_MIC);
        	memmove(pEntry->PairwiseKey.TxMic, pAd->SharedKey[BSS0][0].TxMic, LEN_TKIP_MIC);
        	pEntry->PairwiseKey.CipherAlg = pAd->SharedKey[BSS0][0].CipherAlg;

        	/* Update pairwise key information to ASIC Shared Key Table */
        	AsicAddSharedKeyEntry(pAd,
        						  BSS0,
        						  0,
        						  &pAd->SharedKey[BSS0][0]);

        	/* Update ASIC WCID attribute table and IVEIV table */
        	RTMPSetWcidSecurityInfo(pAd,
        							  BSS0,
        							  0,
        							  pAd->SharedKey[BSS0][0].CipherAlg,
        							  BSSID_WCID,
        							  SHAREDKEYTABLE);

            if (pAd->StaCfg.AuthMode >= Ndis802_11AuthModeWPA2)
            {
                /* set 802.1x port control */
				STA_PORT_SECURED(pAd);
            }
		}
        else
        {
            /* Update GTK */
            pAd->StaCfg.DefaultKeyId = (pKey->KeyIndex & 0xFF);
            memset(&pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId], 0, sizeof(CIPHER_KEY));
            pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].KeyLen = LEN_TK;
            memmove(pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].Key, pKey->KeyMaterial, LEN_TK);
#ifdef WPA_SUPPLICANT_SUPPORT
            if (pAd->StaCfg.GroupCipher == Ndis802_11Encryption2Enabled)
            {
                memmove(pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].RxMic, pKey->KeyMaterial + LEN_TK, LEN_TKIP_MIC);
                memmove(pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].TxMic, pKey->KeyMaterial + LEN_TK + LEN_TKIP_MIC, LEN_TKIP_MIC);
            }
            else
#endif /* WPA_SUPPLICANT_SUPPORT */
            {
            	memmove(pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].TxMic, pKey->KeyMaterial + LEN_TK, LEN_TKIP_MIC);
                memmove(pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].RxMic, pKey->KeyMaterial + LEN_TK + LEN_TKIP_MIC, LEN_TKIP_MIC);
            }

            /* Update Shared Key CipherAlg */
    		pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].CipherAlg = CIPHER_NONE;
    		if (pAd->StaCfg.GroupCipher == Ndis802_11Encryption2Enabled)
    			pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].CipherAlg = CIPHER_TKIP;
    		else if (pAd->StaCfg.GroupCipher == Ndis802_11Encryption3Enabled)
    			pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].CipherAlg = CIPHER_AES;

            /* Update group key information to ASIC Shared Key Table */
        	AsicAddSharedKeyEntry(pAd,
        						  BSS0,
        						  pAd->StaCfg.DefaultKeyId,
        						  &pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId]);


            /* set 802.1x port control */
			STA_PORT_SECURED(pAd);
        }
	}
	else	/* dynamic WEP from wpa_supplicant */
	{
		u8 CipherAlg;
    	u8 *Key;

		if(pKey->KeyLength == 32)
			goto end;

		KeyIdx = pKey->KeyIndex & 0x0fffffff;

		if (KeyIdx < 4)
		{
			/* it is a default shared key, for Pairwise key setting */
			if (pKey->KeyIndex & 0x80000000)
			{
				pEntry = MacTableLookup(pAd, pKey->BSSID);

				if (pEntry)
				{
					DBGPRINT(RT_DEBUG_TRACE, ("RTMPAddKey: Set Pair-wise Key\n"));

					/* set key material and key length */
 					pEntry->PairwiseKey.KeyLen = (u8)pKey->KeyLength;
					memmove(pEntry->PairwiseKey.Key, &pKey->KeyMaterial, pKey->KeyLength);

					/* set Cipher type */
					if (pKey->KeyLength == 5)
						pEntry->PairwiseKey.CipherAlg = CIPHER_WEP64;
					else
						pEntry->PairwiseKey.CipherAlg = CIPHER_WEP128;

					/* Add Pair-wise key to Asic */
					AsicAddPairwiseKeyEntry(
						pAd,
						(u8)pEntry->Aid,
                		&pEntry->PairwiseKey);

					/* update WCID attribute table and IVEIV table for this entry */
					RTMPSetWcidSecurityInfo(pAd,
											BSS0,
											KeyIdx,
											pEntry->PairwiseKey.CipherAlg,
											pEntry->Aid,
											PAIRWISEKEYTABLE);
				}
			}
			else
            {
				/* Default key for tx (shared key) */
				pAd->StaCfg.DefaultKeyId = (u8) KeyIdx;

				/* set key material and key length */
				pAd->SharedKey[BSS0][KeyIdx].KeyLen = (u8) pKey->KeyLength;
				memmove(pAd->SharedKey[BSS0][KeyIdx].Key, &pKey->KeyMaterial, pKey->KeyLength);

				/* Set Ciper type */
				if (pKey->KeyLength == 5)
					pAd->SharedKey[BSS0][KeyIdx].CipherAlg = CIPHER_WEP64;
				else
					pAd->SharedKey[BSS0][KeyIdx].CipherAlg = CIPHER_WEP128;

    			CipherAlg = pAd->SharedKey[BSS0][KeyIdx].CipherAlg;
    			Key = pAd->SharedKey[BSS0][KeyIdx].Key;

				/* Set Group key material to Asic */
    			AsicAddSharedKeyEntry(pAd, BSS0, KeyIdx, &pAd->SharedKey[BSS0][KeyIdx]);

			}
		}
	}
end:
	return;
}



/*
    ==========================================================================
    Description:
        Site survey entry point

    NOTE:
    ==========================================================================
*/
void StaSiteSurvey(
	struct rtmp_adapter * 		pAd,
	PNDIS_802_11_SSID	pSsid,
	u8 			ScanType)
{
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS))
	{
		/*
		 * Still scanning, ignore this scanning.
		 */
		DBGPRINT(RT_DEBUG_TRACE, ("StaSiteSurvey:: Scanning now\n"));
		return;
	}
	if (INFRA_ON(pAd))
	{
		pAd->StaCfg.bImprovedScan = true;
		pAd->StaCfg.ScanChannelCnt = 0;	/* reset channel counter to 0 */
	}


	if (pAd->Mlme.CntlMachine.CurrState != CNTL_IDLE)
	{
		RTMP_MLME_RESET_STATE_MACHINE(pAd);
		DBGPRINT(RT_DEBUG_TRACE, ("!!! MLME busy, reset MLME state machine !!!\n"));
	}

	NdisGetSystemUpTime(&pAd->StaCfg.LastScanTime);


	if (pSsid)
		MlmeEnqueue(pAd,
			MLME_CNTL_STATE_MACHINE,
			OID_802_11_BSSID_LIST_SCAN,
			pSsid->SsidLength,
			pSsid->Ssid,
			0);
	else
		MlmeEnqueue(pAd,
			MLME_CNTL_STATE_MACHINE,
			OID_802_11_BSSID_LIST_SCAN,
			0,
			"",
			0);

	RTMP_MLME_HANDLER(pAd);
}

INT Set_AdhocN_Proc(
    struct rtmp_adapter *pAd,
    char *		arg)
{
#ifdef DOT11_N_SUPPORT
	if (simple_strtol(arg, 0, 10) == 0)
        pAd->StaCfg.bAdhocN = false;
	else
		pAd->StaCfg.bAdhocN = true;

	DBGPRINT(RT_DEBUG_TRACE, ("IF Set_AdhocN_Proc::(bAdhocN=%d)\n", pAd->StaCfg.bAdhocN));
#endif /* DOT11_N_SUPPORT */
	return true;
}

#ifdef DBG
/*
    ==========================================================================
    Description:
        Read / Write MAC
    Arguments:
        pAd                    Pointer to our adapter
        wrq                         Pointer to the ioctl argument

    Return Value:
        None

    Note:
        Usage:
               1.) iwpriv ra0 mac 0        ==> read MAC where Addr=0x0
               2.) iwpriv ra0 mac 0=12     ==> write MAC where Addr=0x0, value=12
    ==========================================================================
*/
void RTMPIoctlMAC(
	struct rtmp_adapter*pAd,
	RTMP_IOCTL_INPUT_STRUCT *wrq)
{
	char *this_char, *value;
	INT j = 0, k = 0;
	char *msg = NULL;
	char *arg = NULL;
	u32 macAddr = 0, macValue = 0;
	u8 temp[16];
	char temp2[16];
	INT Status;
	bool bIsPrintAllMAC = false;



	msg = kmalloc(sizeof(char)*1024, GFP_ATOMIC);
	if (!msg)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: Allocate memory fail!!!\n", __FUNCTION__));
		goto LabelOK;
	}
	memset(msg, 0x00, 1024);

	arg = kmalloc(sizeof(char)*255, GFP_ATOMIC);
	if (arg == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: Allocate memory fail!!!\n", __FUNCTION__));
		goto LabelOK;
	}
	memset(arg, 0x00, 255);

DBGPRINT(RT_DEBUG_OFF, ("%s():wrq->u.data.length=%d, wrq->u.data.pointer=%s!\n", __FUNCTION__, wrq->u.data.length, wrq->u.data.pointer));
	if (wrq->u.data.length > 1)
	{
		Status = copy_from_user(arg, wrq->u.data.pointer, (wrq->u.data.length > 255) ? 255 : wrq->u.data.length);
		arg[254] = 0x00;
		sprintf(msg, "\n");

		/*Parsing Read or Write */
		this_char = arg;
		if (!*this_char)
			goto next;

		if ((value = rtstrchr(this_char, '=')) != NULL)
			*value++ = 0;

		if (!value || !*value)
		{ /*Read */
			if(strlen(this_char) > 4)
				goto next;

			j = strlen(this_char);
			while(j-- > 0)
			{
				if(this_char[j] > 'f' || this_char[j] < '0')
					goto LabelOK;
			}

			/* Mac Addr */
			k = j = strlen(this_char);
			while(j-- > 0)
			{
				this_char[4-k+j] = this_char[j];
			}

			while(k < 4)
				this_char[3-k++]='0';
			this_char[4]='\0';

			if(strlen(this_char) == 4)
			{
				AtoH(this_char, temp, 2);
				macAddr = *temp*256 + temp[1];
				if (macAddr < 0xFFFF)
				{
					macValue = mt7610u_read32(pAd, macAddr);
					DBGPRINT(RT_DEBUG_TRACE, ("MacAddr=0x%04x, MacValue=%x\n", macAddr, macValue));
					sprintf(msg+strlen(msg), "[0x%04x]:%08x  ", macAddr , macValue);
				}
				else
				{/*Invalid parametes, so default printk all mac */
					bIsPrintAllMAC = true;
					goto next;
				}
			}
		}
		else
		{ /*Write */
			memcpy(&temp2, value, strlen(value));
			temp2[strlen(value)] = '\0';

			/* Sanity check */
			if((strlen(this_char) > 4) || strlen(temp2) > 8)
				goto next;

			j = strlen(this_char);
			while(j-- > 0)
			{
				if(this_char[j] > 'f' || this_char[j] < '0')
					goto LabelOK;
			}

			j = strlen(temp2);
			while(j-- > 0)
			{
				if(temp2[j] > 'f' || temp2[j] < '0')
					goto LabelOK;
			}

			/*MAC Addr */
			k = j = strlen(this_char);
			while(j-- > 0)
			{
				this_char[4-k+j] = this_char[j];
			}

			while(k < 4)
				this_char[3-k++]='0';
			this_char[4]='\0';

			/*MAC value */
			k = j = strlen(temp2);
			while(j-- > 0)
			{
				temp2[8-k+j] = temp2[j];
			}

			while(k < 8)
				temp2[7-k++]='0';
			temp2[8]='\0';

			AtoH(this_char, temp, 2);
			macAddr = *temp*256 + temp[1];

			AtoH(temp2, temp, 4);
			macValue = (temp[0] << 24) + (temp[1] << 16) + (temp[2] << 8) + temp[3];

			/* debug mode */
			if (macAddr == (HW_DEBUG_SETTING_BASE + 4))
			{
				/* 0x2bf4: byte0 non-zero: enable R17 tuning, 0: disable R17 tuning */
				if (macValue & 0x000000ff)
				{
					pAd->BbpTuning.bEnable = true;
					DBGPRINT(RT_DEBUG_TRACE,("turn on R17 tuning\n"));
				}
				else
				{
					pAd->BbpTuning.bEnable = false;
				}
				goto LabelOK;
			}

			DBGPRINT(RT_DEBUG_TRACE, ("MacAddr=0x%04x, MacValue=0x%x\n", macAddr, macValue));

			mt7610u_write32(pAd, macAddr, macValue);
			sprintf(msg+strlen(msg), "[0x%04x]:%08x  ", macAddr, macValue);
		}
	}
	else
		bIsPrintAllMAC = true;
next:
	if (bIsPrintAllMAC)
	{
		u32 *pBufMac = NULL, *pBuf;
		u32 AddrStart = 0x1000, AddrEnd = 0x1800;
		u32 IdAddr;

		ASSERT((AddrEnd >= AddrStart));
		/* *2 for safe */
		pBufMac = kmalloc((AddrEnd - AddrStart)*2, GFP_ATOMIC);
		if (pBufMac != NULL)
		{
			pBuf = pBufMac;
			for(IdAddr=AddrStart; IdAddr<=AddrEnd; IdAddr+=4, pBuf++)
				pBuf = mt7610u_read32(pAd, IdAddr);
			RtmpDrvAllMacPrint(pAd, pBufMac, AddrStart, AddrEnd, 4);
#ifdef RT65xx
			if (IS_RT65XX(pAd)) {
				pBuf = pBufMac;
				AddrStart = 0x0; AddrEnd = 0x800;
				for(IdAddr=AddrStart; IdAddr<=AddrEnd; IdAddr+=4, pBuf++)
					pBuf = mt7610u_read32(pAd, IdAddr);
				RtmpDrvAllMacPrint(pAd, pBufMac, AddrStart, AddrEnd, 4);
			}
#endif /* RT65xx */
			kfree(pBufMac);
		}
	}
	if(strlen(msg) == 1)
		sprintf(msg+strlen(msg), "===>Error command format!");

	/* Copy the information into the user buffer */
	wrq->u.data.length = strlen(msg);
	Status = copy_to_user(wrq->u.data.pointer, msg, wrq->u.data.length);

LabelOK:
	if (msg != NULL)
		kfree(msg);
	if (arg != NULL)
		kfree(arg);

	DBGPRINT(RT_DEBUG_TRACE, ("<==RTMPIoctlMAC\n\n"));
	return;
}

#endif /* DBG */

#ifdef DOT11_N_SUPPORT
void	getBaInfo(
	struct rtmp_adapter *pAd,
	char *		pOutBuf,
	u32			size)
{
	INT i, j;
	BA_ORI_ENTRY *pOriBAEntry;
	BA_REC_ENTRY *pRecBAEntry;

	for (i=0; i<MAX_LEN_OF_MAC_TABLE; i++)
	{
		PMAC_TABLE_ENTRY pEntry = &pAd->MacTab.Content[i];
		if (((IS_ENTRY_CLIENT(pEntry) || IS_ENTRY_APCLI(pEntry) || IS_ENTRY_TDLS(pEntry)) && (pEntry->Sst == SST_ASSOC))
			|| IS_ENTRY_WDS(pEntry) || IS_ENTRY_MESH(pEntry))
		{
			sprintf(pOutBuf, "%s\n%02X:%02X:%02X:%02X:%02X:%02X (Aid = %d) (AP) -\n",
                pOutBuf,
				pEntry->Addr[0], pEntry->Addr[1], pEntry->Addr[2],
				pEntry->Addr[3], pEntry->Addr[4], pEntry->Addr[5], pEntry->Aid);

			sprintf(pOutBuf, "%s[Recipient]\n", pOutBuf);
			for (j=0; j < NUM_OF_TID; j++)
			{
				if (pEntry->BARecWcidArray[j] != 0)
				{
					pRecBAEntry =&pAd->BATable.BARecEntry[pEntry->BARecWcidArray[j]];
					sprintf(pOutBuf, "%sTID=%d, BAWinSize=%d, LastIndSeq=%d, ReorderingPkts=%d\n", pOutBuf, j, pRecBAEntry->BAWinSize, pRecBAEntry->LastIndSeq, pRecBAEntry->list.qlen);
				}
			}
			sprintf(pOutBuf, "%s\n", pOutBuf);

			sprintf(pOutBuf, "%s[Originator]\n", pOutBuf);
			for (j=0; j < NUM_OF_TID; j++)
			{
				if (pEntry->BAOriWcidArray[j] != 0)
				{
					pOriBAEntry =&pAd->BATable.BAOriEntry[pEntry->BAOriWcidArray[j]];
					sprintf(pOutBuf, "%sTID=%d, BAWinSize=%d, StartSeq=%d, CurTxSeq=%d\n", pOutBuf, j, pOriBAEntry->BAWinSize, pOriBAEntry->Sequence, pEntry->TxSeq[j]);
				}
			}
			sprintf(pOutBuf, "%s\n\n", pOutBuf);
		}
        if (strlen(pOutBuf) > (size - 30))
                break;
	}

	return;
}
#endif /* DOT11_N_SUPPORT */

/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWFREQ.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwfreq(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_FREQ *pIoctlFreq = (RT_CMD_STA_IOCTL_FREQ *)pData;
	int 	chan = -1;
	unsigned long	freq;

	if ( pIoctlFreq->m > 100000000 )
		freq = pIoctlFreq->m / 100000;
	else if ( pIoctlFreq->m > 100000 )
		freq = pIoctlFreq->m / 100;
	else
		freq = pIoctlFreq->m;


	if((pIoctlFreq->e == 0) && (freq <= 1000))
		chan = pIoctlFreq->m;	/* Setting by channel number */
	else
	{
		MAP_KHZ_TO_CHANNEL_ID( freq , chan); /* Setting by frequency - search the table , like 2.412G, 2.422G, */
	}

    if (ChannelSanity(pAd, chan) == true)
    {
	pAd->CommonCfg.Channel = chan;
		/* Save the channel on MlmeAux for CntlOidRTBssidProc used. */
		pAd->MlmeAux.Channel = pAd->CommonCfg.Channel;
		/*save connect info*/
		pAd->StaCfg.ConnectinfoChannel = pAd->CommonCfg.Channel;
	DBGPRINT(RT_DEBUG_ERROR, ("==>rt_ioctl_siwfreq::SIOCSIWFREQ(Channel=%d)\n", pAd->CommonCfg.Channel));
    }
    else
        return NDIS_STATUS_FAILURE;

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWFREQ.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwfreq(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	u8 ch;
	unsigned long	m = 2412000;

		ch = pAd->CommonCfg.Channel;

	DBGPRINT(RT_DEBUG_TRACE,("==>rt_ioctl_giwfreq  %d\n", ch));

	MAP_CHANNEL_ID_TO_KHZ(ch, m);
	*(unsigned long *)pData = m;
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWMODE.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwmode(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	switch(Data)
	{
		case RTMP_CMD_STA_MODE_ADHOC:
			Set_NetworkType_Proc(pAd, "Adhoc");
			break;
		case RTMP_CMD_STA_MODE_INFRA:
			Set_NetworkType_Proc(pAd, "Infra");
			break;
		case RTMP_CMD_STA_MODE_MONITOR:
			Set_NetworkType_Proc(pAd, "Monitor");
			break;
	}

	/* Reset Ralink supplicant to not use, it will be set to start when UI set PMK key */
	pAd->StaCfg.WpaState = SS_NOTUSE;
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWMODE.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwmode(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	if (ADHOC_ON(pAd))
		*(unsigned long *)pData = RTMP_CMD_STA_MODE_ADHOC;
	else if (INFRA_ON(pAd))
		*(unsigned long *)pData = RTMP_CMD_STA_MODE_INFRA;
	else if (MONITOR_ON(pAd))
		*(unsigned long *)pData = RTMP_CMD_STA_MODE_MONITOR;
	else
		*(unsigned long *)pData = RTMP_CMD_STA_MODE_AUTO;
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWAP.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwap(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	u8 *pBssid = (u8 *)pData;


	if (pAd->Mlme.CntlMachine.CurrState != CNTL_IDLE)
	{
		RTMP_MLME_RESET_STATE_MACHINE(pAd);
		DBGPRINT(RT_DEBUG_TRACE, ("!!! MLME busy, reset MLME state machine !!!\n"));
	}

	/* tell CNTL state machine to call NdisMSetInformationComplete() after completing */
	/* this request, because this request is initiated by NDIS. */
	pAd->MlmeAux.CurrReqIsFromNdis = false;
	/* Prevent to connect AP again in STAMlmePeriodicExec */
	pAd->MlmeAux.AutoReconnectSsidLen= 32;

	if (MAC_ADDR_EQUAL(pBssid, ZERO_MAC_ADDR))
	{
		if (INFRA_ON(pAd))
		{
			LinkDown(pAd, false);
		}
	}
	else
	{
		MlmeEnqueue(pAd,
			MLME_CNTL_STATE_MACHINE,
			OID_802_11_BSSID,
			sizeof(NDIS_802_11_MAC_ADDRESS),
			(void *)pBssid, 0);
	}
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWAP.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwap(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	if (INFRA_ON(pAd) || ADHOC_ON(pAd))
		memmove(pData, pAd->CommonCfg.Bssid, ETH_ALEN);
#ifdef WPA_SUPPLICANT_SUPPORT
	/* Add for RT2870 */
	else if (pAd->StaCfg.WpaSupplicantUP != WPA_SUPPLICANT_DISABLE)
		memmove(pData, pAd->MlmeAux.Bssid, ETH_ALEN);
#endif /* WPA_SUPPLICANT_SUPPORT */
	else
		return NDIS_STATUS_FAILURE;
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWSCAN.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwscan(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	/*
		Can not use SIOCGIWSCAN definition, it is used in wireless.h
		We will not see the definition in MODULE.
		The definition can be saw in UTIL and NETIF.
	*/
/* #if defined(SIOCGIWSCAN) || defined(RT_CFG80211_SUPPORT) */
	RT_CMD_STA_IOCTL_SCAN *pConfig = (RT_CMD_STA_IOCTL_SCAN *)pData;
	int Status = NDIS_STATUS_SUCCESS;

	pConfig->Status = 0;

	if (MONITOR_ON(pAd))
    {
        DBGPRINT(RT_DEBUG_TRACE, ("!!! Driver is in Monitor Mode now !!!\n"));
		pConfig->Status = RTMP_IO_EINVAL;
		return NDIS_STATUS_FAILURE;
    }


#ifdef WPA_SUPPLICANT_SUPPORT
	if ((pAd->StaCfg.WpaSupplicantUP & 0x7F) == WPA_SUPPLICANT_ENABLE)
	{
		pAd->StaCfg.WpaSupplicantScanCount++;
	}
#endif /* WPA_SUPPLICANT_SUPPORT */

    pAd->StaCfg.bSkipAutoScanConn = true;
	do{

		if ((OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED)) &&
			((pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA) ||
				(pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPAPSK) ||
				(pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA2) ||
				(pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA2PSK)) &&
			(pAd->StaCfg.PortSecured == WPA_802_1X_PORT_NOT_SECURED))
		{
			DBGPRINT(RT_DEBUG_TRACE, ("!!! Link UP, Port Not Secured! ignore this set::OID_802_11_BSSID_LIST_SCAN\n"));
			Status = NDIS_STATUS_SUCCESS;
			break;
		}

#ifdef WPA_SUPPLICANT_SUPPORT
		if (pConfig->FlgScanThisSsid)
		{
				NDIS_802_11_SSID          Ssid;
				Ssid.SsidLength = pConfig->SsidLen;
				DBGPRINT(RT_DEBUG_TRACE, ("rt_ioctl_siwscan:: req.essid_len-%d, essid-%s\n", pConfig->SsidLen, pConfig->pSsid));
				memset(&Ssid.Ssid, 0, NDIS_802_11_LENGTH_SSID);
				memmove(Ssid.Ssid, pConfig->pSsid, Ssid.SsidLength);
				StaSiteSurvey(pAd, &Ssid, SCAN_ACTIVE);
		}
		else
#endif /* WPA_SUPPLICANT_SUPPORT */
		StaSiteSurvey(pAd, NULL, SCAN_ACTIVE);
	}while(0);

	pConfig->Status = Status;
/* #endif */ /* SIOCGIWSCAN || RT_CFG80211_SUPPORT */
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Set the signal quality.

Arguments:
	*pSignal		- signal structure
	pBssEntry		- the BSS information

Return Value:
	None

Note:
========================================================================
*/
static void set_quality(
	RT_CMD_STA_IOCTL_BSS	*pSignal,
	PBSS_ENTRY				pBssEntry)
{
	memcpy(pSignal->Bssid, pBssEntry->Bssid, ETH_ALEN);

	/* Normalize Rssi */
	if (pBssEntry->Rssi >= -50)
        pSignal->ChannelQuality = 100;
	else if (pBssEntry->Rssi >= -80) /* between -50 ~ -80dbm */
		pSignal->ChannelQuality = (__u8)(24 + ((pBssEntry->Rssi + 80) * 26)/10);
	else if (pBssEntry->Rssi >= -90)   /* between -80 ~ -90dbm */
        pSignal->ChannelQuality = (__u8)((pBssEntry->Rssi + 90) * 26)/10;
	else
		pSignal->ChannelQuality = 0;

    pSignal->Rssi = (__u8)(pBssEntry->Rssi);

    if (pBssEntry->Rssi >= -70)
		pSignal->Noise = -92;
	else
		pSignal->Noise = pBssEntry->Rssi - pBssEntry->MinSNR;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWSCAN.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwscan(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_SCAN_TABLE *pIoctlScan = (RT_CMD_STA_IOCTL_SCAN_TABLE *)pData;
	RT_CMD_STA_IOCTL_BSS_TABLE *pBssTable;
	PBSS_ENTRY pBssEntry;
	u32 IdBss;


	pIoctlScan->BssNr = 0;


#ifdef WPA_SUPPLICANT_SUPPORT
	if ((pAd->StaCfg.WpaSupplicantUP & 0x7F) == WPA_SUPPLICANT_ENABLE)
	{
		pAd->StaCfg.WpaSupplicantScanCount = 0;
	}
#endif /* WPA_SUPPLICANT_SUPPORT */

	pIoctlScan->BssNr = pAd->ScanTab.BssNr;
	if (pIoctlScan->BssNr == 0)
		return NDIS_STATUS_SUCCESS;

	pIoctlScan->pBssTable =
		kmalloc(pAd->ScanTab.BssNr * sizeof(RT_CMD_STA_IOCTL_BSS_TABLE), GFP_ATOMIC);
	if (pIoctlScan->pBssTable == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("Allocate memory fail!\n"));
		return NDIS_STATUS_FAILURE;
	}

	for(IdBss=0; IdBss<pAd->ScanTab.BssNr; IdBss++)
	{
		HT_CAP_INFO capInfo = pAd->ScanTab.BssEntry[IdBss].HtCapability.HtCapInfo;

		pBssTable = pIoctlScan->pBssTable + IdBss;
		pBssEntry = &pAd->ScanTab.BssEntry[IdBss];

		memcpy(pBssTable->Bssid, pBssEntry->Bssid, ETH_ALEN);
		pBssTable->Channel = pBssEntry->Channel;
		pBssTable->BssType = pBssEntry->BssType;
		pBssTable->HtCapabilityLen = pBssEntry->HtCapabilityLen;
		memcpy(pBssTable->SupRate, pBssEntry->SupRate, 12);
		pBssTable->SupRateLen = pBssEntry->SupRateLen;
		memcpy(pBssTable->ExtRate, pBssEntry->ExtRate, 12);
		pBssTable->ExtRateLen = pBssEntry->ExtRateLen;
		pBssTable->SsidLen = pBssEntry->SsidLen;
		memcpy(pBssTable->Ssid, pBssEntry->Ssid, 32);
		pBssTable->CapabilityInfo = pBssEntry->CapabilityInfo;
		pBssTable->ChannelWidth = capInfo.ChannelWidth;
		pBssTable->ShortGIfor40 = capInfo.ShortGIfor40;
		pBssTable->ShortGIfor20 = capInfo.ShortGIfor20;
		pBssTable->MCSSet = pBssEntry->HtCapability.MCSSet[1];
		pBssTable->WpaIeLen = pBssEntry->WpaIE.IELen;
		pBssTable->pWpaIe = pBssEntry->WpaIE.IE;
		pBssTable->RsnIeLen = pBssEntry->RsnIE.IELen;
		pBssTable->pRsnIe = pBssEntry->RsnIE.IE;
		pBssTable->WpsIeLen = pBssEntry->WpsIE.IELen;
		pBssTable->pWpsIe = pBssEntry->WpsIE.IE;
		pBssTable->FlgIsPrivacyOn = CAP_IS_PRIVACY_ON(pBssEntry->CapabilityInfo);
		set_quality(&pBssTable->Signal, pBssEntry);
	}

	memcpy(pIoctlScan->MainSharedKey[0], pAd->SharedKey[BSS0][0].Key, 16);
	memcpy(pIoctlScan->MainSharedKey[1], pAd->SharedKey[BSS0][1].Key, 16);
	memcpy(pIoctlScan->MainSharedKey[2], pAd->SharedKey[BSS0][2].Key, 16);
	memcpy(pIoctlScan->MainSharedKey[3], pAd->SharedKey[BSS0][3].Key, 16);

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWESSID.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwessid(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_SSID *pSsid = (RT_CMD_STA_IOCTL_SSID *)pData;

	if (pSsid->FlgAnySsid)
	{
		char *pSsidString = NULL;

		/* Includes null character. */
/*				pSsidString = kmalloc(MAX_LEN_OF_SSID+1, MEM_ALLOC_FLAG); */
		pSsidString = kmalloc(MAX_LEN_OF_SSID+1, GFP_ATOMIC);
		if (pSsidString)
		{
			memset(pSsidString, 0, MAX_LEN_OF_SSID+1);
			memmove(pSsidString, pSsid->pSsid, pSsid->SsidLen);
			if (Set_SSID_Proc(pAd, pSsidString) == false)
			{
				kfree(pSsidString);
				pSsid->Status = RTMP_IO_EINVAL;
				return NDIS_STATUS_SUCCESS;
			}
			kfree(pSsidString);
		}
		else
		{
			pSsid->Status = RTMP_IO_ENOMEM;
			return NDIS_STATUS_SUCCESS;
		}
	}
	else
	{
		/* ANY ssid */
		if (Set_SSID_Proc(pAd, "") == false)
		{
			pSsid->Status = RTMP_IO_EINVAL;
			return NDIS_STATUS_SUCCESS;
		}
	}
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWESSID.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwessid(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_SSID *pSsid = (RT_CMD_STA_IOCTL_SSID *)pData;

	if (MONITOR_ON(pAd))
	{
		pSsid->SsidLen = 0;
		return NDIS_STATUS_SUCCESS;
	}

	if (OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED))
	{
		DBGPRINT(RT_DEBUG_TRACE ,("MediaState is connected\n"));
		pSsid->SsidLen = pAd->CommonCfg.SsidLen;
		memcpy(pSsid->pSsid, pAd->CommonCfg.Ssid, pAd->CommonCfg.SsidLen);
	}
#ifdef RTMP_MAC_USB
#ifdef WPA_SUPPLICANT_SUPPORT
	/* Add for RT2870 */
	else if (pAd->StaCfg.WpaSupplicantUP != WPA_SUPPLICANT_DISABLE)
	{
		pSsid->SsidLen = pAd->CommonCfg.SsidLen;
		memcpy(pSsid->pSsid, pAd->CommonCfg.Ssid, pAd->CommonCfg.SsidLen);
	}
#endif /* WPA_SUPPLICANT_SUPPORT */
#endif /* RTMP_MAC_USB */
	else
	{/*the ANY ssid was specified */
		pSsid->SsidLen = 0;
		DBGPRINT(RT_DEBUG_TRACE ,("MediaState is not connected, ess\n"));
	}
	return NDIS_STATUS_SUCCESS;
}

/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWRTS.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwrts(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	pAd->CommonCfg.RtsThreshold = Data;
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWRTS.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwrts(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	*(unsigned short *)pData = pAd->CommonCfg.RtsThreshold;
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWFRAG.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwfrag(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	pAd->CommonCfg.FragmentThreshold = Data;
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWFRAG.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwfrag(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	*(unsigned short *)pData = pAd->CommonCfg.FragmentThreshold;
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWENCODE.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
#define NR_WEP_KEYS 				4
#define MAX_WEP_KEY_SIZE			13
#define MIN_WEP_KEY_SIZE			5
INT
RtmpIoctl_rt_ioctl_siwencode(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_SECURITY *pIoctlSec = (RT_CMD_STA_IOCTL_SECURITY *)pData;


	if ((pIoctlSec->length == 0) &&
        (pIoctlSec->flags & RT_CMD_STA_IOCTL_SECURITY_DISABLED))
	{
		pAd->StaCfg.PairCipher = Ndis802_11WEPDisabled;
		pAd->StaCfg.GroupCipher = Ndis802_11WEPDisabled;
		pAd->StaCfg.WepStatus = Ndis802_11WEPDisabled;
        pAd->StaCfg.AuthMode = Ndis802_11AuthModeOpen;
        goto done;
	}
	else if (pIoctlSec->flags & RT_CMD_STA_IOCTL_SECURITY_RESTRICTED ||
				pIoctlSec->flags & RT_CMD_STA_IOCTL_SECURITY_OPEN)
	{
		pAd->StaCfg.PortSecured = WPA_802_1X_PORT_SECURED;
		pAd->StaCfg.PairCipher = Ndis802_11WEPEnabled;
		pAd->StaCfg.GroupCipher = Ndis802_11WEPEnabled;
		pAd->StaCfg.WepStatus = Ndis802_11WEPEnabled;
		if (pIoctlSec->flags & RT_CMD_STA_IOCTL_SECURITY_RESTRICTED)
			pAd->StaCfg.AuthMode = Ndis802_11AuthModeShared;
    	else
			pAd->StaCfg.AuthMode = Ndis802_11AuthModeOpen;
	}

    if (pIoctlSec->length > 0)
	{
		int keyIdx = pIoctlSec->KeyIdx; /*(erq->flags & IW_ENCODE_INDEX) - 1; */
		/* Check the size of the key */
		if (pIoctlSec->length > MAX_WEP_KEY_SIZE)
		{
			pIoctlSec->Status = RTMP_IO_EINVAL;
			return NDIS_STATUS_SUCCESS;
		}
		/* Check key index */
		if ((keyIdx < 0) || (keyIdx >= NR_WEP_KEYS))
        {
            DBGPRINT(RT_DEBUG_TRACE ,("==>rt_ioctl_siwencode::Wrong keyIdx=%d! Using default key instead (%d)\n",
                                        keyIdx, pAd->StaCfg.DefaultKeyId));

            /*Using default key */
			keyIdx = pAd->StaCfg.DefaultKeyId;
        }
		else
			pAd->StaCfg.DefaultKeyId = keyIdx;

        memset(pAd->SharedKey[BSS0][keyIdx].Key,  0, 16);

		if (pIoctlSec->length == MAX_WEP_KEY_SIZE)
        {
			pAd->SharedKey[BSS0][keyIdx].KeyLen = MAX_WEP_KEY_SIZE;
            pAd->SharedKey[BSS0][keyIdx].CipherAlg = CIPHER_WEP128;
		}
		else if (pIoctlSec->length == MIN_WEP_KEY_SIZE)
        {
            pAd->SharedKey[BSS0][keyIdx].KeyLen = MIN_WEP_KEY_SIZE;
            pAd->SharedKey[BSS0][keyIdx].CipherAlg = CIPHER_WEP64;
		}
		else
			/* Disable the key */
			pAd->SharedKey[BSS0][keyIdx].KeyLen = 0;

		/* Check if the key is not marked as invalid */
		if(!(pIoctlSec->flags & RT_CMD_STA_IOCTL_SECURITY_NOKEY))
		{
			/* Copy the key in the driver */
			memmove(pAd->SharedKey[BSS0][keyIdx].Key, pIoctlSec->pData, pIoctlSec->length);
        }
	}
    else
			{
		/* Do we want to just set the transmit key index ? */
		int index = pIoctlSec->KeyIdx; /*(erq->flags & IW_ENCODE_INDEX) - 1; */
		if ((index >= 0) && (index < 4))
        {
			pAd->StaCfg.DefaultKeyId = index;
            }
        else
			/* Don't complain if only change the mode */
		if(!(pIoctlSec->flags & RT_CMD_STA_IOCTL_SECURITY_MODE))
		{
			pIoctlSec->Status = RTMP_IO_EINVAL;
			return NDIS_STATUS_SUCCESS;
		}
	}

done:
    DBGPRINT(RT_DEBUG_TRACE ,("==>rt_ioctl_siwencode::erq->flags=%x\n",pIoctlSec->flags));
	DBGPRINT(RT_DEBUG_TRACE ,("==>rt_ioctl_siwencode::AuthMode=%x\n",pAd->StaCfg.AuthMode));
	DBGPRINT(RT_DEBUG_TRACE ,("==>rt_ioctl_siwencode::DefaultKeyId=%x, KeyLen = %d\n",pAd->StaCfg.DefaultKeyId , pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].KeyLen));
	DBGPRINT(RT_DEBUG_TRACE ,("==>rt_ioctl_siwencode::WepStatus=%x\n",pAd->StaCfg.WepStatus));
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWENCODE.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwencode(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_SECURITY *pIoctlSec = (RT_CMD_STA_IOCTL_SECURITY *)pData;
	int kid;


	kid = pIoctlSec->KeyIdx; /*erq->flags & IW_ENCODE_INDEX; */
	DBGPRINT(RT_DEBUG_TRACE, ("===>rt_ioctl_giwencode %d\n", kid));

	if (pAd->StaCfg.WepStatus == Ndis802_11WEPDisabled)
	{
		pIoctlSec->length = 0;
		pIoctlSec->flags = RT_CMD_STA_IOCTL_SECURITY_DISABLED;
	}
	else if ((kid > 0) && (kid <=4))
	{
		/* copy wep key */
		pIoctlSec->KeyIdx = kid;
		if (pIoctlSec->length > pAd->SharedKey[BSS0][kid-1].KeyLen)
			pIoctlSec->length = pAd->SharedKey[BSS0][kid-1].KeyLen;
		memcpy(pIoctlSec->pData, pAd->SharedKey[BSS0][kid-1].Key, pIoctlSec->length);
		if (pAd->StaCfg.AuthMode == Ndis802_11AuthModeShared)
			pIoctlSec->flags |= RT_CMD_STA_IOCTL_SECURITY_RESTRICTED;		/* XXX */
		else
			pIoctlSec->flags |= RT_CMD_STA_IOCTL_SECURITY_OPEN;		/* XXX */

	}
	else if (kid == 0)
	{
		if (pAd->StaCfg.AuthMode == Ndis802_11AuthModeShared)
			pIoctlSec->flags |= RT_CMD_STA_IOCTL_SECURITY_RESTRICTED;		/* XXX */
		else
			pIoctlSec->flags |= RT_CMD_STA_IOCTL_SECURITY_OPEN;		/* XXX */
		pIoctlSec->length = pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].KeyLen;
		memcpy(pIoctlSec->pData, pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].Key, pIoctlSec->length);
		/* copy default key ID */
		if (pAd->StaCfg.AuthMode == Ndis802_11AuthModeShared)
			pIoctlSec->flags |= RT_CMD_STA_IOCTL_SECURITY_RESTRICTED;		/* XXX */
		else
			pIoctlSec->flags |= RT_CMD_STA_IOCTL_SECURITY_OPEN;		/* XXX */
		pIoctlSec->KeyIdx = pAd->StaCfg.DefaultKeyId + 1;			/* NB: base 1 */
		pIoctlSec->flags |= RT_CMD_STA_IOCTL_SECURITY_ENABLED;	/* XXX */
	}

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWMLME.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwmlme(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data,
	u32					Subcmd)
{
	MLME_QUEUE_ELEM				*pMsgElem = NULL;
	MLME_DISASSOC_REQ_STRUCT	DisAssocReq;
	MLME_DEAUTH_REQ_STRUCT      DeAuthReq;
	unsigned long						reason_code = (unsigned long)Data;


	/* allocate memory */
	pMsgElem = kmalloc(sizeof(MLME_QUEUE_ELEM), GFP_ATOMIC);
	if (pMsgElem == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: Allocate memory fail!!!\n", __FUNCTION__));
		return NDIS_STATUS_FAILURE;
	}

	switch(Subcmd)
	{
		case RT_CMD_STA_IOCTL_IW_MLME_DEAUTH:
			DBGPRINT(RT_DEBUG_TRACE, ("====> %s - IW_MLME_DEAUTH\n", __FUNCTION__));
			memcpy(DeAuthReq.Addr, pAd->CommonCfg.Bssid, ETH_ALEN);
			DeAuthReq.Reason = reason_code;
			pMsgElem->MsgLen = sizeof(MLME_DEAUTH_REQ_STRUCT);
			memmove(pMsgElem->Msg, &DeAuthReq, sizeof(MLME_DEAUTH_REQ_STRUCT));
			MlmeDeauthReqAction(pAd, pMsgElem);
			if (INFRA_ON(pAd))
			{
			    LinkDown(pAd, false);
			    pAd->Mlme.AssocMachine.CurrState = ASSOC_IDLE;
			}
			break;
		case RT_CMD_STA_IOCTL_IW_MLME_DISASSOC:
			DBGPRINT(RT_DEBUG_TRACE, ("====> %s - IW_MLME_DISASSOC\n", __FUNCTION__));
			memset(pAd->StaCfg.ConnectinfoSsid, 0, MAX_LEN_OF_SSID);
			memset(pAd->StaCfg.ConnectinfoBssid, 0, ETH_ALEN);
			pAd->StaCfg.ConnectinfoSsidLen  = 0;
			pAd->StaCfg.ConnectinfoBssType  = 1;
			pAd->StaCfg.ConnectinfoChannel = 0;

			memcpy(DisAssocReq.Addr, pAd->CommonCfg.Bssid, ETH_ALEN);
			DisAssocReq.Reason =  reason_code;

			pMsgElem->Machine = ASSOC_STATE_MACHINE;
			pMsgElem->MsgType = MT2_MLME_DISASSOC_REQ;
			pMsgElem->MsgLen = sizeof(MLME_DISASSOC_REQ_STRUCT);
			memmove(pMsgElem->Msg, &DisAssocReq, sizeof(MLME_DISASSOC_REQ_STRUCT));

			pAd->Mlme.CntlMachine.CurrState = CNTL_WAIT_OID_DISASSOC;
			MlmeDisassocReqAction(pAd, pMsgElem);
			break;
	}

	if (pMsgElem != NULL)
		kfree(pMsgElem);

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWAUTH.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwauth(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_SECURITY_ADV *pIoctlWpa = (RT_CMD_STA_IOCTL_SECURITY_ADV *)pData;


	switch (pIoctlWpa->flags)
	{
    	case RT_CMD_STA_IOCTL_WPA_VERSION:
            if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_VERSION1)
            {
                pAd->StaCfg.AuthMode = Ndis802_11AuthModeWPAPSK;
				if (pAd->StaCfg.BssType == BSS_ADHOC)
					pAd->StaCfg.AuthMode = Ndis802_11AuthModeWPANone;
            }
            else if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_VERSION2)
                pAd->StaCfg.AuthMode = Ndis802_11AuthModeWPA2PSK;

            DBGPRINT(RT_DEBUG_TRACE, ("%s::IW_AUTH_WPA_VERSION - param->value = %d!\n", __FUNCTION__, pIoctlWpa->value));
            break;
    	case RT_CMD_STA_IOCTL_WPA_PAIRWISE:
            if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_PAIRWISE_NONE)
            {
                pAd->StaCfg.WepStatus = Ndis802_11WEPDisabled;
                pAd->StaCfg.PairCipher = Ndis802_11WEPDisabled;
            }
            else if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_PAIRWISE_WEP40 ||
                     pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_PAIRWISE_WEP104)
            {
                pAd->StaCfg.WepStatus = Ndis802_11WEPEnabled;
                pAd->StaCfg.PairCipher = Ndis802_11WEPEnabled;
#ifdef WPA_SUPPLICANT_SUPPORT
                pAd->StaCfg.IEEE8021X = false;
#endif /* WPA_SUPPLICANT_SUPPORT */
            }
/*            else if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_PAIRWISE_TKIP)
            {
                pAd->StaCfg.WepStatus = Ndis802_11Encryption2Enabled;
                pAd->StaCfg.PairCipher = Ndis802_11Encryption2Enabled;
            }
            else if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_PAIRWISE_CCMP)
            {
                pAd->StaCfg.WepStatus = Ndis802_11Encryption3Enabled;
                pAd->StaCfg.PairCipher = Ndis802_11Encryption3Enabled;
            }*/
            else if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_PAIRWISE_TKIP)
            {
                pAd->StaCfg.WepStatus = Ndis802_11TKIPEnable;
                pAd->StaCfg.PairCipher = Ndis802_11TKIPEnable;
            }
            else if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_PAIRWISE_CCMP)
            {
                pAd->StaCfg.WepStatus = Ndis802_11AESEnable;
                pAd->StaCfg.PairCipher = Ndis802_11AESEnable;
            }
            DBGPRINT(RT_DEBUG_TRACE, ("%s::IW_AUTH_CIPHER_PAIRWISE - param->value = %d!\n", __FUNCTION__, pIoctlWpa->value));
            break;
    	case RT_CMD_STA_IOCTL_WPA_GROUP:
            if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_GROUP_NONE)
            {
                pAd->StaCfg.GroupCipher = Ndis802_11WEPDisabled;
            }
            else if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_GROUP_WEP40)
            {
                pAd->StaCfg.GroupCipher = Ndis802_11GroupWEP40Enabled;
            }
            else if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_GROUP_WEP104)
            {
                pAd->StaCfg.GroupCipher = Ndis802_11GroupWEP104Enabled;
            }
            else if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_GROUP_TKIP)
            {
//                pAd->StaCfg.GroupCipher = Ndis802_11Encryption2Enabled;
                pAd->StaCfg.GroupCipher = Ndis802_11TKIPEnable;
            }
            else if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_GROUP_CCMP)
            {
//                pAd->StaCfg.GroupCipher = Ndis802_11Encryption3Enabled;
                pAd->StaCfg.GroupCipher = Ndis802_11AESEnable;
            }
            DBGPRINT(RT_DEBUG_TRACE, ("%s::IW_AUTH_CIPHER_GROUP - param->value = %d!\n", __FUNCTION__, pIoctlWpa->value));
            break;
    	case RT_CMD_STA_IOCTL_WPA_KEY_MGMT:
#ifdef NATIVE_WPA_SUPPLICANT_SUPPORT
			pAd->StaCfg.WpaSupplicantUP &= 0x7F;
#endif /* NATIVE_WPA_SUPPLICANT_SUPPORT */
            if (pIoctlWpa->value == RT_CMD_STA_IOCTL_WPA_KEY_MGMT_1X)
            {
                if (pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPAPSK)
                {
                    pAd->StaCfg.AuthMode = Ndis802_11AuthModeWPA;
#ifdef WPA_SUPPLICANT_SUPPORT
                    pAd->StaCfg.IEEE8021X = false;
#endif /* WPA_SUPPLICANT_SUPPORT */
                }
                else if (pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA2PSK)
                {
                    pAd->StaCfg.AuthMode = Ndis802_11AuthModeWPA2;
#ifdef WPA_SUPPLICANT_SUPPORT
                    pAd->StaCfg.IEEE8021X = false;
#endif /* WPA_SUPPLICANT_SUPPORT */
                }
#ifdef WPA_SUPPLICANT_SUPPORT
                else
                    /* WEP 1x */
                    pAd->StaCfg.IEEE8021X = true;
#endif /* WPA_SUPPLICANT_SUPPORT */
            }
#ifdef NATIVE_WPA_SUPPLICANT_SUPPORT
#endif /* NATIVE_WPA_SUPPLICANT_SUPPORT */
            else if (pIoctlWpa->value == 0)
            {
				pAd->StaCfg.PortSecured = WPA_802_1X_PORT_SECURED;
            }
            DBGPRINT(RT_DEBUG_TRACE, ("%s::IW_AUTH_KEY_MGMT - param->value = %d!\n", __FUNCTION__, pIoctlWpa->value));
            break;
    	case RT_CMD_STA_IOCTL_WPA_AUTH_RX_UNENCRYPTED_EAPOL:
            break;
    	case RT_CMD_STA_IOCTL_WPA_AUTH_PRIVACY_INVOKED:
            /*if (pIoctlWpa->value == 0)
			{
                pAd->StaCfg.AuthMode = Ndis802_11AuthModeOpen;
                pAd->StaCfg.WepStatus = Ndis802_11WEPDisabled;
                pAd->StaCfg.PairCipher = Ndis802_11WEPDisabled;
        	    pAd->StaCfg.GroupCipher = Ndis802_11WEPDisabled;
            }*/
            DBGPRINT(RT_DEBUG_TRACE, ("%s::IW_AUTH_PRIVACY_INVOKED - param->value = %d!\n", __FUNCTION__, pIoctlWpa->value));
    		break;
    	case RT_CMD_STA_IOCTL_WPA_AUTH_DROP_UNENCRYPTED:
            if (pIoctlWpa->value != 0)
                pAd->StaCfg.PortSecured = WPA_802_1X_PORT_NOT_SECURED;
			else
			{
				pAd->StaCfg.PortSecured = WPA_802_1X_PORT_SECURED;
			}
            DBGPRINT(RT_DEBUG_TRACE, ("%s::IW_AUTH_DROP_UNENCRYPTED - param->value = %d!\n", __FUNCTION__, pIoctlWpa->value));
    		break;
    	case RT_CMD_STA_IOCTL_WPA_AUTH_80211_AUTH_ALG:
				pAd->StaCfg.AuthMode = Ndis802_11AuthModeAutoSwitch;
            DBGPRINT(RT_DEBUG_TRACE, ("%s::IW_AUTH_80211_AUTH_ALG - param->value = %d!\n", __FUNCTION__, pIoctlWpa->value));
			break;
    	case RT_CMD_STA_IOCTL_WPA_AUTH_WPA_ENABLED:
    		DBGPRINT(RT_DEBUG_TRACE, ("%s::IW_AUTH_WPA_ENABLED - Driver supports WPA!(param->value = %d)\n", __FUNCTION__, pIoctlWpa->value));
    		break;
}

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWAUTH.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwauth(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_SECURITY_ADV *pIoctlWpa = (RT_CMD_STA_IOCTL_SECURITY_ADV *)pData;


	switch (pIoctlWpa->flags) {
	case RT_CMD_STA_IOCTL_WPA_AUTH_DROP_UNENCRYPTED:
        pIoctlWpa->value = (pAd->StaCfg.WepStatus == Ndis802_11WEPDisabled) ? 0 : 1;
		break;

	case RT_CMD_STA_IOCTL_WPA_AUTH_80211_AUTH_ALG:
        pIoctlWpa->value = (pAd->StaCfg.AuthMode == Ndis802_11AuthModeShared) ? 0 : 1;
		break;

	case RT_CMD_STA_IOCTL_WPA_AUTH_WPA_ENABLED:
		pIoctlWpa->value = (pAd->StaCfg.AuthMode >= Ndis802_11AuthModeWPA) ? 1 : 0;
		break;
	}

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Set security key.

Arguments:
	pAd				- WLAN control block pointer
	keyIdx			- key index
	CipherAlg		- cipher algorithm
	bGTK			- 1: the key is group key
	*pKey			- the key

Return Value:
	None

Note:
========================================================================
*/
void fnSetCipherKey(
    struct rtmp_adapter *  pAd,
    INT             keyIdx,
    u8           CipherAlg,
    bool         bGTK,
    u8 		*pKey)
{
    memset(&pAd->SharedKey[BSS0][keyIdx], 0, sizeof(CIPHER_KEY));
    pAd->SharedKey[BSS0][keyIdx].KeyLen = LEN_TK;
    memmove(pAd->SharedKey[BSS0][keyIdx].Key, pKey, LEN_TK);
    memmove(pAd->SharedKey[BSS0][keyIdx].TxMic, pKey + LEN_TK, LEN_TKIP_MIC);
    memmove(pAd->SharedKey[BSS0][keyIdx].RxMic, pKey + LEN_TK + LEN_TKIP_MIC, LEN_TKIP_MIC);
    pAd->SharedKey[BSS0][keyIdx].CipherAlg = CipherAlg;

	if (!bGTK)
	{
/*
	Fix Apple TSN security (RSN (AES or TKIP unicast cipher) with WEP104 group cipher)
	Call AsicAddPairwiseKeyEntry() instead of AsicAddSharedKeyEntry()
*/
			MAC_TABLE_ENTRY  *pEntry;
	            /* Update these related information to MAC_TABLE_ENTRY */
	        	pEntry = &pAd->MacTab.Content[BSSID_WCID];
	        	pEntry->PairwiseKey.KeyLen = LEN_TK;
	            	memmove(pEntry->PairwiseKey.Key, pAd->SharedKey[BSS0][keyIdx].Key, LEN_TK);
	        	memmove(pEntry->PairwiseKey.RxMic, pAd->SharedKey[BSS0][keyIdx].RxMic, LEN_TKIP_MIC);
	        	memmove(pEntry->PairwiseKey.TxMic, pAd->SharedKey[BSS0][keyIdx].TxMic, LEN_TKIP_MIC);
	        	pEntry->PairwiseKey.CipherAlg = pAd->SharedKey[BSS0][keyIdx].CipherAlg;

			/* Add Pair-wise key to Asic */
		    	AsicAddPairwiseKeyEntry(
		        pAd,
		        (u8)pEntry->Aid,
		        &pEntry->PairwiseKey);

			RTMPSetWcidSecurityInfo(pAd,
									BSS0,
									0,
									pEntry->PairwiseKey.CipherAlg,
									(u8)pEntry->Aid,
									PAIRWISEKEYTABLE);
	}
	else
	{
			pAd->StaCfg.DefaultKeyId = keyIdx;
		    	/* Update group key information to ASIC Shared Key Table */
			AsicAddSharedKeyEntry(pAd,
								  BSS0,
								  keyIdx,
								  &pAd->SharedKey[BSS0][keyIdx]);
	}
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWENCODEEXT.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwencodeext(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_SECURITY *pIoctlSec = (RT_CMD_STA_IOCTL_SECURITY *)pData;
    int keyIdx;


    if (pIoctlSec->flags == RT_CMD_STA_IOCTL_SECURITY_DISABLED)
	{
        keyIdx = pIoctlSec->KeyIdx; /*(encoding->flags & IW_ENCODE_INDEX) - 1; */
        /* set BSSID wcid entry of the Pair-wise Key table as no-security mode */
	    AsicRemovePairwiseKeyEntry(pAd, BSSID_WCID);
        pAd->SharedKey[BSS0][keyIdx].KeyLen = 0;
		pAd->SharedKey[BSS0][keyIdx].CipherAlg = CIPHER_NONE;
		AsicRemoveSharedKeyEntry(pAd, 0, (u8)keyIdx);
        memset(&pAd->SharedKey[BSS0][keyIdx], 0, sizeof(CIPHER_KEY));
        DBGPRINT(RT_DEBUG_TRACE, ("%s::Remove all keys!\n", __FUNCTION__));
    }
	else
    {
        /* Get Key Index and convet to our own defined key index */
    	keyIdx = pIoctlSec->KeyIdx; /*(encoding->flags & IW_ENCODE_INDEX) - 1; */
    	if((keyIdx < 0) || (keyIdx >= NR_WEP_KEYS))
    		return NDIS_STATUS_FAILURE;

        if (pIoctlSec->ext_flags & RT_CMD_STA_IOCTL_SECURTIY_EXT_SET_TX_KEY)
        {
            pAd->StaCfg.DefaultKeyId = keyIdx;
            DBGPRINT(RT_DEBUG_TRACE, ("%s::DefaultKeyId = %d\n", __FUNCTION__, pAd->StaCfg.DefaultKeyId));
        }

        switch (pIoctlSec->Alg) {
    		case RT_CMD_STA_IOCTL_SECURITY_ALG_NONE:
                DBGPRINT(RT_DEBUG_TRACE, ("%s::IW_ENCODE_ALG_NONE\n", __FUNCTION__));
    			break;
    		case RT_CMD_STA_IOCTL_SECURITY_ALG_WEP:
                DBGPRINT(RT_DEBUG_TRACE, ("%s::IW_ENCODE_ALG_WEP - ext->key_len = %d, keyIdx = %d\n", __FUNCTION__, pIoctlSec->length, keyIdx));
    			if (pIoctlSec->length == MAX_WEP_KEY_SIZE)
                {
        			pAd->SharedKey[BSS0][keyIdx].KeyLen = MAX_WEP_KEY_SIZE;
                    pAd->SharedKey[BSS0][keyIdx].CipherAlg = CIPHER_WEP128;
				}
        		else if (pIoctlSec->length == MIN_WEP_KEY_SIZE)
                {
                    pAd->SharedKey[BSS0][keyIdx].KeyLen = MIN_WEP_KEY_SIZE;
                    pAd->SharedKey[BSS0][keyIdx].CipherAlg = CIPHER_WEP64;
				}
        		else
                    return NDIS_STATUS_FAILURE;

                memset(pAd->SharedKey[BSS0][keyIdx].Key,  0, 16);
			    memmove(pAd->SharedKey[BSS0][keyIdx].Key, pIoctlSec->pData, pIoctlSec->length);

				if ((pAd->StaCfg.GroupCipher == Ndis802_11GroupWEP40Enabled) ||
					(pAd->StaCfg.GroupCipher == Ndis802_11GroupWEP104Enabled))
				{
					/* Set Group key material to Asic */
					AsicAddSharedKeyEntry(pAd, BSS0, keyIdx, &pAd->SharedKey[BSS0][keyIdx]);

					/* Assign pairwise key info */
					RTMPSetWcidSecurityInfo(pAd,
										 	BSS0,
										 	keyIdx,
										 	pAd->SharedKey[BSS0][keyIdx].CipherAlg,
										 	BSSID_WCID,
										 	SHAREDKEYTABLE);

					STA_PORT_SECURED(pAd);
				}
    			break;
            case RT_CMD_STA_IOCTL_SECURITY_ALG_TKIP:
                DBGPRINT(RT_DEBUG_TRACE, ("%s::IW_ENCODE_ALG_TKIP - keyIdx = %d, ext->key_len = %d\n", __FUNCTION__, keyIdx, pIoctlSec->length));
                if (pIoctlSec->length == 32)
                {
                	if (pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPANone)
                	{
                		memset(pAd->StaCfg.PMK, 0, LEN_PMK);
				memmove(pAd->StaCfg.PMK, pIoctlSec->pData, pIoctlSec->length);
                	}
					else
					{
	                    if (pIoctlSec->ext_flags & RT_CMD_STA_IOCTL_SECURTIY_EXT_SET_TX_KEY)
	                    {
	                        fnSetCipherKey(pAd, keyIdx, CIPHER_TKIP, false, pIoctlSec->pData);
	                        if (pAd->StaCfg.AuthMode >= Ndis802_11AuthModeWPA2)
	                        {
	                            STA_PORT_SECURED(pAd);
	                        }
						}
	                    else if (pIoctlSec->ext_flags & RT_CMD_STA_IOCTL_SECURTIY_EXT_GROUP_KEY)
	                    {
	                        fnSetCipherKey(pAd, keyIdx, CIPHER_TKIP, true, pIoctlSec->pData);

	                        /* set 802.1x port control */
	            	        STA_PORT_SECURED(pAd);
	                    }
					}
                }
                else
                    return NDIS_STATUS_FAILURE;
                break;
            case RT_CMD_STA_IOCTL_SECURITY_ALG_CCMP:
				if (pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPANone)
            	{
            		memset(pAd->StaCfg.PMK, 0, LEN_PMK);
			memmove(pAd->StaCfg.PMK, pIoctlSec->pData, pIoctlSec->length);
            	}
				else
				{
	                if (pIoctlSec->ext_flags & RT_CMD_STA_IOCTL_SECURTIY_EXT_SET_TX_KEY)
					{
	                    fnSetCipherKey(pAd, keyIdx, CIPHER_AES, false, pIoctlSec->pData);
	                    if (pAd->StaCfg.AuthMode >= Ndis802_11AuthModeWPA2)
						{
	                    	STA_PORT_SECURED(pAd);
						}
	                }
	                else if (pIoctlSec->ext_flags & RT_CMD_STA_IOCTL_SECURTIY_EXT_GROUP_KEY)
	                {
	                    fnSetCipherKey(pAd, keyIdx, CIPHER_AES, true, pIoctlSec->pData);

	                    /* set 802.1x port control */
	        	        STA_PORT_SECURED(pAd);
	                }
				}
                break;
    		default:
    			return NDIS_STATUS_FAILURE;
		}
    }

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWENCODEEXT.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwencodeext(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_SECURITY *pIoctlSec = (RT_CMD_STA_IOCTL_SECURITY *)pData;
	int idx;


	idx = pIoctlSec->KeyIdx;
	if (idx)
	{
		if (idx < 1 || idx > 4)
		{
			pIoctlSec->Status = RTMP_IO_EINVAL;
			return NDIS_STATUS_FAILURE;
		}
		idx--;

		if ((pAd->StaCfg.WepStatus == Ndis802_11Encryption2Enabled) ||
			(pAd->StaCfg.WepStatus == Ndis802_11Encryption3Enabled))
		{
			if (idx != pAd->StaCfg.DefaultKeyId)
			{
				pIoctlSec->Status = 0;
				pIoctlSec->length = 0;
				return NDIS_STATUS_FAILURE;
			}
		}
	}
	else
		idx = pAd->StaCfg.DefaultKeyId;

	pIoctlSec->KeyIdx = idx + 1;

	pIoctlSec->length = 0;
	switch(pAd->StaCfg.WepStatus) {
		case Ndis802_11WEPDisabled:
			pIoctlSec->Alg = RT_CMD_STA_IOCTL_SECURITY_ALG_NONE;
			pIoctlSec->flags |= RT_CMD_STA_IOCTL_SECURITY_DISABLED;
			break;
		case Ndis802_11WEPEnabled:
			pIoctlSec->Alg = RT_CMD_STA_IOCTL_SECURITY_ALG_WEP;
			if (pAd->SharedKey[BSS0][idx].KeyLen > pIoctlSec->MaxKeyLen)
			{
				pIoctlSec->Status = RTMP_IO_E2BIG;
				return NDIS_STATUS_FAILURE;
			}
			else
			{
				pIoctlSec->length = pAd->SharedKey[BSS0][idx].KeyLen;
				pIoctlSec->pData = (char *)&(pAd->SharedKey[BSS0][idx].Key[0]);
			}
			break;
		case Ndis802_11Encryption2Enabled:
		case Ndis802_11Encryption3Enabled:
			if (pAd->StaCfg.WepStatus == Ndis802_11Encryption2Enabled)
				pIoctlSec->Alg = RT_CMD_STA_IOCTL_SECURITY_ALG_TKIP;
			else
				pIoctlSec->Alg = RT_CMD_STA_IOCTL_SECURITY_ALG_CCMP;

			if (pIoctlSec->MaxKeyLen < 32)
			{
				pIoctlSec->Status = RTMP_IO_E2BIG;
				return NDIS_STATUS_FAILURE;
			}
			else
			{
				pIoctlSec->length = 32;
				pIoctlSec->pData = (char *)&pAd->StaCfg.PMK[0];
			}
			break;
		default:
			pIoctlSec->Status = RTMP_IO_EINVAL;
			return NDIS_STATUS_FAILURE;
	}

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWGENIE.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwgenie(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
#ifdef WPA_SUPPLICANT_SUPPORT
	unsigned long length = (unsigned long)Data;


	if (pAd->StaCfg.WpaSupplicantUP != WPA_SUPPLICANT_DISABLE)
	{
		DBGPRINT(RT_DEBUG_TRACE ,("===> rt_ioctl_siwgenie\n"));
		pAd->StaCfg.bRSN_IE_FromWpaSupplicant = false;
		if ((length > 0) &&
		    (pData == NULL))
		{
			return NDIS_STATUS_FAILURE;
		}
		else if (length)
		{
			if (pAd->StaCfg.pWpaAssocIe)
			{
				kfree(pAd->StaCfg.pWpaAssocIe);
				pAd->StaCfg.pWpaAssocIe = NULL;
			}
/*			pAd->StaCfg.pWpaAssocIe = kmalloc(wrqu->data.length, MEM_ALLOC_FLAG); */
			pAd->StaCfg.pWpaAssocIe = kmalloc(length, GFP_ATOMIC);
			if (pAd->StaCfg.pWpaAssocIe)
			{
				pAd->StaCfg.WpaAssocIeLen = length;
				memmove(pAd->StaCfg.pWpaAssocIe, pData, pAd->StaCfg.WpaAssocIeLen);
				pAd->StaCfg.bRSN_IE_FromWpaSupplicant = true;
			}
			else
				pAd->StaCfg.WpaAssocIeLen = 0;
		}
	}
#endif /* WPA_SUPPLICANT_SUPPORT */

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWGENIE.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwgenie(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_RSN_IE *IoctlRsnIe = (RT_CMD_STA_IOCTL_RSN_IE *)pData;


	if ((pAd->StaCfg.RSNIE_Len == 0) ||
		(pAd->StaCfg.AuthMode < Ndis802_11AuthModeWPA))
	{
		IoctlRsnIe->length = 0;
		return NDIS_STATUS_SUCCESS;
	}

#ifdef WPA_SUPPLICANT_SUPPORT
	/*
		Can not use SIOCSIWGENIE definition, it is used in wireless.h
		We will not see the definition in MODULE.
		The definition can be saw in UTIL and NETIF.
	*/
/* #ifdef SIOCSIWGENIE */
	if ((pAd->StaCfg.WpaSupplicantUP & 0x7F) == WPA_SUPPLICANT_ENABLE &&
		(pAd->StaCfg.WpaAssocIeLen > 0))
	{
		if (IoctlRsnIe->length < pAd->StaCfg.WpaAssocIeLen)
			return NDIS_STATUS_FAILURE;

		IoctlRsnIe->length = pAd->StaCfg.WpaAssocIeLen;
		memcpy(IoctlRsnIe->pRsnIe, pAd->StaCfg.pWpaAssocIe, pAd->StaCfg.WpaAssocIeLen);
	}
	else
/* #endif */ /* SIOCSIWGENIE */
#endif /* NATIVE_WPA_SUPPLICANT_SUPPORT */
	{
		u8 RSNIe = IE_WPA;

		if (IoctlRsnIe->length < (pAd->StaCfg.RSNIE_Len + 2)) /* ID, Len */
			return NDIS_STATUS_FAILURE;
		IoctlRsnIe->length = pAd->StaCfg.RSNIE_Len + 2;

		if ((pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA2PSK) ||
            (pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA2))
			RSNIe = IE_RSN;

		IoctlRsnIe->pRsnIe[0] = (char)RSNIe;
		IoctlRsnIe->pRsnIe[1] = pAd->StaCfg.RSNIE_Len;
		memcpy(IoctlRsnIe->pRsnIe+2, &pAd->StaCfg.RSN_IE[0], pAd->StaCfg.RSNIE_Len);
	}

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWPMKSA.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwpmksa(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_STA_IOCTL_PMA_SA *pIoctlPmaSa = (RT_CMD_STA_IOCTL_PMA_SA *)pData;
	INT	CachedIdx = 0, idx = 0;


	switch(pIoctlPmaSa->Cmd)
	{
		case RT_CMD_STA_IOCTL_PMA_SA_FLUSH:
			memset(pAd->StaCfg.SavedPMK, 0, sizeof(BSSID_INFO)*PMKID_NO);
			DBGPRINT(RT_DEBUG_TRACE ,("rt_ioctl_siwpmksa - IW_PMKSA_FLUSH\n"));
			break;
		case RT_CMD_STA_IOCTL_PMA_SA_REMOVE:
			for (CachedIdx = 0; CachedIdx < pAd->StaCfg.SavedPMKNum; CachedIdx++)
			{
		        /* compare the BSSID */
		        if (memcmp(pIoctlPmaSa->Bssid, pAd->StaCfg.SavedPMK[CachedIdx].BSSID, ETH_ALEN) == 0)
		        {
		        	memset(pAd->StaCfg.SavedPMK[CachedIdx].BSSID, 0, ETH_ALEN);
					memset(pAd->StaCfg.SavedPMK[CachedIdx].PMKID, 0, 16);
					for (idx = CachedIdx; idx < (pAd->StaCfg.SavedPMKNum - 1); idx++)
					{
						memmove(&pAd->StaCfg.SavedPMK[idx].BSSID[0], &pAd->StaCfg.SavedPMK[idx+1].BSSID[0], ETH_ALEN);
						memmove(&pAd->StaCfg.SavedPMK[idx].PMKID[0], &pAd->StaCfg.SavedPMK[idx+1].PMKID[0], 16);
					}
					pAd->StaCfg.SavedPMKNum--;
			        break;
		        }
	        }

			DBGPRINT(RT_DEBUG_TRACE ,("rt_ioctl_siwpmksa - IW_PMKSA_REMOVE\n"));
			break;
		case RT_CMD_STA_IOCTL_PMA_SA_ADD:
			for (CachedIdx = 0; CachedIdx < pAd->StaCfg.SavedPMKNum; CachedIdx++)
			{
		        /* compare the BSSID */
		        if (memcmp(pIoctlPmaSa->Bssid, pAd->StaCfg.SavedPMK[CachedIdx].BSSID, ETH_ALEN) == 0)
			        break;
	        }

	        /* Found, replace it */
	        if (CachedIdx < PMKID_NO)
	        {
		        DBGPRINT(RT_DEBUG_OFF, ("Update PMKID, idx = %d\n", CachedIdx));
		        memmove(&pAd->StaCfg.SavedPMK[CachedIdx].BSSID[0], pIoctlPmaSa->Bssid, ETH_ALEN);
			memmove(&pAd->StaCfg.SavedPMK[CachedIdx].PMKID[0], pIoctlPmaSa->Pmkid, IW_PMKID_LEN);
		        pAd->StaCfg.SavedPMKNum++;
	        }
	        /* Not found, replace the last one */
	        else
	        {
		        /* Randomly replace one */
		        CachedIdx = (pIoctlPmaSa->Bssid[5] % PMKID_NO);
		        DBGPRINT(RT_DEBUG_OFF, ("Update PMKID, idx = %d\n", CachedIdx));
		        memmove(&pAd->StaCfg.SavedPMK[CachedIdx].BSSID[0], pIoctlPmaSa->Bssid, ETH_ALEN);
			memmove(&pAd->StaCfg.SavedPMK[CachedIdx].PMKID[0], pIoctlPmaSa->Pmkid, IW_PMKID_LEN);
	        }

			DBGPRINT(RT_DEBUG_TRACE ,("rt_ioctl_siwpmksa - IW_PMKSA_ADD\n"));
			break;
		default:
			DBGPRINT(RT_DEBUG_TRACE ,("rt_ioctl_siwpmksa - Unknow Command!!\n"));
			break;
	}

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWRATE.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_siwrate(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	RT_CMD_RATE_SET *pCmdRate = (RT_CMD_RATE_SET *)pData;
	u32 rate = pCmdRate->Rate;
	u32 fixed = pCmdRate->Fixed;


    /* rate = -1 => auto rate
       rate = X, fixed = 1 => (fixed rate X)
    */
    if (rate == -1)
    {
        /*Auto Rate */
        pAd->StaCfg.DesiredTransmitSetting.field.MCS = MCS_AUTO;
		pAd->StaCfg.bAutoTxRateSwitch = true;
		if ((!WMODE_CAP_N(pAd->CommonCfg.PhyMode)) ||
			(pAd->MacTab.Content[BSSID_WCID].HTPhyMode.field.MODE <= MODE_OFDM))
			RTMPSetDesiredRates(pAd, -1);

#ifdef DOT11_N_SUPPORT
			SetCommonHT(pAd);
#endif /* DOT11_N_SUPPORT */
	}
	else
	{
		if (fixed)
		{
			pAd->StaCfg.bAutoTxRateSwitch = false;
			if ((!WMODE_CAP_N(pAd->CommonCfg.PhyMode)) ||
				(pAd->MacTab.Content[BSSID_WCID].HTPhyMode.field.MODE <= MODE_OFDM))
				RTMPSetDesiredRates(pAd, rate);
			else
			{
				pAd->StaCfg.DesiredTransmitSetting.field.MCS = MCS_AUTO;
#ifdef DOT11_N_SUPPORT
				SetCommonHT(pAd);
#endif /* DOT11_N_SUPPORT */
			}
			DBGPRINT(RT_DEBUG_TRACE,
					("rt_ioctl_siwrate::(HtMcs=%d)\n",pAd->StaCfg.DesiredTransmitSetting.field.MCS));
		}
		else
		{
			/* TODO: rate = X, fixed = 0 => (rates <= X) */
			return NDIS_STATUS_FAILURE;
		}
	}

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWRATE.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_giwrate(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
    int rate_index = 0, rate_count = 0;
	HTTRANSMIT_SETTING ht_setting;


    rate_count = RT_RateSize/sizeof(__s32);

    if ((pAd->StaCfg.bAutoTxRateSwitch == false) &&
        (INFRA_ON(pAd)) &&
        ((!WMODE_CAP_N(pAd->CommonCfg.PhyMode)) || (pAd->MacTab.Content[BSSID_WCID].HTPhyMode.field.MODE <= MODE_OFDM)))
        ht_setting.word = pAd->StaCfg.HTPhyMode.word;
    else
        ht_setting.word = pAd->MacTab.Content[BSSID_WCID].HTPhyMode.word;

#ifdef DOT11_VHT_AC
       if (ht_setting.field.MODE >= MODE_VHT) {
               if (ht_setting.field.BW == 0 /* 20Mhz */) {
                       rate_index = 112 + ((u8)ht_setting.field.ShortGI * 29) + ((u8)ht_setting.field.MCS);
               } else if (ht_setting.field.BW == 1 /* 40Mhz */) {
                       rate_index = 121 + ((u8)ht_setting.field.ShortGI * 29) + ((u8)ht_setting.field.MCS);
               } else if (ht_setting.field.BW == 2 /* 80Mhz */) {
                       rate_index = 131 + ((u8)ht_setting.field.ShortGI * 29) + ((u8)ht_setting.field.MCS);
               }
       } else
#endif /* DOT11_VHT_AC */

#ifdef DOT11_N_SUPPORT
    if ((ht_setting.field.MODE >= MODE_HTMIX) && (ht_setting.field.MODE < MODE_VHT)) {
		/* rate_index = 12 + ((u8)ht_setting.field.BW *16) + ((u8)ht_setting.field.ShortGI *32) + ((u8)ht_setting.field.MCS); */
		rate_index = 16 + ((u8)ht_setting.field.BW *24) + ((u8)ht_setting.field.ShortGI *48) + ((u8)ht_setting.field.MCS);
    } else
#endif /* DOT11_N_SUPPORT */
    if (ht_setting.field.MODE == MODE_OFDM)
    	rate_index = (u8)(ht_setting.field.MCS) + 4;
    else if (ht_setting.field.MODE == MODE_CCK)
    	rate_index = (u8)(ht_setting.field.MCS);

    if (rate_index < 0)
        rate_index = 0;

    if (rate_index >= rate_count)
        rate_index = rate_count-1;

	*(unsigned long *)pData = ralinkrate[rate_index] * 500000;

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIFHWADDR.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_gifhwaddr(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	memcpy(pData, pAd->CurrentAddress, ETH_ALEN);
	return NDIS_STATUS_SUCCESS;
}

/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCSIWPRIVRSSI.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_rssi(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{

        (*(CHAR *)pData) =  pAd->StaCfg.RssiSample.AvgRssi0;
	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_IW_SET_PARAM_PRE.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_ioctl_setparam(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{
	struct os_cookie *pObj;


	pObj = pAd->OS_Cookie;
	{
		pObj->ioctl_if_type = INT_MAIN;
        pObj->ioctl_if = MAIN_MBSSID;
	}

	return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_IW_SET_WSC_U32_ITEM.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_private_set_wsc_u32_item(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{

    return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_IW_SET_WSC_STR_ITEM.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT
RtmpIoctl_rt_private_set_wsc_string_item(
	struct rtmp_adapter		*pAd,
	void 				*pData,
	unsigned long					Data)
{

    return NDIS_STATUS_SUCCESS;
}


/*
========================================================================
Routine Description:
	Communication with DRIVER module, whatever IOCTL.

Arguments:
	pAdSrc			- WLAN control block pointer
	*pRequest		- the request from IOCTL
	Command			- communication command
	Subcmd			- communication sub-command
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT RTMP_STA_IoctlHandle(
	void 				*pAdSrc,
	RTMP_IOCTL_INPUT_STRUCT	*pRequest,
	INT						Command,
	unsigned short					Subcmd,
	void 				*pData,
	unsigned long					Data,
	unsigned short                  priv_flags)
{
	struct rtmp_adapter *pAd = (struct rtmp_adapter *)pAdSrc;
	struct os_cookie *pObj = pAd->OS_Cookie;
	INT Status = NDIS_STATUS_SUCCESS;

	{	/* determine this ioctl command is comming from which interface. */
		pObj->ioctl_if_type = INT_MAIN;
		pObj->ioctl_if = MAIN_MBSSID;
	}


	/* handle by command */
	switch(Command)
	{
		case CMD_RTPRIV_IOCTL_RF:
			break;

		case CMD_RTPRIV_IOCTL_SITESURVEY:
			StaSiteSurvey(pAd, (NDIS_802_11_SSID *)pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_CHID_2_FREQ:
			RTMP_MapChannelID2KHZ(Data, (u32 *)pData);
			break;

		case CMD_RTPRIV_IOCTL_FREQ_2_CHID:
			RTMP_MapKHZ2ChannelID(Data, (u32 *)pData);
			break;

		case CMD_RTPRIV_IOCTL_ORI_DEV_TYPE_SET:
			pAd->StaCfg.OriDevType = Data;

			break;
		case CMD_RTPRIV_IOCTL_STA_SCAN_SANITY_CHECK:
			if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS))
		    {
				/*
				 * Still scanning, indicate the caller should try again.
				 */
				pAd->StaCfg.bSkipAutoScanConn = true;
				return NDIS_STATUS_FAILURE;
			}

			if (pAd->StaCfg.bImprovedScan)
			{
				/*
				 * Fast scanning doesn't complete yet.
				 */
				pAd->StaCfg.bSkipAutoScanConn = true;
				return NDIS_STATUS_FAILURE;
			}
			break;

		case CMD_RTPRIV_IOCTL_STA_SCAN_END:
		    pAd->StaCfg.bSkipAutoScanConn = false;
			DBGPRINT(RT_DEBUG_ERROR ,("===>rt_ioctl_giwscan. %d(%d) BSS returned, data->length = %ld\n",pAd->ScanTab.BssNr , pAd->ScanTab.BssNr, Data));
			break;

		case CMD_RTPRIV_IOCTL_BSS_LIST_GET:
		{
			RT_CMD_STA_IOCTL_BSS_LIST *pBssList = (RT_CMD_STA_IOCTL_BSS_LIST *)pData;
			RT_CMD_STA_IOCTL_BSS *pList;
			u32 i;

			pBssList->BssNum = pAd->ScanTab.BssNr;
			for (i = 0; i <pBssList->MaxNum ; i++)
			{
				if (i >=  pAd->ScanTab.BssNr)
					break;
				pList = (pBssList->pList) + i;
				set_quality(pList, &pAd->ScanTab.BssEntry[i]);
			}
		}
			break;

		/* ------------------------------------------------------------------ */
		/* for standard IOCTL in LINUX OS */

		/* ------------------- Functions for Standard IOCTL ------------------------- */
		case CMD_RTPRIV_IOCTL_STA_SIOCSIWFREQ:
			return RtmpIoctl_rt_ioctl_siwfreq(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWFREQ:
			return RtmpIoctl_rt_ioctl_giwfreq(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWMODE:
			return RtmpIoctl_rt_ioctl_siwmode(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWMODE:
			return RtmpIoctl_rt_ioctl_giwmode(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWAP:
			return RtmpIoctl_rt_ioctl_siwap(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWAP:
			return RtmpIoctl_rt_ioctl_giwap(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWSCAN:
			return RtmpIoctl_rt_ioctl_siwscan(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWSCAN:
			return RtmpIoctl_rt_ioctl_giwscan(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWESSID:
			return RtmpIoctl_rt_ioctl_siwessid(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWESSID:
			return RtmpIoctl_rt_ioctl_giwessid(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWRTS:
			return RtmpIoctl_rt_ioctl_siwrts(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWRTS:
			return RtmpIoctl_rt_ioctl_giwrts(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWFRAG:
			return RtmpIoctl_rt_ioctl_siwfrag(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWFRAG:
			return RtmpIoctl_rt_ioctl_giwfrag(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWENCODE:
			return RtmpIoctl_rt_ioctl_siwencode(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWENCODE:
			return RtmpIoctl_rt_ioctl_giwencode(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWMLME:
			return RtmpIoctl_rt_ioctl_siwmlme(pAd, pData, Data, Subcmd);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWAUTH:
			return RtmpIoctl_rt_ioctl_siwauth(pAd, pData, Data);			\
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWAUTH:
			return RtmpIoctl_rt_ioctl_giwauth(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWENCODEEXT:
			return RtmpIoctl_rt_ioctl_siwencodeext(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWENCODEEXT:
			return RtmpIoctl_rt_ioctl_giwencodeext(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWGENIE:
			return RtmpIoctl_rt_ioctl_siwgenie(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWGENIE:
			return RtmpIoctl_rt_ioctl_giwgenie(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWPMKSA:
			return RtmpIoctl_rt_ioctl_siwpmksa(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWRATE:
			return RtmpIoctl_rt_ioctl_siwrate(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIWRATE:
			return RtmpIoctl_rt_ioctl_giwrate(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCGIFHWADDR:
			return RtmpIoctl_rt_ioctl_gifhwaddr(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_SIOCSIWPRIVRSSI:
			return RtmpIoctl_rt_ioctl_rssi(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_IW_SET_WSC_U32_ITEM:
			return RtmpIoctl_rt_private_set_wsc_u32_item(pAd, pData, Data);
			break;

		case CMD_RTPRIV_IOCTL_STA_IW_SET_WSC_STR_ITEM:
			return RtmpIoctl_rt_private_set_wsc_string_item(pAd, pData, Data);
			break;

		/* ------------------------------------------------------------------ */

		default:
			/* for IOCTL that also can be used in AP mode */
			Status = RTMP_COM_IoctlHandle(pAd, pRequest, Command, Subcmd, pData, Data);
			break;
	}

	return Status;
}

