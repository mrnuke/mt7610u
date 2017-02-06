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


#ifndef	__WPA_H__
#define	__WPA_H__

#ifndef ROUND_UP
#define ROUND_UP(__x, __y) \
	(((unsigned long)((__x)+((__y)-1))) & ((unsigned long)~((__y)-1)))
#endif

#define	SET_UINT16_TO_ARRARY(_V, _LEN)		\
{											\
	_V[0] = ((uint16_t)_LEN) >> 8;			\
	_V[1] = ((uint16_t)_LEN & 0xFF);					\
}

#define	INC_UINT16_TO_ARRARY(_V, _LEN)			\
{												\
	uint16_t	var_len;							\
												\
	var_len = (_V[0]<<8) | (_V[1]);				\
	var_len += _LEN;							\
												\
	_V[0] = (var_len & 0xFF00) >> 8;			\
	_V[1] = (var_len & 0xFF);					\
}

#define	CONV_ARRARY_TO_UINT16(_V)	((_V[0]<<8) | (_V[1]))

#define	ADD_ONE_To_64BIT_VAR(_V)		\
{										\
	u8 cnt = LEN_KEY_DESC_REPLAY;	\
	do									\
	{									\
		cnt--;							\
		_V[cnt]++;						\
		if (cnt == 0)					\
			break;						\
	}while (_V[cnt] == 0);				\
}

#define INC_TX_TSC(_tsc, _cnt)                          \
{                                                       \
    INT i=0;                                            \
	while (++_tsc[i] == 0x0)                            \
    {                                                   \
        i++;                                            \
		if (i == (_cnt))                                \
			break;                                      \
	}                                                   \
}

#define IS_WPA_CAPABILITY(a)       (((a) >= Ndis802_11AuthModeWPA) && ((a) <= Ndis802_11AuthModeWPA1PSKWPA2PSK))

/*
	WFA recommend to restrict the encryption type in 11n-HT mode.
 	So, the WEP and TKIP shall not be allowed to use HT rate.
 */
#define IS_INVALID_HT_SECURITY(_mode)		\
	(((_mode) == Ndis802_11Encryption1Enabled) || \
	 ((_mode) == Ndis802_11Encryption2Enabled))

#define MIX_CIPHER_WPA_TKIP_ON(x)       (((x) & 0x08) != 0)
#define MIX_CIPHER_WPA_AES_ON(x)        (((x) & 0x04) != 0)
#define MIX_CIPHER_WPA2_TKIP_ON(x)      (((x) & 0x02) != 0)
#define MIX_CIPHER_WPA2_AES_ON(x)       (((x) & 0x01) != 0)

/* Some definition are different between Keneral mode and Daemon mode */
#ifdef WPA_DAEMON_MODE
/* The definition for Daemon mode */
#define WPA_GET_BSS_NUM(_pAd)		(_pAd)->mbss_num

#define WPA_GET_PMK(_pAd, _pEntry, _pmk)					\
{															\
	_pmk = _pAd->MBSS[_pEntry->apidx].PMK;					\
}

#define WPA_GET_GTK(_pAd, _pEntry, _gtk)					\
{															\
	_gtk = _pAd->MBSS[_pEntry->apidx].GTK;					\
}

#define WPA_GET_GROUP_CIPHER(_pAd, _pEntry, _cipher)		\
{															\
	_cipher = (_pAd)->MBSS[_pEntry->apidx].GroupEncrypType;	\
}

#define WPA_GET_DEFAULT_KEY_ID(_pAd, _pEntry, _idx)			\
{															\
	_idx = (_pAd)->MBSS[_pEntry->apidx].DefaultKeyId;		\
}

#define WPA_GET_BMCST_TSC(_pAd, _pEntry, _tsc)				\
{															\
	_tsc = 1;												\
}

#define WPA_BSSID(_pAd, _apidx)		(_pAd)->MBSS[_apidx].wlan_addr

#define WPA_OS_MALLOC(_p, _s)		\
{									\
	_p = os_malloc(_s);			\
}

#define WPA_OS_FREE(_p)		\
{								\
	os_free(_p);				\
}

#define WPA_GET_CURRENT_TIME(_time)		\
{										\
	struct timeval tv;					\
	gettimeofday(&tv, NULL);			\
	*(_time) = tv.tv_sec;					\
}

#else
/* The definition for Driver mode */

#define WPA_GET_BSS_NUM(_pAd)		1
#define WPA_GET_GROUP_CIPHER(_pAd, _pEntry, _cipher)				\
	{																\
		_cipher = (_pAd)->StaCfg.GroupCipher;						\
	}
#define WPA_BSSID(_pAd, _apidx) 	(_pAd)->CommonCfg.Bssid

#define WPA_OS_MALLOC(_p, _s)		\
{									\
	kmalloc((u8 **)&_p, _s);		\
}

#define WPA_OS_FREE(_p)		\
{							\
	kfree(_p);	\
}

#define WPA_GET_CURRENT_TIME(_time)		NdisGetSystemUpTime(_time);

#endif /* End of Driver Mode */


/*========================================
	The prototype is defined in cmm_wpa.c
  ========================================*/
void inc_iv_byte(
	u8 *iv,
	unsigned int len,
	unsigned int cnt);

bool WpaMsgTypeSubst(
	u8 EAPType,
	INT *MsgType);

void PRF(
	u8 *key,
	INT key_len,
	u8 *prefix,
	INT prefix_len,
	u8 *data,
	INT data_len,
	u8 *output,
	INT len);

int RtmpPasswordHash(
	char *password,
	unsigned char *ssid,
	int ssidlength,
	unsigned char *output);

	void KDF(
	u8 * key,
	INT key_len,
	u8 * label,
	INT label_len,
	u8 * data,
	INT data_len,
	u8 * output,
	unsigned short len);

u8 * WPA_ExtractSuiteFromRSNIE(
	u8 * rsnie,
	unsigned int rsnie_len,
	u8 type,
	u8 *count);

void WpaShowAllsuite(
	u8 * rsnie,
	unsigned int rsnie_len);

void RTMPInsertRSNIE(
	u8 *pFrameBuf,
	unsigned long *pFrameLen,
	u8 * rsnie_ptr,
	u8 rsnie_len,
	u8 * pmkid_ptr,
	u8 pmkid_len);

/*
 =====================================
 	function prototype in cmm_wpa.c
 =====================================
*/
void RTMPToWirelessSta(
	struct rtmp_adapter *pAd,
	PMAC_TABLE_ENTRY pEntry,
	u8 *pHeader802_3,
	unsigned int HdrLen,
	u8 *pData,
	unsigned int DataLen,
	bool bClearFrame);

void WpaDerivePTK(
	struct rtmp_adapter *pAd,
	u8 *PMK,
	u8 *ANonce,
	u8 *AA,
	u8 *SNonce,
	u8 *SA,
	u8 *output,
	unsigned int len);

void WpaDeriveGTK(
	u8 *PMK,
	u8 *GNonce,
	u8 *AA,
	u8 *output,
	unsigned int len);

void GenRandom(
	struct rtmp_adapter *pAd,
	u8 *macAddr,
	u8 *random);

bool RTMPCheckWPAframe(
	struct rtmp_adapter *pAd,
	PMAC_TABLE_ENTRY pEntry,
	u8 *pData,
	unsigned long DataByteCount,
	u8 FromWhichBSSID);

bool RTMPParseEapolKeyData(
	struct rtmp_adapter *pAd,
	u8 *pKeyData,
	u8 KeyDataLen,
	u8 GroupKeyIndex,
	u8 MsgType,
	bool bWPA2,
	MAC_TABLE_ENTRY *pEntry);

void WPA_ConstructKdeHdr(
	u8 data_type,
	u8 data_len,
	u8 *pBuf);

void ConstructEapolMsg(
	PMAC_TABLE_ENTRY pEntry,
	u8 GroupKeyWepStatus,
	u8 MsgType,
	u8 DefaultKeyIdx,
	u8 *KeyNonce,
	u8 *TxRSC,
	u8 *GTK,
	u8 *RSNIE,
	u8 RSNIE_Len,
	PEAPOL_PACKET pMsg);

PCIPHER_KEY RTMPSwCipherKeySelection(
	struct rtmp_adapter *pAd,
	u8 *pIV,
	RX_BLK *pRxBlk,
	PMAC_TABLE_ENTRY pEntry);

int RTMPSoftDecryptionAction(
	struct rtmp_adapter *pAd,
	u8 *pHdr,
	u8 UserPriority,
	PCIPHER_KEY pKey,
	u8 *pData,
	uint16_t *DataByteCnt);

void RTMPSoftConstructIVHdr(
	u8 CipherAlg,
	u8 key_id,
	u8 *pTxIv,
	u8 *pHdrIv,
	u8 *hdr_iv_len);

void RTMPSoftEncryptionAction(
	struct rtmp_adapter *pAd,
	u8 CipherAlg,
	u8 *pHdr,
	u8 *pSrcBufData,
	u32 SrcBufLen,
	u8 KeyIdx,
	PCIPHER_KEY pKey,
	u8 *ext_len);

void RTMPMakeRSNIE(
	struct rtmp_adapter *pAd,
	unsigned int AuthMode,
	unsigned int WepStatus,
	u8 apidx);

void WPAInstallPairwiseKey(
	struct rtmp_adapter *pAd,
	u8 BssIdx,
	PMAC_TABLE_ENTRY pEntry,
	bool bAE);

void WPAInstallSharedKey(
	struct rtmp_adapter *pAd,
	u8 GroupCipher,
	u8 BssIdx,
	u8 KeyIdx,
	u8 Wcid,
	bool bAE,
	u8 * pGtk,
	u8 GtkLen);

void RTMPSetWcidSecurityInfo(
	struct rtmp_adapter *pAd,
	u8 BssIdx,
	u8 KeyIdx,
	u8 CipherAlg,
	u8 Wcid,
	u8 KeyTabFlag);

void CalculateMIC(
	u8 KeyDescVer,
	u8 *PTK,
	PEAPOL_PACKET pMsg);

char *GetEapolMsgType(
	CHAR msg);

#ifdef CONFIG_STA_SUPPORT
#endif /* CONFIG_STA_SUPPORT */

/*
 =====================================
 	function prototype in cmm_wep.c
 =====================================
*/
unsigned int RTMP_CALC_FCS32(
	unsigned int Fcs,
	u8 *Cp,
	INT Len);

void RTMPConstructWEPIVHdr(
	u8 key_idx,
	u8 *pn,
	u8 *iv_hdr);

bool RTMPSoftEncryptWEP(
	struct rtmp_adapter *pAd,
	u8 *pIvHdr,
	PCIPHER_KEY pKey,
	u8 *pData,
	unsigned long DataByteCnt);

bool RTMPSoftDecryptWEP(
	struct rtmp_adapter *pAd,
	PCIPHER_KEY pKey,
	u8 *pData,
	uint16_t *DataByteCnt);

/*
 =====================================
 	function prototype in cmm_tkip.c
 =====================================
*/
bool RTMPSoftDecryptTKIP(
	struct rtmp_adapter *pAd,
	u8 *pHdr,
	u8 UserPriority,
	PCIPHER_KEY pKey,
	u8 *pData,
	uint16_t *DataByteCnt);

void TKIP_GTK_KEY_WRAP(
	u8 *key,
	u8 *iv,
	u8 *input_text,
	u32 input_len,
	u8 *output_text);

void TKIP_GTK_KEY_UNWRAP(
	u8 *key,
	u8 *iv,
	u8 *input_text,
	u32 input_len,
	u8 *output_text);

/*
 =====================================
 	function prototype in cmm_aes.c
 =====================================
*/
bool RTMPSoftDecryptAES(
	struct rtmp_adapter *pAd,
	u8 *pData,
	unsigned long DataByteCnt,
	PCIPHER_KEY pWpaKey);

void RTMPConstructCCMPHdr(
	u8 key_idx,
	u8 *pn,
	u8 *ccmp_hdr);

bool RTMPSoftEncryptCCMP(
	struct rtmp_adapter *pAd,
	u8 *pHdr,
	u8 *pIV,
	u8 *pKey,
	u8 *pData,
	u32 DataLen);

bool RTMPSoftDecryptCCMP(
	struct rtmp_adapter *pAd,
	u8 *pHdr,
	PCIPHER_KEY pKey,
	u8 *pData,
	uint16_t *DataLen);

void CCMP_test_vector(
	struct rtmp_adapter *pAd,
	INT input);

#endif
