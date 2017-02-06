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

/*
    ==========================================================================
    Description:
        MLME message sanity check
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
 */
bool MlmeStartReqSanity(
	struct rtmp_adapter *pAd,
	void *Msg,
	ULONG MsgLen,
	CHAR Ssid[],
	u8 *pSsidLen)
{
	MLME_START_REQ_STRUCT *Info;

	Info = (MLME_START_REQ_STRUCT *) (Msg);

	if (Info->SsidLen > MAX_LEN_OF_SSID) {
		DBGPRINT(RT_DEBUG_TRACE, ("%s(): fail - wrong SSID length\n",
									__FUNCTION__));
		return false;
	}

	*pSsidLen = Info->SsidLen;
	memmove(Ssid, Info->Ssid, *pSsidLen);

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
bool PeerAssocRspSanity(
	struct rtmp_adapter *pAd,
	void *pMsg,
	ULONG MsgLen,
	u8 *pAddr2,
	USHORT *pCapabilityInfo,
	USHORT *pStatus,
	USHORT *pAid,
	u8 SupRate[],
	u8 *pSupRateLen,
	u8 ExtRate[],
	u8 *pExtRateLen,
	HT_CAPABILITY_IE *pHtCapability,
	ADD_HT_INFO_IE *pAddHtInfo,	/* AP might use this additional ht info IE */
	u8 *pHtCapabilityLen,
	u8 *pAddHtInfoLen,
	u8 *pNewExtChannelOffset,
	PEDCA_PARM pEdcaParm,
	EXT_CAP_INFO_ELEMENT *pExtCapInfo,
	u8 *pCkipFlag,
	IE_LISTS *ie_list)
{
	CHAR IeType, *Ptr;
	PFRAME_802_11 pFrame = (PFRAME_802_11) pMsg;
	PEID_STRUCT pEid;
	ULONG Length = 0;

	*pNewExtChannelOffset = 0xff;
	*pHtCapabilityLen = 0;
	*pAddHtInfoLen = 0;
	memcpy(pAddr2, pFrame->Hdr.Addr2, ETH_ALEN);
	Ptr = (char *) pFrame->Octet;
	Length += LENGTH_802_11;

	memmove(pCapabilityInfo, &pFrame->Octet[0], 2);
	Length += 2;
	memmove(pStatus, &pFrame->Octet[2], 2);
	Length += 2;
	*pCkipFlag = 0;
	*pExtRateLen = 0;
	pEdcaParm->bValid = false;

	if (*pStatus != MLME_SUCCESS)
		return true;

	memmove(pAid, &pFrame->Octet[4], 2);
	Length += 2;

	/* Aid already swaped byte order in RTMPFrameEndianChange() for big endian platform */
	*pAid = (*pAid) & 0x3fff;	/* AID is low 14-bit */

	/* -- get supported rates from payload and advance the pointer */
	IeType = pFrame->Octet[6];
	*pSupRateLen = pFrame->Octet[7];
	if ((IeType != IE_SUPP_RATES)
	    || (*pSupRateLen > MAX_LEN_OF_SUPPORTED_RATES)) {
		DBGPRINT(RT_DEBUG_TRACE, ("%s(): fail - wrong SupportedRates IE\n", __FUNCTION__));
		return false;
	} else
		memmove(SupRate, &pFrame->Octet[8], *pSupRateLen);


	Length = Length + 2 + *pSupRateLen;

	/*
	   many AP implement proprietary IEs in non-standard order, we'd better
	   tolerate mis-ordered IEs to get best compatibility
	 */
	pEid = (PEID_STRUCT) & pFrame->Octet[8 + (*pSupRateLen)];

	/* get variable fields from payload and advance the pointer */
	while ((Length + 2 + pEid->Len) <= MsgLen) {
		switch (pEid->Eid) {
		case IE_EXT_SUPP_RATES:
			if (pEid->Len <= MAX_LEN_OF_SUPPORTED_RATES) {
				memmove(ExtRate, pEid->Octet, pEid->Len);
				*pExtRateLen = pEid->Len;
			}
			break;

#ifdef DOT11_N_SUPPORT
		case IE_HT_CAP:
		case IE_HT_CAP2:
			if (pEid->Len >= SIZE_HT_CAP_IE) {	/* Note: allow extension.!! */
				memmove(pHtCapability, pEid->Octet, SIZE_HT_CAP_IE);

				*(USHORT *) (&pHtCapability->HtCapInfo) = cpu2le16(*(USHORT *)(&pHtCapability->HtCapInfo));
				*(USHORT *) (&pHtCapability->ExtHtCapInfo) = cpu2le16(*(USHORT *)(&pHtCapability->ExtHtCapInfo));

				*pHtCapabilityLen = SIZE_HT_CAP_IE;
			} else {
				DBGPRINT(RT_DEBUG_WARN, ("%s():wrong IE_HT_CAP\n", __FUNCTION__));
			}

			break;

		case IE_ADD_HT:
		case IE_ADD_HT2:
			if (pEid->Len >= sizeof (ADD_HT_INFO_IE)) {
				/*
				   This IE allows extension, but we can ignore extra bytes beyond our knowledge , so only
				   copy first sizeof(ADD_HT_INFO_IE)
				 */
				memmove(pAddHtInfo, pEid->Octet, sizeof (ADD_HT_INFO_IE));

				*(USHORT *) (&pAddHtInfo->AddHtInfo2) = cpu2le16(*(USHORT *)(&pAddHtInfo->AddHtInfo2));
				*(USHORT *) (&pAddHtInfo->AddHtInfo3) = cpu2le16(*(USHORT *)(&pAddHtInfo->AddHtInfo3));

				*pAddHtInfoLen = SIZE_ADD_HT_INFO_IE;
			} else {
				DBGPRINT(RT_DEBUG_WARN, ("%s():wrong IE_ADD_HT\n", __FUNCTION__));
			}

			break;
		case IE_SECONDARY_CH_OFFSET:
			if (pEid->Len == 1) {
				*pNewExtChannelOffset = pEid->Octet[0];
			} else {
				DBGPRINT(RT_DEBUG_WARN, ("%s():wrong IE_SECONDARY_CH_OFFSET\n", __FUNCTION__));
			}
			break;

#ifdef DOT11_VHT_AC
		case IE_VHT_CAP:
			if (pEid->Len == sizeof(VHT_CAP_IE)) {
				memmove(&ie_list->vht_cap, pEid->Octet, sizeof(VHT_CAP_IE));
				ie_list->vht_cap_len = sizeof(VHT_CAP_IE);
			} else {
				DBGPRINT(RT_DEBUG_WARN, ("%s():wrong IE_VHT_CAP\n", __FUNCTION__));
			}
			break;

		case IE_VHT_OP:
			if (pEid->Len == sizeof(VHT_OP_IE)) {
				memmove(&ie_list->vht_op, pEid->Octet, sizeof(VHT_OP_IE));
				ie_list->vht_op_len = sizeof(VHT_OP_IE);
			}else {
				DBGPRINT(RT_DEBUG_WARN, ("%s():wrong IE_VHT_OP\n", __FUNCTION__));
			}
			break;
#endif /* DOT11_VHT_AC */
#endif /* DOT11_N_SUPPORT */

		case IE_VENDOR_SPECIFIC:
			/* handle WME PARAMTER ELEMENT */
			if (memcmp(pEid->Octet, WME_PARM_ELEM, 6) == 0
			    && (pEid->Len == 24)) {
				u8 *ptr;
				int i;

				/* parsing EDCA parameters */
				pEdcaParm->bValid = true;
				pEdcaParm->bQAck = false;	/* pEid->Octet[0] & 0x10; */
				pEdcaParm->bQueueRequest = false;	/* pEid->Octet[0] & 0x20; */
				pEdcaParm->bTxopRequest = false;	/* pEid->Octet[0] & 0x40; */
				pEdcaParm->EdcaUpdateCount =
				    pEid->Octet[6] & 0x0f;
				pEdcaParm->bAPSDCapable =
				    (pEid->Octet[6] & 0x80) ? 1 : 0;
				ptr = (u8 *) & pEid->Octet[8];
				for (i = 0; i < 4; i++) {
					u8 aci = (*ptr & 0x60) >> 5;	/* b5~6 is AC INDEX */
					pEdcaParm->bACM[aci] = (((*ptr) & 0x10) == 0x10);	/* b5 is ACM */
					pEdcaParm->Aifsn[aci] = (*ptr) & 0x0f;	/* b0~3 is AIFSN */
					pEdcaParm->Cwmin[aci] = *(ptr + 1) & 0x0f;	/* b0~4 is Cwmin */
					pEdcaParm->Cwmax[aci] = *(ptr + 1) >> 4;	/* b5~8 is Cwmax */
					pEdcaParm->Txop[aci] = *(ptr + 2) + 256 * (*(ptr + 3));	/* in unit of 32-us */
					ptr += 4;	/* point to next AC */
				}
			}
			break;
		case IE_EXT_CAPABILITY:
			if (pEid->Len >= 1)
			{
				u8 MaxSize;
				u8 MySize = sizeof(EXT_CAP_INFO_ELEMENT);

				MaxSize = min(pEid->Len, MySize);
				memmove(pExtCapInfo, &pEid->Octet[0], MaxSize);
				DBGPRINT(RT_DEBUG_WARN, ("PeerAssocReqSanity - IE_EXT_CAPABILITY!\n"));
			}
			break;

		default:
			DBGPRINT(RT_DEBUG_TRACE,
				 ("%s():ignore unrecognized EID = %d\n", __FUNCTION__, pEid->Eid));
			break;
		}

		Length = Length + 2 + pEid->Len;
		pEid = (PEID_STRUCT) ((u8 *) pEid + 2 + pEid->Len);
	}


	return true;
}


/*
    ==========================================================================
    Description:

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
bool GetTimBit(
	CHAR *Ptr,
	USHORT Aid,
	u8 *TimLen,
	u8 *BcastFlag,
	u8 *DtimCount,
	u8 *DtimPeriod,
	u8 *MessageToMe)
{
	u8 BitCntl, N1, N2, MyByte, MyBit;
	CHAR *IdxPtr;

	IdxPtr = Ptr;

	IdxPtr++;
	*TimLen = *IdxPtr;

	/* get DTIM Count from TIM element */
	IdxPtr++;
	*DtimCount = *IdxPtr;

	/* get DTIM Period from TIM element */
	IdxPtr++;
	*DtimPeriod = *IdxPtr;

	/* get Bitmap Control from TIM element */
	IdxPtr++;
	BitCntl = *IdxPtr;

	if ((*DtimCount == 0) && (BitCntl & 0x01))
		*BcastFlag = true;
	else
		*BcastFlag = false;

	/* Parse Partial Virtual Bitmap from TIM element */
	N1 = BitCntl & 0xfe;	/* N1 is the first bitmap byte# */
	N2 = *TimLen - 4 + N1;	/* N2 is the last bitmap byte# */

	if ((Aid < (N1 << 3)) || (Aid >= ((N2 + 1) << 3)))
		*MessageToMe = false;
	else {
		MyByte = (Aid >> 3) - N1;	/* my byte position in the bitmap byte-stream */
		MyBit = Aid % 16 - ((MyByte & 0x01) ? 8 : 0);

		IdxPtr += (MyByte + 1);

		if (*IdxPtr & (0x01 << MyBit))
			*MessageToMe = true;
		else
			*MessageToMe = false;
	}

	return true;
}
