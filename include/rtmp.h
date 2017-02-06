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


#ifndef __RTMP_H__
#define __RTMP_H__

#include "link_list.h"
#include "spectrum_def.h"

#include "rtmp_dot11.h"
#include "wpa_cmm.h"


#include "wsc.h"







#ifdef CLIENT_WDS
#include "client_wds_cmm.h"
#endif /* CLIENT_WDS */

#include "drs_extr.h"

struct _RTMP_RA_LEGACY_TB;

struct rtmp_adapter;

typedef struct _UAPSD_INFO {
	bool bAPSDCapable;
} UAPSD_INFO;

#include "mcu/mcu.h"


#ifdef CONFIG_ANDES_SUPPORT
#include "mcu/mcu_and.h"
#endif

#include "rtmp_chip.h"

#include "radar.h"

#ifdef DFS_SUPPORT
#include "dfs.h"
#endif /* DFS_SUPPORT */

#ifdef LED_CONTROL_SUPPORT
#include "rt_led.h"
#endif /* LED_CONTROL_SUPPORT */

/*#define DBG		1 */

/*#define DBG_DIAGNOSE		1 */
#define ASIC_VERSION	0x0000

/*+++Used for merge MiniportMMRequest() and MiniportDataMMRequest() into one function */
#define MAX_DATAMM_RETRY	3
#define MGMT_USE_QUEUE_FLAG	0x80
/*---Used for merge MiniportMMRequest() and MiniportDataMMRequest() into one function */
/* The number of channels for per-channel Tx power offset */


#define	MAXSEQ		(0xFFF)

#ifdef DOT11N_SS3_SUPPORT
#define MAX_MCS_SET 24		/* From MCS 0 ~ MCS 23 */
#else
#define MAX_MCS_SET 16		/* From MCS 0 ~ MCS 15 */
#endif /* DOT11N_SS3_SUPPORT */


#define MAX_TXPOWER_ARRAY_SIZE	5

extern unsigned char CISCO_OUI[];
extern u8 BaSizeArray[4];

extern u8 BROADCAST_ADDR[ETH_ALEN];
extern u8 ZERO_MAC_ADDR[ETH_ALEN];
extern unsigned long BIT32[32];
extern char *CipherName[];
extern u8 RxwiMCSToOfdmRate[12];
extern u8 SNAP_802_1H[6];
extern u8 SNAP_BRIDGE_TUNNEL[6];
extern u8 EAPOL[2];
extern u8 IPX[2];
extern u8 TPID[];
extern u8 APPLE_TALK[2];
extern u8 OfdmRateToRxwiMCS[];
extern u8 MapUserPriorityToAccessCategory[8];

extern unsigned char RateIdToMbps[];
extern unsigned short RateIdTo500Kbps[];

extern u8 CipherSuiteWpaNoneTkip[];
extern u8 CipherSuiteWpaNoneTkipLen;

extern u8 CipherSuiteWpaNoneAes[];
extern u8 CipherSuiteWpaNoneAesLen;

extern u8 SsidIe;
extern u8 SupRateIe;
extern u8 ExtRateIe;

#ifdef DOT11_N_SUPPORT
extern u8 HtCapIe;
extern u8 AddHtInfoIe;
extern u8 NewExtChanIe;
extern u8 BssCoexistIe;
extern u8 ExtHtCapIe;
#ifdef CONFIG_STA_SUPPORT
extern u8 PRE_N_HT_OUI[];
#endif /* CONFIG_STA_SUPPORT */
#endif /* DOT11_N_SUPPORT */
extern u8 ExtCapIe;

extern u8 ErpIe;
extern u8 DsIe;
extern u8 TimIe;
extern u8 WpaIe;
extern u8 Wpa2Ie;
extern u8 IbssIe;
extern u8 WapiIe;

extern u8 WPA_OUI[];
extern u8 RSN_OUI[];
extern u8 WAPI_OUI[];
extern u8 WME_INFO_ELEM[];
extern u8 WME_PARM_ELEM[];
extern u8 RALINK_OUI[];
extern u8 PowerConstraintIE[];

typedef struct _RSSI_SAMPLE {
	CHAR LastRssi0;		/* last received RSSI */
	CHAR LastRssi1;		/* last received RSSI */
	CHAR LastRssi2;		/* last received RSSI */
	CHAR AvgRssi0;
	CHAR AvgRssi1;
	CHAR AvgRssi2;
	short AvgRssi0X8;
	short AvgRssi1X8;
	short AvgRssi2X8;
	CHAR LastSnr0;
	CHAR LastSnr1;
	CHAR LastSnr2;
	CHAR AvgSnr0;
	CHAR AvgSnr1;
	CHAR AvgSnr2;
	short AvgSnr0X8;
	short AvgSnr1X8;
	short AvgSnr2X8;
	CHAR LastNoiseLevel0;
	CHAR LastNoiseLevel1;
	CHAR LastNoiseLevel2;
} RSSI_SAMPLE;

/* */
/*  Queue structure and macros */
/* */
#define InitializeQueueHeader(QueueHeader)              \
{                                                       \
	(QueueHeader)->Head = (QueueHeader)->Tail = NULL;   \
	(QueueHeader)->Number = 0;                          \
}

#define RemoveHeadQueue(QueueHeader)                \
(QueueHeader)->Head;                                \
{                                                   \
	PQUEUE_ENTRY pNext;                             \
	if ((QueueHeader)->Head != NULL)				\
	{												\
		pNext = (QueueHeader)->Head->Next;          \
		(QueueHeader)->Head->Next = NULL;		\
		(QueueHeader)->Head = pNext;                \
		if (pNext == NULL)                          \
			(QueueHeader)->Tail = NULL;             \
		(QueueHeader)->Number--;                    \
	}												\
}

#define InsertHeadQueue(QueueHeader, QueueEntry)            \
{                                                           \
		((PQUEUE_ENTRY)QueueEntry)->Next = (QueueHeader)->Head; \
		(QueueHeader)->Head = (PQUEUE_ENTRY)(QueueEntry);       \
		if ((QueueHeader)->Tail == NULL)                        \
			(QueueHeader)->Tail = (PQUEUE_ENTRY)(QueueEntry);   \
		(QueueHeader)->Number++;                                \
}

#define InsertTailQueue(QueueHeader, QueueEntry)				\
{                                                               \
	((PQUEUE_ENTRY)QueueEntry)->Next = NULL;                    \
	if ((QueueHeader)->Tail)                                    \
		(QueueHeader)->Tail->Next = (PQUEUE_ENTRY)(QueueEntry); \
	else                                                        \
		(QueueHeader)->Head = (PQUEUE_ENTRY)(QueueEntry);       \
	(QueueHeader)->Tail = (PQUEUE_ENTRY)(QueueEntry);           \
	(QueueHeader)->Number++;                                    \
}

#define InsertTailQueueAc(pAd, pEntry, QueueHeader, QueueEntry)			\
{																		\
	((PQUEUE_ENTRY)QueueEntry)->Next = NULL;							\
	if ((QueueHeader)->Tail)											\
		(QueueHeader)->Tail->Next = (PQUEUE_ENTRY)(QueueEntry);			\
	else																\
		(QueueHeader)->Head = (PQUEUE_ENTRY)(QueueEntry);				\
	(QueueHeader)->Tail = (PQUEUE_ENTRY)(QueueEntry);					\
	(QueueHeader)->Number++;											\
}
void DisplayTxAgg (struct rtmp_adapter*pAd);


/* */
/*  Macros for flag and ref count operations */
/* */
#define RTMP_SET_FLAG(_M, _F)       ((_M)->Flags |= (_F))
#define RTMP_CLEAR_FLAG(_M, _F)     ((_M)->Flags &= ~(_F))
#define RTMP_CLEAR_FLAGS(_M)        ((_M)->Flags = 0)
#define RTMP_TEST_FLAG(_M, _F)      (((_M)->Flags & (_F)) != 0)
#define RTMP_TEST_FLAGS(_M, _F)     (((_M)->Flags & (_F)) == (_F))
/* Macro for power save flag. */
#define RTMP_SET_PSFLAG(_M, _F)       ((_M)->PSFlags |= (_F))
#define RTMP_CLEAR_PSFLAG(_M, _F)     ((_M)->PSFlags &= ~(_F))
#define RTMP_CLEAR_PSFLAGS(_M)        ((_M)->PSFlags = 0)
#define RTMP_TEST_PSFLAG(_M, _F)      (((_M)->PSFlags & (_F)) != 0)
#define RTMP_TEST_PSFLAGS(_M, _F)     (((_M)->PSFlags & (_F)) == (_F))

#define OPSTATUS_SET_FLAG(_pAd, _F)     ((_pAd)->CommonCfg.OpStatusFlags |= (_F))
#define OPSTATUS_CLEAR_FLAG(_pAd, _F)   ((_pAd)->CommonCfg.OpStatusFlags &= ~(_F))
#define OPSTATUS_TEST_FLAG(_pAd, _F)    (((_pAd)->CommonCfg.OpStatusFlags & (_F)) != 0)

#define WIFI_TEST_SET_FLAG(_pAd, _F)     ((_pAd)->CommonCfg.WiFiTestFlags |= (_F))
#define WIFI_TEST_CLEAR_FLAG(_pAd, _F)   ((_pAd)->CommonCfg.WiFiTestFlags &= ~(_F))
#define WIFI_TEST_CHECK_FLAG(_pAd, _F)    (((_pAd)->CommonCfg.WiFiTestFlags & (_F)) != 0)

#define CLIENT_STATUS_SET_FLAG(_pEntry,_F)      ((_pEntry)->ClientStatusFlags |= (_F))
#define CLIENT_STATUS_CLEAR_FLAG(_pEntry,_F)    ((_pEntry)->ClientStatusFlags &= ~(_F))
#define CLIENT_STATUS_TEST_FLAG(_pEntry,_F)     (((_pEntry)->ClientStatusFlags & (_F)) != 0)

#define RX_FILTER_SET_FLAG(_pAd, _F)    ((_pAd)->CommonCfg.PacketFilter |= (_F))
#define RX_FILTER_CLEAR_FLAG(_pAd, _F)  ((_pAd)->CommonCfg.PacketFilter &= ~(_F))
#define RX_FILTER_TEST_FLAG(_pAd, _F)   (((_pAd)->CommonCfg.PacketFilter & (_F)) != 0)

#define RTMP_SET_MORE_FLAG(_M, _F)       ((_M)->MoreFlags |= (_F))
#define RTMP_TEST_MORE_FLAG(_M, _F)      (((_M)->MoreFlags & (_F)) != 0)
#define RTMP_CLEAR_MORE_FLAG(_M, _F)     ((_M)->MoreFlags &= ~(_F))

#define SET_ASIC_CAP(_pAd, _caps)		((_pAd)->chipCap.asic_caps |= (_caps))
#define IS_ASIC_CAP(_pAd, _caps)			(((_pAd)->chipCap.asic_caps & (_caps)) != 0)
#define CLR_ASIC_CAP(_pAd, _caps)		((_pAd)->chipCap.asic_caps &= ~(_caps))


#ifdef CONFIG_STA_SUPPORT
#define STA_NO_SECURITY_ON(_p)          (_p->StaCfg.WepStatus == Ndis802_11EncryptionDisabled)
#define STA_WEP_ON(_p)                  (_p->StaCfg.WepStatus == Ndis802_11Encryption1Enabled)
#define STA_TKIP_ON(_p)                 (_p->StaCfg.WepStatus == Ndis802_11Encryption2Enabled)
#define STA_AES_ON(_p)                  (_p->StaCfg.WepStatus == Ndis802_11Encryption3Enabled)

#define STA_TGN_WIFI_ON(_p)             (_p->StaCfg.bTGnWifiTest == true)
#endif /* CONFIG_STA_SUPPORT */

#define CKIP_KP_ON(_p)				((((_p)->StaCfg.CkipFlag) & 0x10) && ((_p)->StaCfg.bCkipCmicOn == true))
#define CKIP_CMIC_ON(_p)			((((_p)->StaCfg.CkipFlag) & 0x08) && ((_p)->StaCfg.bCkipCmicOn == true))

#define INC_RING_INDEX(_idx, _RingSize)    \
{                                          \
    (_idx) = (_idx+1) % (_RingSize);       \
}

#ifdef USB_BULK_BUF_ALIGMENT
#define CUR_WRITE_IDX_INC(_idx, _RingSize)    \
{                                          \
    (_idx) = (_idx+1) % (_RingSize);       \
}
#endif /* USB_BULK_BUF_ALIGMENT */

#ifdef DOT11_N_SUPPORT
/* StaActive.SupportedHtPhy.MCSSet is copied from AP beacon.  Don't need to update here. */
#define COPY_HTSETTINGS_FROM_MLME_AUX_TO_ACTIVE_CFG(_pAd)                                 \
{                                                                                       \
	_pAd->StaActive.SupportedHtPhy.ChannelWidth = _pAd->MlmeAux.HtCapability.HtCapInfo.ChannelWidth;      \
	_pAd->StaActive.SupportedHtPhy.MimoPs = _pAd->MlmeAux.HtCapability.HtCapInfo.MimoPs;      \
	_pAd->StaActive.SupportedHtPhy.GF = _pAd->MlmeAux.HtCapability.HtCapInfo.GF;      \
	_pAd->StaActive.SupportedHtPhy.ShortGIfor20 = _pAd->MlmeAux.HtCapability.HtCapInfo.ShortGIfor20;      \
	_pAd->StaActive.SupportedHtPhy.ShortGIfor40 = _pAd->MlmeAux.HtCapability.HtCapInfo.ShortGIfor40;      \
	_pAd->StaActive.SupportedHtPhy.TxSTBC = _pAd->MlmeAux.HtCapability.HtCapInfo.TxSTBC;      \
	_pAd->StaActive.SupportedHtPhy.RxSTBC = _pAd->MlmeAux.HtCapability.HtCapInfo.RxSTBC;      \
	_pAd->StaActive.SupportedHtPhy.ExtChanOffset = _pAd->MlmeAux.AddHtInfo.AddHtInfo.ExtChanOffset;      \
	_pAd->StaActive.SupportedHtPhy.RecomWidth = _pAd->MlmeAux.AddHtInfo.AddHtInfo.RecomWidth;      \
	_pAd->StaActive.SupportedHtPhy.OperaionMode = _pAd->MlmeAux.AddHtInfo.AddHtInfo2.OperaionMode;      \
	_pAd->StaActive.SupportedHtPhy.NonGfPresent = _pAd->MlmeAux.AddHtInfo.AddHtInfo2.NonGfPresent;      \
	memmove((_pAd)->MacTab.Content[BSSID_WCID].HTCapability.MCSSet, (_pAd)->StaActive.SupportedPhyInfo.MCSSet, sizeof(u8) * 16);\
}

#define COPY_AP_HTSETTINGS_FROM_BEACON(_pAd, _pHtCapability)                                 \
{                                                                                       \
	_pAd->MacTab.Content[BSSID_WCID].AMsduSize = (u8)(_pHtCapability->HtCapInfo.AMsduSize);	\
	_pAd->MacTab.Content[BSSID_WCID].MmpsMode= (u8)(_pHtCapability->HtCapInfo.MimoPs);	\
	_pAd->MacTab.Content[BSSID_WCID].MaxRAmpduFactor = (u8)(_pHtCapability->HtCapParm.MaxRAmpduFactor);	\
}
#endif /* DOT11_N_SUPPORT */

#ifdef DOT11_VHT_AC
#define COPY_VHT_FROM_MLME_AUX_TO_ACTIVE_CFG(_pAd)                                 \
{                                                                                       \
}
#endif /* DOT11_VHT_AC */


/*
	Common fragment list structure -  Identical to the scatter gather frag list structure
*/
#define NIC_MAX_PHYS_BUF_COUNT              8

typedef struct _RTMP_SCATTER_GATHER_ELEMENT {
	void *Address;
	unsigned long Length;
	unsigned long *Reserved;
} RTMP_SCATTER_GATHER_ELEMENT, *PRTMP_SCATTER_GATHER_ELEMENT;

typedef struct _RTMP_SCATTER_GATHER_LIST {
	unsigned long NumberOfElements;
	unsigned long *Reserved;
	RTMP_SCATTER_GATHER_ELEMENT Elements[NIC_MAX_PHYS_BUF_COUNT];
} RTMP_SCATTER_GATHER_LIST, *PRTMP_SCATTER_GATHER_LIST;


/*
	Some utility macros
*/
#ifndef min
#define min(_a, _b)     (((_a) < (_b)) ? (_a) : (_b))
#endif

#ifndef max
#define max(_a, _b)     (((_a) > (_b)) ? (_a) : (_b))
#endif

#define GET_LNA_GAIN(_pAd)	((_pAd->LatchRfRegs.Channel <= 14) ? (_pAd->BLNAGain) : ((_pAd->LatchRfRegs.Channel <= 64) ? (_pAd->ALNAGain0) : ((_pAd->LatchRfRegs.Channel <= 128) ? (_pAd->ALNAGain1) : (_pAd->ALNAGain2))))

#define INC_COUNTER64(Val)          (Val.QuadPart++)

#define INFRA_ON(_p)                (OPSTATUS_TEST_FLAG(_p, fOP_STATUS_INFRA_ON))
#define ADHOC_ON(_p)                (OPSTATUS_TEST_FLAG(_p, fOP_STATUS_ADHOC_ON))
#define MONITOR_ON(_p)              (((_p)->StaCfg.BssType) == BSS_MONITOR)
#define IDLE_ON(_p)                 (!INFRA_ON(_p) && !ADHOC_ON(_p))

/* Check LEAP & CCKM flags */
#define LEAP_ON(_p)                 (((_p)->StaCfg.LeapAuthMode) == CISCO_AuthModeLEAP)
#define LEAP_CCKM_ON(_p)            ((((_p)->StaCfg.LeapAuthMode) == CISCO_AuthModeLEAP) && ((_p)->StaCfg.LeapAuthInfo.CCKM == true))

/* if orginal Ethernet frame contains no LLC/SNAP, then an extra LLC/SNAP encap is required */
#define EXTRA_LLCSNAP_ENCAP_FROM_PKT_START(_pBufVA, _pExtraLlcSnapEncap)		\
{																\
	if (((*(_pBufVA + 12) << 8) + *(_pBufVA + 13)) > 1500)		\
	{															\
		_pExtraLlcSnapEncap = SNAP_802_1H;						\
		if (memcmp(IPX, _pBufVA + 12, 2) == 0|| 			\
		    memcmp(APPLE_TALK, _pBufVA + 12, 2) == 0)		\
		{														\
			_pExtraLlcSnapEncap = SNAP_BRIDGE_TUNNEL;			\
		}														\
	}															\
	else														\
	{															\
		_pExtraLlcSnapEncap = NULL;								\
	}															\
}

/* New Define for new Tx Path. */
#define EXTRA_LLCSNAP_ENCAP_FROM_PKT_OFFSET(_pBufVA, _pExtraLlcSnapEncap)	\
{																\
	if (((*(_pBufVA) << 8) + *(_pBufVA + 1)) > 1500)			\
	{															\
		_pExtraLlcSnapEncap = SNAP_802_1H;						\
		if (memcmp(IPX, _pBufVA, 2) == 0|| 				\
		    memcmp(APPLE_TALK, _pBufVA, 2) == 0)			\
		{														\
			_pExtraLlcSnapEncap = SNAP_BRIDGE_TUNNEL;			\
		}														\
	}															\
	else														\
	{															\
		_pExtraLlcSnapEncap = NULL;								\
	}															\
}

#define MAKE_802_3_HEADER(_p, _pMac1, _pMac2, _pType)                   \
{                                                                       \
    memmove(_p, _pMac1, ETH_ALEN);                           \
    memmove((_p + ETH_ALEN), _pMac2, ETH_ALEN);          \
    memmove((_p + ETH_ALEN * 2), _pType, LENGTH_802_3_TYPE); \
}

/*
	if pData has no LLC/SNAP (neither RFC1042 nor Bridge tunnel),
		keep it that way.
	else if the received frame is LLC/SNAP-encaped IPX or APPLETALK,
		preserve the LLC/SNAP field
	else remove the LLC/SNAP field from the result Ethernet frame

	Patch for WHQL only, which did not turn on Netbios but use IPX within its payload
	Note:
		_pData & _DataSize may be altered (remove 8-byte LLC/SNAP) by this MACRO
		_pRemovedLLCSNAP: pointer to removed LLC/SNAP; NULL is not removed
*/
#define CONVERT_TO_802_3(_p8023hdr, _pDA, _pSA, _pData, _DataSize, _pRemovedLLCSNAP)      \
{                                                                       \
    char LLC_Len[2];                                                    \
                                                                        \
    _pRemovedLLCSNAP = NULL;                                            \
    if (memcmp(SNAP_802_1H, _pData, 6) == 0 ||                     \
        memcmp(SNAP_BRIDGE_TUNNEL, _pData, 6) == 0)                 \
    {                                                                   \
        u8 *pProto = _pData + 6;                                     \
                                                                        \
        if ((memcmp(IPX, pProto, 2) == 0 || memcmp(APPLE_TALK, pProto, 2) == 0) &&  \
            memcmp(SNAP_802_1H, _pData, 6) == 0)                    \
        {                                                               \
            LLC_Len[0] = (u8)(_DataSize >> 8);                       \
            LLC_Len[1] = (u8)(_DataSize & (256 - 1));                \
            MAKE_802_3_HEADER(_p8023hdr, _pDA, _pSA, LLC_Len);          \
        }                                                               \
        else                                                            \
        {                                                               \
            MAKE_802_3_HEADER(_p8023hdr, _pDA, _pSA, pProto);           \
            _pRemovedLLCSNAP = _pData;                                  \
            _DataSize -= LENGTH_802_1_H;                                \
            _pData += LENGTH_802_1_H;                                   \
        }                                                               \
    }                                                                   \
    else                                                                \
    {                                                                   \
        LLC_Len[0] = (u8)(_DataSize >> 8);                           \
        LLC_Len[1] = (u8)(_DataSize & (256 - 1));                    \
        MAKE_802_3_HEADER(_p8023hdr, _pDA, _pSA, LLC_Len);              \
    }                                                                   \
}

/*
	Enqueue this frame to MLME engine
	We need to enqueue the whole frame because MLME need to pass data type
	information from 802.11 header
*/
#ifdef RTMP_MAC_USB
#define REPORT_MGMT_FRAME_TO_MLME(_pAd, Wcid, _pFrame, _FrameSize, _Rssi0, _Rssi1, _Rssi2, _MinSNR, _OpMode)        \
{                                                                                       \
    u32 High32TSF=0, Low32TSF=0;                                                          \
    MlmeEnqueueForRecv(_pAd, Wcid, High32TSF, Low32TSF, (u8)_Rssi0, (u8)_Rssi1,(u8)_Rssi2,_FrameSize, _pFrame, (u8)_MinSNR, _OpMode);   \
}
#endif /* RTMP_MAC_USB */

#define MAC_ADDR_EQUAL(pAddr1,pAddr2)           (memcmp(pAddr1, pAddr2, ETH_ALEN) == 0)
#define SSID_EQUAL(ssid1, len1, ssid2, len2)    ((len1==len2) && (memcmp(ssid1, ssid2, len1) == 0))


#ifdef CONFIG_STA_SUPPORT
#define STA_EXTRA_SETTING(_pAd)

#define STA_PORT_SECURED(_pAd) \
{ \
	bool Cancelled; \
	(_pAd)->StaCfg.PortSecured = WPA_802_1X_PORT_SECURED; \
	RTMP_IndicateMediaState(_pAd, NdisMediaStateConnected); \
	NdisAcquireSpinLock(&((_pAd)->MacTabLock)); \
	(_pAd)->MacTab.Content[BSSID_WCID].PortSecured = (_pAd)->StaCfg.PortSecured; \
	(_pAd)->MacTab.Content[BSSID_WCID].PrivacyFilter = Ndis802_11PrivFilterAcceptAll;\
	NdisReleaseSpinLock(&(_pAd)->MacTabLock); \
	RTMPCancelTimer(&((_pAd)->Mlme.LinkDownTimer), &Cancelled);\
	STA_EXTRA_SETTING(_pAd); \
}
#endif /* CONFIG_STA_SUPPORT */

/* */
/*  Data buffer for DMA operation, the buffer must be contiguous physical memory */
/*  Both DMA to / from CPU use the same structure. */
/* */
typedef struct _RTMP_DMABUF {
	unsigned long AllocSize;
	void *AllocVa;		/* TxBuf virtual address */
	NDIS_PHYSICAL_ADDRESS AllocPa;	/* TxBuf physical address */
} RTMP_DMABUF, *PRTMP_DMABUF;

/* */
/* Control block (Descriptor) for all ring descriptor DMA operation, buffer must be */
/* contiguous physical memory. NDIS_PACKET stored the binding Rx packet descriptor */
/* which won't be released, driver has to wait until upper layer return the packet */
/* before giveing up this rx ring descriptor to ASIC. NDIS_BUFFER is assocaited pair */
/* to describe the packet buffer. For Tx, NDIS_PACKET stored the tx packet descriptor */
/* which driver should ACK upper layer when the tx is physically done or failed. */
/* */
typedef struct _RTMP_DMACB {
	unsigned long AllocSize;	/* Control block size */
	void *AllocVa;		/* Control block virtual address */
	NDIS_PHYSICAL_ADDRESS AllocPa;	/* Control block physical address */
	struct sk_buff * pNdisPacket;
	struct sk_buff * pNextNdisPacket;

	RTMP_DMABUF DmaBuf;	/* Associated DMA buffer structure */
#ifdef CACHE_LINE_32B
	RXD_STRUC LastBDInfo;
#endif /* CACHE_LINE_32B */
} RTMP_DMACB, *PRTMP_DMACB;

typedef struct _RTMP_TX_RING {
	RTMP_DMACB Cell[TX_RING_SIZE];
	u32 TxCpuIdx;
	u32 TxDmaIdx;
	u32 TxSwFreeIdx;	/* software next free tx index */
} RTMP_TX_RING, *PRTMP_TX_RING;

typedef struct _RTMP_RX_RING {
	RTMP_DMACB Cell[RX_RING_SIZE];
	u32 RxCpuIdx;
	u32 RxDmaIdx;
	int32_t RxSwReadIdx;	/* software next read index */
} RTMP_RX_RING, *PRTMP_RX_RING;

typedef struct _RTMP_MGMT_RING {
	RTMP_DMACB Cell[MGMT_RING_SIZE];
	u32 TxCpuIdx;
	u32 TxDmaIdx;
	u32 TxSwFreeIdx;	/* software next free tx index */
} RTMP_MGMT_RING, *PRTMP_MGMT_RING;

typedef struct _RTMP_CTRL_RING {
	RTMP_DMACB Cell[16];
	u32 TxCpuIdx;
	u32 TxDmaIdx;
	u32 TxSwFreeIdx;	/* software next free tx index */
} RTMP_CTRL_RING, *PRTMP_CTRL_RING;

/* */
/*  Statistic counter structure */
/* */
typedef struct _COUNTER_802_3 {
	/* General Stats */
	unsigned long GoodTransmits;
	unsigned long GoodReceives;
	unsigned long TxErrors;
	unsigned long RxErrors;
	unsigned long RxNoBuffer;

	/* Ethernet Stats */
	unsigned long RcvAlignmentErrors;
	unsigned long OneCollision;
	unsigned long MoreCollisions;

} COUNTER_802_3, *PCOUNTER_802_3;

typedef struct _COUNTER_802_11 {
	unsigned long Length;
/*	LARGE_INTEGER   LastTransmittedFragmentCount; */
	LARGE_INTEGER TransmittedFragmentCount;
	LARGE_INTEGER MulticastTransmittedFrameCount;
	LARGE_INTEGER FailedCount;
	LARGE_INTEGER RetryCount;
	LARGE_INTEGER MultipleRetryCount;
	LARGE_INTEGER RTSSuccessCount;
	LARGE_INTEGER RTSFailureCount;
	LARGE_INTEGER ACKFailureCount;
	LARGE_INTEGER FrameDuplicateCount;
	LARGE_INTEGER ReceivedFragmentCount;
	LARGE_INTEGER MulticastReceivedFrameCount;
	LARGE_INTEGER FCSErrorCount;
	LARGE_INTEGER TransmittedFrameCount;
	LARGE_INTEGER WEPUndecryptableCount;
	LARGE_INTEGER TransmitCountFrmOs;
} COUNTER_802_11, *PCOUNTER_802_11;

typedef struct _COUNTER_RALINK {
	u32 OneSecStart;	/* for one sec count clear use */
	u32 OneSecBeaconSentCnt;
	u32 OneSecFalseCCACnt;	/* CCA error count, for debug purpose, might move to global counter */
	u32 OneSecRxFcsErrCnt;	/* CRC error */
	u32 OneSecRxOkCnt;	/* RX without error */
	u32 OneSecTxFailCount;
	u32 OneSecTxNoRetryOkCount;
	u32 OneSecTxRetryOkCount;
	u32 OneSecRxOkDataCnt;	/* unicast-to-me DATA frame count */
	u32 OneSecTransmittedByteCount;	/* both successful and failure, used to calculate TX throughput */

	unsigned long OneSecOsTxCount[NUM_OF_TX_RING];
	unsigned long OneSecDmaDoneCount[NUM_OF_TX_RING];
	u32 OneSecTxDoneCount;
	unsigned long OneSecRxCount;
	u32 OneSecReceivedByteCount;
	u32 OneSecTxAggregationCount;
	u32 OneSecRxAggregationCount;
	u32 OneSecEnd;	/* for one sec count clear use */

	unsigned long TransmittedByteCount;	/* both successful and failure, used to calculate TX throughput */
	unsigned long ReceivedByteCount;	/* both CRC okay and CRC error, used to calculate RX throughput */
	unsigned long BadCQIAutoRecoveryCount;
	unsigned long PoorCQIRoamingCount;
	unsigned long MgmtRingFullCount;
	unsigned long RxCountSinceLastNULL;
	unsigned long RxCount;
	unsigned long KickTxCount;
	LARGE_INTEGER RealFcsErrCount;
	unsigned long PendingNdisPacketCount;
	unsigned long FalseCCACnt;                    /* CCA error count */

	u32 LastOneSecTotalTxCount;	/* OneSecTxNoRetryOkCount + OneSecTxRetryOkCount + OneSecTxFailCount */
	u32 LastOneSecRxOkDataCnt;	/* OneSecRxOkDataCnt */
	unsigned long DuplicateRcv;
	unsigned long TxAggCount;
	unsigned long TxNonAggCount;
	unsigned long TxAgg1MPDUCount;
	unsigned long TxAgg2MPDUCount;
	unsigned long TxAgg3MPDUCount;
	unsigned long TxAgg4MPDUCount;
	unsigned long TxAgg5MPDUCount;
	unsigned long TxAgg6MPDUCount;
	unsigned long TxAgg7MPDUCount;
	unsigned long TxAgg8MPDUCount;
	unsigned long TxAgg9MPDUCount;
	unsigned long TxAgg10MPDUCount;
	unsigned long TxAgg11MPDUCount;
	unsigned long TxAgg12MPDUCount;
	unsigned long TxAgg13MPDUCount;
	unsigned long TxAgg14MPDUCount;
	unsigned long TxAgg15MPDUCount;
	unsigned long TxAgg16MPDUCount;

	LARGE_INTEGER TransmittedOctetsInAMSDU;
	LARGE_INTEGER TransmittedAMSDUCount;
	LARGE_INTEGER ReceivedOctesInAMSDUCount;
	LARGE_INTEGER ReceivedAMSDUCount;
	LARGE_INTEGER TransmittedAMPDUCount;
	LARGE_INTEGER TransmittedMPDUsInAMPDUCount;
	LARGE_INTEGER TransmittedOctetsInAMPDUCount;
	LARGE_INTEGER MPDUInReceivedAMPDUCount;

	unsigned long PhyErrCnt;
	unsigned long PlcpErrCnt;
} COUNTER_RALINK, *PCOUNTER_RALINK;

typedef struct _COUNTER_DRS {
	/* to record the each TX rate's quality. 0 is best, the bigger the worse. */
	unsigned short TxQuality[MAX_TX_RATE_INDEX+1];
	u8 PER[MAX_TX_RATE_INDEX+1];
	u8 TxRateUpPenalty;	/* extra # of second penalty due to last unstable condition */
	unsigned long CurrTxRateStableTime;	/* # of second in current TX rate */
	/*bool         fNoisyEnvironment; */
	bool fLastSecAccordingRSSI;
	u8 LastSecTxRateChangeAction;	/* 0: no change, 1:rate UP, 2:rate down */
	u8 LastTimeTxRateChangeAction;	/*Keep last time value of LastSecTxRateChangeAction */
	unsigned long LastTxOkCount;
} COUNTER_DRS, *PCOUNTER_DRS;

/***************************************************************************
  *	security key related data structure
  **************************************************************************/

/* structure to define WPA Group Key Rekey Interval */
typedef struct __attribute__ ((packed)) _RT_802_11_WPA_REKEY {
	unsigned long ReKeyMethod;	/* mechanism for rekeying: 0:disable, 1: time-based, 2: packet-based */
	unsigned long ReKeyInterval;	/* time-based: seconds, packet-based: kilo-packets */
} RT_WPA_REKEY,*PRT_WPA_REKEY, RT_802_11_WPA_REKEY, *PRT_802_11_WPA_REKEY;


#ifdef RTMP_MAC_USB
/***************************************************************************
  *	RTUSB I/O related data structure
  **************************************************************************/

/* for USB interface, avoid in interrupt when write key */
typedef struct RT_ADD_PAIRWISE_KEY_ENTRY {
	u8 MacAddr[6];
	unsigned short MacTabMatchWCID;	/* ASIC */
	CIPHER_KEY CipherKey;
} RT_ADD_PAIRWISE_KEY_ENTRY,*PRT_ADD_PAIRWISE_KEY_ENTRY;


/* Cipher suite type for mixed mode group cipher, P802.11i-2004 */
typedef enum _RT_802_11_CIPHER_SUITE_TYPE {
	Cipher_Type_NONE,
	Cipher_Type_WEP40,
	Cipher_Type_TKIP,
	Cipher_Type_RSVD,
	Cipher_Type_CCMP,
	Cipher_Type_WEP104
} RT_802_11_CIPHER_SUITE_TYPE, *PRT_802_11_CIPHER_SUITE_TYPE;
#endif /* RTMP_MAC_USB */

typedef struct {
	u8 Addr[ETH_ALEN];
	u8 ErrorCode[2];	/*00 01-Invalid authentication type */
	/*00 02-Authentication timeout */
	/*00 03-Challenge from AP failed */
	/*00 04-Challenge to AP failed */
	bool Reported;
} ROGUEAP_ENTRY, *PROGUEAP_ENTRY;

typedef struct {
	u8 RogueApNr;
	ROGUEAP_ENTRY RogueApEntry[MAX_LEN_OF_BSS_TABLE];
} ROGUEAP_TABLE, *PROGUEAP_TABLE;

/*
  *	Fragment Frame structure
  */
typedef struct _FRAGMENT_FRAME {
	struct sk_buff * pFragPacket;
	unsigned long RxSize;
	unsigned short Sequence;
	unsigned short LastFrag;
	unsigned long Flags;		/* Some extra frame information. bit 0: LLC presented */
} FRAGMENT_FRAME, *PFRAGMENT_FRAME;


/* */
/* Tkip Key structure which RC4 key & MIC calculation */
/* */
typedef struct _TKIP_KEY_INFO {
	unsigned int nBytesInM;		/* # bytes in M for MICKEY */
	unsigned long IV16;
	unsigned long IV32;
	unsigned long K0;		/* for MICKEY Low */
	unsigned long K1;		/* for MICKEY Hig */
	unsigned long L;		/* Current state for MICKEY */
	unsigned long R;		/* Current state for MICKEY */
	unsigned long M;		/* Message accumulator for MICKEY */
	u8 RC4KEY[16];
	u8 MIC[8];
} TKIP_KEY_INFO, *PTKIP_KEY_INFO;


/* */
/* Private / Misc data, counters for driver internal use */
/* */
typedef struct __PRIVATE_STRUC {
	unsigned int SystemResetCnt;	/* System reset counter */
	unsigned int TxRingFullCnt;	/* Tx ring full occurrance number */
	unsigned int PhyRxErrCnt;	/* PHY Rx error count, for debug purpose, might move to global counter */
	/* Variables for WEP encryption / decryption in rtmp_wep.c */
	/* Tkip stuff */
	TKIP_KEY_INFO Tx;
	TKIP_KEY_INFO Rx;
} PRIVATE_STRUC, *PPRIVATE_STRUC;


/***************************************************************************
  *	Channel and BBP related data structures
  **************************************************************************/
/* structure to tune BBP R66 (BBP TUNING) */
typedef struct _BBP_R66_TUNING {
	bool bEnable;
	unsigned short FalseCcaLowerThreshold;	/* default 100 */
	unsigned short FalseCcaUpperThreshold;	/* default 512 */
	u8 R66Delta;
	u8 R66CurrentValue;
	bool R66LowerUpperSelect;	/*Before LinkUp, Used LowerBound or UpperBound as R66 value. */
} BBP_R66_TUNING, *PBBP_R66_TUNING;


#ifdef DOT11_N_SUPPORT
#ifdef DOT11N_DRAFT3
#define EFFECTED_CH_SECONDARY 0x1
#define EFFECTED_CH_PRIMARY	0x2
#define EFFECTED_CH_LEGACY		0x4
#endif /* DOT11N_DRAFT3 */
#endif /* DOT11_N_SUPPORT */

/* structure to store channel TX power */
typedef struct _CHANNEL_TX_POWER {
	unsigned short RemainingTimeForUse;	/*unit: sec */
	u8 Channel;
#ifdef DOT11N_DRAFT3
	bool bEffectedChannel;	/* For BW 40 operating in 2.4GHz , the "effected channel" is the channel that is covered in 40Mhz. */
#endif /* DOT11N_DRAFT3 */
	CHAR Power;
	CHAR Power2;
#ifdef DOT11N_SS3_SUPPORT
	CHAR Power3;
#endif /* DOT11N_SS3_SUPPORT */
	u8 MaxTxPwr;
	u8 DfsReq;
	u8 RegulatoryDomain;

/*
	Channel property:

	CHANNEL_DISABLED: The channel is disabled.
	CHANNEL_PASSIVE_SCAN: Only passive scanning is allowed.
	CHANNEL_NO_IBSS: IBSS is not allowed.
	CHANNEL_RADAR: Radar detection is required.
	CHANNEL_NO_FAT_ABOVE: Extension channel above this channel is not allowed.
	CHANNEL_NO_FAT_BELOW: Extension channel below this channel is not allowed.
	CHANNEL_40M_CAP: 40 BW channel group
 */
#define CHANNEL_DEFAULT_PROP	0x00
#define CHANNEL_DISABLED		0x01	/* no use */
#define CHANNEL_PASSIVE_SCAN	0x02
#define CHANNEL_NO_IBSS			0x04
#define CHANNEL_RADAR			0x08
#define CHANNEL_NO_FAT_ABOVE	0x10
#define CHANNEL_NO_FAT_BELOW	0x20
#define CHANNEL_40M_CAP			0x40

	u8 Flags;

} CHANNEL_TX_POWER, *PCHANNEL_TX_POWER;

/* Channel list subset */
typedef struct _CHANNEL_LIST_SUB {
	u8 Channel;
	u8 IdxMap; /* Index mapping to original channel list */
} CHANNEL_LIST_SUB, *PCHANNEL_LIST_SUB;


typedef struct _SOFT_RX_ANT_DIVERSITY_STRUCT {
	u8 EvaluatePeriod;	/* 0:not evalute status, 1: evaluate status, 2: switching status */
	u8 EvaluateStableCnt;
	u8 Pair1PrimaryRxAnt;	/* 0:Ant-E1, 1:Ant-E2 */
	u8 Pair1SecondaryRxAnt;	/* 0:Ant-E1, 1:Ant-E2 */
#ifdef CONFIG_STA_SUPPORT
	short Pair1AvgRssi[2];	/* AvgRssi[0]:E1, AvgRssi[1]:E2 */
	short Pair2AvgRssi[2];	/* AvgRssi[0]:E3, AvgRssi[1]:E4 */
#endif /* CONFIG_STA_SUPPORT */
	short Pair1LastAvgRssi;	/* */
	short Pair2LastAvgRssi;	/* */
	unsigned long RcvPktNumWhenEvaluate;
	bool FirstPktArrivedWhenEvaluate;
} SOFT_RX_ANT_DIVERSITY, *PSOFT_RX_ANT_DIVERSITY;

typedef enum _ABGBAND_STATE_ {
	UNKNOWN_BAND,
	BG_BAND,
	A_BAND,
} ABGBAND_STATE;

#ifdef CONFIG_STA_SUPPORT
#endif /* CONFIG_STA_SUPPORT */
/***************************************************************************
  *	structure for MLME state machine
  **************************************************************************/
typedef struct _MLME_STRUCT {
#ifdef CONFIG_STA_SUPPORT
	/* STA state machines */
	STATE_MACHINE CntlMachine;
	STATE_MACHINE AssocMachine;
	STATE_MACHINE AuthMachine;
	STATE_MACHINE AuthRspMachine;
	STATE_MACHINE SyncMachine;
	STATE_MACHINE WpaPskMachine;
	STATE_MACHINE LeapMachine;
	STATE_MACHINE_FUNC AssocFunc[ASSOC_FUNC_SIZE];
	STATE_MACHINE_FUNC AuthFunc[AUTH_FUNC_SIZE];
	STATE_MACHINE_FUNC AuthRspFunc[AUTH_RSP_FUNC_SIZE];
	STATE_MACHINE_FUNC SyncFunc[SYNC_FUNC_SIZE];

#endif /* CONFIG_STA_SUPPORT */
	STATE_MACHINE_FUNC ActFunc[ACT_FUNC_SIZE];
	/* Action */
	STATE_MACHINE ActMachine;


#ifdef QOS_DLS_SUPPORT
	STATE_MACHINE DlsMachine;
	STATE_MACHINE_FUNC DlsFunc[DLS_FUNC_SIZE];
#endif /* QOS_DLS_SUPPORT */



	/* common WPA state machine */
	STATE_MACHINE WpaMachine;
	STATE_MACHINE_FUNC WpaFunc[WPA_FUNC_SIZE];


	unsigned long ChannelQuality;	/* 0..100, Channel Quality Indication for Roaming */
	unsigned long Now32;		/* latch the value of NdisGetSystemUpTime() */
	unsigned long LastSendNULLpsmTime;

	bool bRunning;
	spinlock_t TaskLock;
	MLME_QUEUE Queue;

	unsigned int ShiftReg;

	RALINK_TIMER_STRUCT PeriodicTimer;
	RALINK_TIMER_STRUCT APSDPeriodicTimer;
	RALINK_TIMER_STRUCT LinkDownTimer;
	RALINK_TIMER_STRUCT LinkUpTimer;
	unsigned long PeriodicRound;
	unsigned long GPIORound;
	unsigned long OneSecPeriodicRound;

	u8 RealRxPath;
	bool bLowThroughput;
	bool bEnableAutoAntennaCheck;
	RALINK_TIMER_STRUCT RxAntEvalTimer;


#ifdef RTMP_MAC_USB
	RALINK_TIMER_STRUCT AutoWakeupTimer;
	bool AutoWakeupTimerRunning;
#endif /* RTMP_MAC_USB */
} MLME_STRUCT, *PMLME_STRUCT;

#ifdef DOT11_N_SUPPORT
/***************************************************************************
  *	802.11 N related data structures
  **************************************************************************/
struct reordering_mpdu {
	struct reordering_mpdu *next;
	struct sk_buff * pPacket;	/* coverted to 802.3 frame */
	int Sequence;		/* sequence number of MPDU */
	bool bAMSDU;
	u8 				OpMode;
};

struct reordering_list {
	struct reordering_mpdu *next;
	int qlen;
};

struct reordering_mpdu_pool {
	void *mem;
	spinlock_t lock;
	struct reordering_list freelist;
};

typedef enum _REC_BLOCKACK_STATUS {
	Recipient_NONE = 0,
	Recipient_USED,
	Recipient_HandleRes,
	Recipient_Accept
} REC_BLOCKACK_STATUS, *PREC_BLOCKACK_STATUS;

typedef enum _ORI_BLOCKACK_STATUS {
	Originator_NONE = 0,
	Originator_USED,
	Originator_WaitRes,
	Originator_Done
} ORI_BLOCKACK_STATUS, *PORI_BLOCKACK_STATUS;

typedef struct _BA_ORI_ENTRY {
	u8 Wcid;
	u8 TID;
	u8 BAWinSize;
	u8 Token;
/* Sequence is to fill every outgoing QoS DATA frame's sequence field in 802.11 header. */
	unsigned short Sequence;
	unsigned short TimeOutValue;
	ORI_BLOCKACK_STATUS ORI_BA_Status;
	RALINK_TIMER_STRUCT ORIBATimer;
	void *pAdapter;
} BA_ORI_ENTRY, *PBA_ORI_ENTRY;

typedef struct _BA_REC_ENTRY {
	u8 Wcid;
	u8 TID;
	u8 BAWinSize;	/* 7.3.1.14. each buffer is capable of holding a max AMSDU or MSDU. */
	/*u8 NumOfRxPkt; */
	/*u8    Curindidx; // the head in the RX reordering buffer */
	unsigned short LastIndSeq;
/*	unsigned short		LastIndSeqAtTimer; */
	unsigned short TimeOutValue;
	RALINK_TIMER_STRUCT RECBATimer;
	unsigned long LastIndSeqAtTimer;
	unsigned long nDropPacket;
	unsigned long rcvSeq;
	REC_BLOCKACK_STATUS REC_BA_Status;
/*	u8 RxBufIdxUsed; */
	/* corresponding virtual address for RX reordering packet storage. */
	/*RTMP_REORDERDMABUF MAP_RXBuf[MAX_RX_REORDERBUF]; */
	spinlock_t RxReRingLock;	/* Rx Ring spinlock */
/*	struct _BA_REC_ENTRY *pNext; */
	void *pAdapter;
	struct reordering_list list;
} BA_REC_ENTRY, *PBA_REC_ENTRY;


typedef struct {
	unsigned long numAsRecipient;	/* I am recipient of numAsRecipient clients. These client are in the BARecEntry[] */
	unsigned long numAsOriginator;	/* I am originator of   numAsOriginator clients. These clients are in the BAOriEntry[] */
	unsigned long numDoneOriginator;	/* count Done Originator sessions */
	BA_ORI_ENTRY BAOriEntry[MAX_LEN_OF_BA_ORI_TABLE];
	BA_REC_ENTRY BARecEntry[MAX_LEN_OF_BA_REC_TABLE];
} BA_TABLE, *PBA_TABLE;

/*For QureyBATableOID use; */
typedef struct __attribute__ ((packed)) _OID_BA_REC_ENTRY {
	u8 MACAddr[ETH_ALEN];
	u8 BaBitmap;		/* if (BaBitmap&(1<<TID)), this session with{MACAddr, TID}exists, so read BufSize[TID] for BufferSize */
	u8 rsv;
	u8 BufSize[8];
	REC_BLOCKACK_STATUS REC_BA_Status[8];
} OID_BA_REC_ENTRY, *POID_BA_REC_ENTRY;

/*For QureyBATableOID use; */
typedef struct __attribute__ ((packed)) _OID_BA_ORI_ENTRY {
	u8 MACAddr[ETH_ALEN];
	u8 BaBitmap;		/* if (BaBitmap&(1<<TID)), this session with{MACAddr, TID}exists, so read BufSize[TID] for BufferSize, read ORI_BA_Status[TID] for status */
	u8 rsv;
	u8 BufSize[8];
	ORI_BLOCKACK_STATUS ORI_BA_Status[8];
} OID_BA_ORI_ENTRY, *POID_BA_ORI_ENTRY;

typedef struct _QUERYBA_TABLE {
	OID_BA_ORI_ENTRY BAOriEntry[32];
	OID_BA_REC_ENTRY BARecEntry[32];
	u8 OriNum;		/* Number of below BAOriEntry */
	u8 RecNum;		/* Number of below BARecEntry */
} QUERYBA_TABLE, *PQUERYBA_TABLE;

typedef union _BACAP_STRUC {
#ifdef RT_BIG_ENDIAN
	struct {
		u32:4;
		u32 b2040CoexistScanSup:1;	/*As Sta, support do 2040 coexistence scan for AP. As Ap, support monitor trigger event to check if can use BW 40MHz. */
		u32 bHtAdhoc:1;	/* adhoc can use ht rate. */
		u32 MMPSmode:2;	/* MIMO power save more, 0:static, 1:dynamic, 2:rsv, 3:mimo enable */
		u32 AmsduSize:1;	/* 0:3839, 1:7935 bytes. unsigned int  MSDUSizeToBytes[]        = { 3839, 7935}; */
		u32 AmsduEnable:1;	/*Enable AMSDU transmisstion */
		u32 MpduDensity:3;
		u32 Policy:2;	/* 0: DELAY_BA 1:IMMED_BA  (//BA Policy subfiled value in ADDBA frame)   2:BA-not use */
		u32 AutoBA:1;	/* automatically BA */
		u32 TxBAWinLimit:8;
		u32 RxBAWinLimit:8;
	} field;
#else
	struct {
		u32 RxBAWinLimit:8;
		u32 TxBAWinLimit:8;
		u32 AutoBA:1;	/* automatically BA */
		u32 Policy:2;	/* 0: DELAY_BA 1:IMMED_BA  (//BA Policy subfiled value in ADDBA frame)   2:BA-not use */
		u32 MpduDensity:3;
		u32 AmsduEnable:1;	/*Enable AMSDU transmisstion */
		u32 AmsduSize:1;	/* 0:3839, 1:7935 bytes. unsigned int  MSDUSizeToBytes[]        = { 3839, 7935}; */
		u32 MMPSmode:2;	/* MIMO power save more, 0:static, 1:dynamic, 2:rsv, 3:mimo enable */
		u32 bHtAdhoc:1;	/* adhoc can use ht rate. */
		u32 b2040CoexistScanSup:1;	/*As Sta, support do 2040 coexistence scan for AP. As Ap, support monitor trigger event to check if can use BW 40MHz. */
		 u32:4;
	} field;
#endif
	u32 word;
} BACAP_STRUC, *PBACAP_STRUC;

typedef struct {
	bool IsRecipient;
	u8 MACAddr[ETH_ALEN];
	u8 TID;
	u8 nMSDU;
	unsigned short TimeOut;
	bool bAllTid;	/* If True, delete all TID for BA sessions with this MACaddr. */
} OID_ADD_BA_ENTRY, *POID_ADD_BA_ENTRY;

#ifdef DOT11N_DRAFT3
typedef enum _BSS2040COEXIST_FLAG {
	BSS_2040_COEXIST_DISABLE = 0,
	BSS_2040_COEXIST_TIMER_FIRED = 1,
	BSS_2040_COEXIST_INFO_SYNC = 2,
	BSS_2040_COEXIST_INFO_NOTIFY = 4,
} BSS2040COEXIST_FLAG;

typedef struct _BssCoexChRange_ {
	u8 primaryCh;
	u8 secondaryCh;
	u8 effectChStart;
	u8 effectChEnd;
} BSS_COEX_CH_RANGE;
#endif /* DOT11N_DRAFT3 */

#define IS_HT_STA(_pMacEntry)	\
	(_pMacEntry->MaxHTPhyMode.field.MODE >= MODE_HTMIX)

#define IS_HT_RATE(_pMacEntry)	\
	(_pMacEntry->HTPhyMode.field.MODE >= MODE_HTMIX)

#define PEER_IS_HT_RATE(_pMacEntry)	\
	(_pMacEntry->HTPhyMode.field.MODE >= MODE_HTMIX)

#endif /* DOT11_N_SUPPORT */

/*This structure is for all 802.11n card InterOptibilityTest action. Reset all Num every n second.  (Details see MLMEPeriodic) */
typedef struct _IOT_STRUC {
	bool bRTSLongProtOn;
#ifdef CONFIG_STA_SUPPORT
	bool bLastAtheros;
	bool bCurrentAtheros;
	bool bNowAtherosBurstOn;
	bool bNextDisableRxBA;
	bool bToggle;
#endif /* CONFIG_STA_SUPPORT */
} IOT_STRUC, *PIOT_STRUC;

/* This is the registry setting for 802.11n transmit setting.  Used in advanced page. */
typedef union _REG_TRANSMIT_SETTING {
#ifdef RT_BIG_ENDIAN
	struct {
		u32 rsv:13;
		u32 EXTCHA:2;
		u32 HTMODE:1;
		u32 TRANSNO:2;
		u32 STBC:1;	/*SPACE */
		u32 ShortGI:1;
		u32 BW:1;	/*channel bandwidth 20MHz or 40 MHz */
		u32 TxBF:1;	/* 3*3 */
		u32 ITxBfEn:1;
		u32 rsv0:9;
		/*u32  MCS:7;                 // MCS */
		/*u32  PhyMode:4; */
	} field;
#else
	struct {
		/*u32  PhyMode:4; */
		/*u32  MCS:7;                 // MCS */
		u32 rsv0:9;
		u32 ITxBfEn:1;
		u32 TxBF:1;
		u32 BW:1;	/*channel bandwidth 20MHz or 40 MHz */
		u32 ShortGI:1;
		u32 STBC:1;	/*SPACE */
		u32 TRANSNO:2;
		u32 HTMODE:1;
		u32 EXTCHA:2;
		u32 rsv:13;
	} field;
#endif
	u32 word;
} REG_TRANSMIT_SETTING, *PREG_TRANSMIT_SETTING;


typedef union _DESIRED_TRANSMIT_SETTING {
#ifdef RT_BIG_ENDIAN
	struct {
		unsigned short rsv:3;
		unsigned short FixedTxMode:2;	/* If MCS isn't AUTO, fix rate in CCK, OFDM or HT mode. */
		unsigned short PhyMode:4;
		unsigned short MCS:7;	/* MCS */
	} field;
#else
	struct {
		unsigned short MCS:7;	/* MCS */
		unsigned short PhyMode:4;
		unsigned short FixedTxMode:2;	/* If MCS isn't AUTO, fix rate in CCK, OFDM or HT mode. */
		unsigned short rsv:3;
	} field;
#endif
	unsigned short word;
} DESIRED_TRANSMIT_SETTING, *PDESIRED_TRANSMIT_SETTING;


struct hw_setting{
	u8 prim_ch;
	u8 cent_ch;
	u8 bbp_bw;
	u8 rf_band;
	u8 cur_ch_pwr[3];
};


struct wifi_dev{
	NDIS_802_11_AUTHENTICATION_MODE AuthMode;
	NDIS_802_11_WEP_STATUS WepStatus;
	NDIS_802_11_WEP_STATUS GroupKeyWepStatus;
	WPA_MIX_PAIR_CIPHER WpaMixPairCipher;

	RT_PHY_INFO DesiredHtPhyInfo;
	DESIRED_TRANSMIT_SETTING DesiredTransmitSetting;	/* Desired transmit setting. this is for reading registry setting only. not useful. */
	bool bAutoTxRateSwitch;

	bool bWmmCapable;	/* 0:disable WMM, 1:enable WMM */

	HTTRANSMIT_SETTING HTPhyMode, MaxHTPhyMode, MinHTPhyMode;
};


#ifdef RTMP_MAC_USB
/***************************************************************************
  *	USB-based chip Beacon related data structures
  **************************************************************************/
#define BEACON_BITMAP_MASK		0xff
typedef struct _BEACON_SYNC_STRUCT_ {
	u8 BeaconBuf[HW_BEACON_MAX_NUM][HW_BEACON_OFFSET];
	u8 *BeaconTxWI[HW_BEACON_MAX_NUM];
	unsigned long TimIELocationInBeacon[HW_BEACON_MAX_NUM];
	unsigned long CapabilityInfoLocationInBeacon[HW_BEACON_MAX_NUM];
	bool EnableBeacon;	/* trigger to enable beacon transmission. */
	u8 BeaconBitMap;	/* NOTE: If the MAX_MBSSID_NUM is larger than 8, this parameter need to change. */
	u8 DtimBitOn;	/* NOTE: If the MAX_MBSSID_NUM is larger than 8, this parameter need to change. */
} BEACON_SYNC_STRUCT;
#endif /* RTMP_MAC_USB */

/***************************************************************************
  *	Multiple SSID related data structures
  **************************************************************************/
#define WLAN_MAX_NUM_OF_TIM			((MAX_LEN_OF_MAC_TABLE >> 3) + 1)	/* /8 + 1 */
#define WLAN_CT_TIM_BCMC_OFFSET		0	/* unit: 32B */

/* clear bcmc TIM bit */
#define WLAN_MR_TIM_BCMC_CLEAR(apidx) \
	pAd->ApCfg.MBSSID[apidx].TimBitmaps[WLAN_CT_TIM_BCMC_OFFSET] &= ~NUM_BIT8[0];

/* set bcmc TIM bit */
#define WLAN_MR_TIM_BCMC_SET(apidx) \
	pAd->ApCfg.MBSSID[apidx].TimBitmaps[WLAN_CT_TIM_BCMC_OFFSET] |= NUM_BIT8[0];

/* clear a station PS TIM bit */
#define WLAN_MR_TIM_BIT_CLEAR(ad_p, apidx, wcid) \
	{	u8 tim_offset = wcid >> 3; \
		u8 bit_offset = wcid & 0x7; \
		ad_p->ApCfg.MBSSID[apidx].TimBitmaps[tim_offset] &= (~NUM_BIT8[bit_offset]); }

/* set a station PS TIM bit */
#define WLAN_MR_TIM_BIT_SET(ad_p, apidx, wcid) \
	{	u8 tim_offset = wcid >> 3; \
		u8 bit_offset = wcid & 0x7; \
		ad_p->ApCfg.MBSSID[apidx].TimBitmaps[tim_offset] |= NUM_BIT8[bit_offset]; }




/* configuration common to OPMODE_AP as well as OPMODE_STA */
struct common_config {
	bool bCountryFlag;
	u8 CountryCode[3];
#ifdef EXT_BUILD_CHANNEL_LIST
	u8 Geography;
	u8 DfsType;
	u8 *pChDesp;
#endif				/* EXT_BUILD_CHANNEL_LIST */
	u8 CountryRegion;	/* Enum of country region, 0:FCC, 1:IC, 2:ETSI, 3:SPAIN, 4:France, 5:MKK, 6:MKK1, 7:Israel */
	u8 CountryRegionForABand;	/* Enum of country region for A band */
	u8 PhyMode;
	u8 cfg_wmode;
	u8 SavedPhyMode;
	unsigned short Dsifs;		/* in units of usec */
	unsigned long PacketFilter;	/* Packet filter for receiving */
	u8 RegulatoryClass[MAX_NUM_OF_REGULATORY_CLASS];

	CHAR Ssid[MAX_LEN_OF_SSID];	/* NOT NULL-terminated */
	u8 SsidLen;		/* the actual ssid length in used */
	u8 LastSsidLen;	/* the actual ssid length in used */
	CHAR LastSsid[MAX_LEN_OF_SSID];	/* NOT NULL-terminated */
	u8 LastBssid[ETH_ALEN];

	u8 Bssid[ETH_ALEN];
	unsigned short BeaconPeriod;
	u8 Channel;
	u8 CentralChannel;	/* Central Channel when using 40MHz is indicating. not real channel. */

	u8 SupRate[MAX_LEN_OF_SUPPORTED_RATES];
	u8 SupRateLen;
	u8 ExtRate[MAX_LEN_OF_SUPPORTED_RATES];
	u8 ExtRateLen;
	u8 DesireRate[MAX_LEN_OF_SUPPORTED_RATES];	/* OID_802_11_DESIRED_RATES */
	u8 MaxDesiredRate;
	u8 ExpectedACKRate[MAX_LEN_OF_SUPPORTED_RATES];

	unsigned long BasicRateBitmap;	/* backup basic ratebitmap */
	unsigned long BasicRateBitmapOld;	/* backup basic ratebitmap */

	bool bInServicePeriod;


	bool bAPSDAC_BE;
	bool bAPSDAC_BK;
	bool bAPSDAC_VI;
	bool bAPSDAC_VO;


	/* because TSPEC can modify the APSD flag, we need to keep the APSD flag
	   requested in association stage from the station;
	   we need to recover the APSD flag after the TSPEC is deleted. */
	bool bACMAPSDBackup[4];	/* for delivery-enabled & trigger-enabled both */
	bool bACMAPSDTr[4];	/* no use */
	u8 MaxSPLength;

	bool bNeedSendTriggerFrame;
	bool bAPSDForcePowerSave;	/* Force power save mode, should only use in APSD-STAUT */
	unsigned long TriggerTimerCount;
	u8 BBPCurrentBW;	/* BW_10, BW_20, BW_40, BW_80 */
	REG_TRANSMIT_SETTING RegTransmitSetting;	/*registry transmit setting. this is for reading registry setting only. not useful. */
	u8 TxRate;		/* Same value to fill in TXD. TxRate is 6-bit */
	u8 MaxTxRate;	/* RATE_1, RATE_2, RATE_5_5, RATE_11 */
	u8 TxRateIndex;	/* Tx rate index in Rate Switch Table */
	u8 MinTxRate;	/* RATE_1, RATE_2, RATE_5_5, RATE_11 */
	u8 RtsRate;		/* RATE_xxx */
	HTTRANSMIT_SETTING MlmeTransmit;	/* MGMT frame PHY rate setting when operatin at Ht rate. */
	u8 MlmeRate;		/* RATE_xxx, used to send MLME frames */
	u8 BasicMlmeRate;	/* Default Rate for sending MLME frames */

	unsigned short RtsThreshold;	/* in unit of BYTE */
	unsigned short FragmentThreshold;	/* in unit of BYTE */

	u8 TxPower;		/* in unit of mW */
	unsigned long TxPowerPercentage;	/* 0~100 % */
	unsigned long TxPowerDefault;	/* keep for TxPowerPercentage */
	u8 PwrConstraint;

#ifdef DOT11_N_SUPPORT
	BACAP_STRUC BACapability;	/*   NO USE = 0XFF  ;  IMMED_BA =1  ;  DELAY_BA=0 */
	BACAP_STRUC REGBACapability;	/*   NO USE = 0XFF  ;  IMMED_BA =1  ;  DELAY_BA=0 */
#endif /* DOT11_N_SUPPORT */

#ifdef DOT11_VHT_AC
	bool force_vht;
	u8 vht_bw;
	u8 vht_sgi_80;
	u8 vht_stbc;
	u8 vht_bw_signal;
	u8 vht_cent_ch;
	u8 vht_cent_ch2;
#endif /* DOT11_VHT_AC */

	IOT_STRUC IOTestParm;	/* 802.11n InterOpbility Test Parameter; */
	unsigned long TxPreamble;	/* Rt802_11PreambleLong, Rt802_11PreambleShort, Rt802_11PreambleAuto */
	bool bUseZeroToDisableFragment;	/* Microsoft use 0 as disable */
	unsigned long UseBGProtection;	/* 0: auto, 1: always use, 2: always not use */
	bool bUseShortSlotTime;	/* 0: disable, 1 - use short slot (9us) */
	bool bEnableTxBurst;	/* 1: enble TX PACKET BURST (when BA is established or AP is not a legacy WMM AP), 0: disable TX PACKET BURST */
	bool bAggregationCapable;	/* 1: enable TX aggregation when the peer supports it */
	bool bPiggyBackCapable;	/* 1: enable TX piggy-back according MAC's version */
	bool bIEEE80211H;	/* 1: enable IEEE802.11h spec. */
	u8 RDDurRegion; /* Region of radar detection */
	unsigned long DisableOLBCDetect;	/* 0: enable OLBC detect; 1 disable OLBC detect */

#ifdef DOT11_N_SUPPORT
	bool bRdg;
#endif /* DOT11_N_SUPPORT */
	bool bWmmCapable;	/* 0:disable WMM, 1:enable WMM */
	QOS_CAPABILITY_PARM APQosCapability;	/* QOS capability of the current associated AP */
	EDCA_PARM APEdcaParm;	/* EDCA parameters of the current associated AP */
	QBSS_LOAD_PARM APQbssLoad;	/* QBSS load of the current associated AP */
	u8 AckPolicy[4];	/* ACK policy of the specified AC. see ACK_xxx */
#ifdef CONFIG_STA_SUPPORT
	bool bDLSCapable;	/* 0:disable DLS, 1:enable DLS */
#endif /* CONFIG_STA_SUPPORT */
	/* a bitmap of bool flags. each bit represent an operation status of a particular */
	/* bool control, either ON or OFF. These flags should always be accessed via */
	/* OPSTATUS_TEST_FLAG(), OPSTATUS_SET_FLAG(), OP_STATUS_CLEAR_FLAG() macros. */
	/* see fOP_STATUS_xxx in RTMP_DEF.C for detail bit definition */
	unsigned long OpStatusFlags;

	bool NdisRadioStateOff;	/*For HCT 12.0, set this flag to true instead of called MlmeRadioOff. */

#ifdef DFS_SUPPORT
	/* IEEE802.11H--DFS. */
	RADAR_DETECT_STRUCT RadarDetect;
#endif /* DFS_SUPPORT */

#ifdef DOT11_N_SUPPORT
	/* HT */
	RT_HT_CAPABILITY DesiredHtPhy;
	HT_CAPABILITY_IE HtCapability;
	ADD_HT_INFO_IE AddHTInfo;	/* Useful as AP. */
	/*This IE is used with channel switch announcement element when changing to a new 40MHz. */
	/*This IE is included in channel switch ammouncement frames 7.4.1.5, beacons, probe Rsp. */
	NEW_EXT_CHAN_IE NewExtChanOffset;	/*7.3.2.20A, 1 if extension channel is above the control channel, 3 if below, 0 if not present */

	EXT_CAP_INFO_ELEMENT ExtCapIE;	/* this is the extened capibility IE appreed in MGMT frames. Doesn't need to update once set in Init. */

#ifdef DOT11N_DRAFT3
	bool bBssCoexEnable;
	/*
	   Following two paramters now only used for the initial scan operation. the AP only do
	   bandwidth fallback when BssCoexApCnt > BssCoexApCntThr
	   By default, the "BssCoexApCntThr" is set as 0 in "UserCfgInit()".
	 */
	u8 BssCoexApCntThr;
	u8 BssCoexApCnt;

	u8 Bss2040CoexistFlag;	/* bit 0: bBssCoexistTimerRunning, bit 1: NeedSyncAddHtInfo. */
	RALINK_TIMER_STRUCT Bss2040CoexistTimer;
	u8 Bss2040NeedFallBack; 	/* 1: Need Fall back to 20MHz */

	/*This IE is used for 20/40 BSS Coexistence. */
	BSS_2040_COEXIST_IE BSS2040CoexistInfo;

	unsigned short Dot11OBssScanPassiveDwell;	/* Unit : TU. 5~1000 */
	unsigned short Dot11OBssScanActiveDwell;	/* Unit : TU. 10~1000 */
	unsigned short Dot11BssWidthTriggerScanInt;	/* Unit : Second */
	unsigned short Dot11OBssScanPassiveTotalPerChannel;	/* Unit : TU. 200~10000 */
	unsigned short Dot11OBssScanActiveTotalPerChannel;	/* Unit : TU. 20~10000 */
	unsigned short Dot11BssWidthChanTranDelayFactor;
	unsigned short Dot11OBssScanActivityThre;	/* Unit : percentage */

	unsigned long Dot11BssWidthChanTranDelay;	/* multiple of (Dot11BssWidthTriggerScanInt * Dot11BssWidthChanTranDelayFactor) */
	unsigned long CountDownCtr;	/* CountDown Counter from (Dot11BssWidthTriggerScanInt * Dot11BssWidthChanTranDelayFactor) */

	BSS_2040_COEXIST_IE LastBSSCoexist2040;
	BSS_2040_COEXIST_IE BSSCoexist2040;
	TRIGGER_EVENT_TAB TriggerEventTab;
	u8 ChannelListIdx;

	bool bOverlapScanning;
	bool bBssCoexNotify;
#endif /* DOT11N_DRAFT3 */

	bool bHTProtect;
	bool bMIMOPSEnable;
	bool bBADecline;
	bool bDisableReordering;
	bool bForty_Mhz_Intolerant;
	bool bExtChannelSwitchAnnouncement;
	bool bRcvBSSWidthTriggerEvents;
	unsigned long LastRcvBSSWidthTriggerEventsTime;

	u8 TxBASize;

	bool bRalinkBurstMode;
	u32 RestoreBurstMode;
#endif /* DOT11_N_SUPPORT */

#ifdef DOT11_VHT_AC
	u32 cfg_vht;
	VHT_CAP_INFO vht_info;
#endif /* DOT11_VHT_AC */

	bool bWiFiTest;	/* Enable this parameter for WiFi test */

	/* Tx & Rx Stream number selection */
	u8 TxStream;
	u8 RxStream;

	/* transmit phy mode, trasmit rate for Multicast. */
#ifdef MCAST_RATE_SPECIFIC
	u8 McastTransmitMcs;
	u8 McastTransmitPhyMode;
#endif /* MCAST_RATE_SPECIFIC */

	bool bHardwareRadio;	/* Hardware controlled Radio enabled */

#ifdef RTMP_MAC_USB
	bool bMultipleIRP;	/* Multiple Bulk flag */
	u8 NumOfBulkInIRP;	/* if bMultipleIRP == true, NumOfBulkInIRP will be 4 otherwise be 1 */
	RT_HT_CAPABILITY SupportedHtPhy;
	unsigned long MaxPktOneTxBulk;
	u8 TxBulkFactor;
	u8 RxBulkFactor;

	bool IsUpdateBeacon;
	BEACON_SYNC_STRUCT *pBeaconSync;
	RALINK_TIMER_STRUCT BeaconUpdateTimer;
	u32 BeaconAdjust;
	u32 BeaconFactor;
	u32 BeaconRemain;
#endif				/* RTMP_MAC_USB */



	spinlock_t MeasureReqTabLock;
	PMEASURE_REQ_TAB pMeasureReqTab;

	spinlock_t TpcReqTabLock;
	PTPC_REQ_TAB pTpcReqTab;

	/* transmit phy mode, trasmit rate for Multicast. */
#ifdef MCAST_RATE_SPECIFIC
	HTTRANSMIT_SETTING MCastPhyMode;
#endif /* MCAST_RATE_SPECIFIC */

	bool HT_DisallowTKIP;	/* Restrict the encryption type in 11n HT mode */

	bool HT_Disable;	/* 1: disable HT function; 0: enable HT function */


#ifdef CFO_TRACK
	short	CFOTrack;	/* CFO Tracking. 0=>use default, 1=>track, 2-7=> track 8-n times, 8=>done tracking */
#endif /* CFO_TRACK */

#ifdef NEW_RATE_ADAPT_SUPPORT
	unsigned short	lowTrafficThrd;		/* Threshold for reverting to default MCS when traffic is low */
	bool TrainUpRule;		/* QuickDRS train up criterion: 0=>Throughput, 1=>PER, 2=> Throughput & PER */
	short	TrainUpRuleRSSI;	/* If TrainUpRule=2 then use Hybrid rule when RSSI < TrainUpRuleRSSI */
	unsigned short	TrainUpLowThrd;		/* QuickDRS Hybrid train up low threshold */
	unsigned short	TrainUpHighThrd;	/* QuickDRS Hybrid train up high threshold */
#endif /* NEW_RATE_ADAPT_SUPPORT */

#ifdef DBG_CTRL_SUPPORT
	unsigned long DebugFlags;	/* Temporary debug flags */
#endif /* DBG_CTRL_SUPPORT */



	//brian
	u32 nLoopBack_Count;
	u32 nWIFI_Info_Idx;
};

#ifdef DBG_CTRL_SUPPORT
/* DebugFlag definitions */
#define DBF_NO_BF_AWARE_RA		0x0001	/* Revert to older Rate Adaptation that is not BF aware */
#define DBF_SHOW_BF_STATS		0x0002	/* Display BF statistics in AP "iwpriv stat" display */
#define DBF_NO_TXBF_3SS			0x0004	/* Disable TXBF for MCS > 20 */
#define DBF_UNUSED0008			0x0008	/* Unused */
#define DBF_DBQ_RA_LOG			0x0010	/* Log RA information in DBQ */
#define DBF_INIT_MCS_MARGIN		0x0020	/* Use 6 dB margin when selecting initial MCS */
#define DBF_INIT_MCS_DIS1		0x0040	/* Disable highest MCSs when selecting initial MCS */
#define DBF_FORCE_QUICK_DRS		0x0080	/* Force Quick DRS even if rate didn't change */
#define DBF_FORCE_SGI			0x0100	/* Force Short GI */
#define DBF_DBQ_NO_BCN			0x0200	/* Disable logging of RX Beacon frames */
#define DBF_LOG_VCO_CAL			0x0400	/* Log VCO cal */
#define DBF_DISABLE_CAL			0x0800	/* Disable Divider Calibration at channel change */
#ifdef INCLUDE_DEBUG_QUEUE
#define DBF_DBQ_TXFIFO			0x1000	/* Enable logging of TX information from FIFO */
#define DBF_DBQ_TXFRAME			0x2000	/* Enable logging of Frames queued for TX */
#define DBF_DBQ_RXWI_FULL		0x4000	/* Enable logging of full RXWI */
#define DBF_DBQ_RXWI			0x8000	/* Enable logging of partial RXWI */
#endif /* INCLUDE_DEBUG_QUEUE */

#define DBF_SHOW_RA_LOG			0x010000	/* Display concise Rate Adaptation information */
#define DBF_SHOW_ZERO_RA_LOG	0x020000	/* Include RA Log entries when TxCount is 0 */
#define DBF_FORCE_20MHZ			0x040000	/* Force 20 MHz TX */
#define DBF_FORCE_40MHZ 		0x080000	/* Force 40 MHz Tx */
#define DBF_DISABLE_CCK			0x100000	/* Disable CCK */
#define DBF_UNUSED200000		0x200000	/* Unused */
#define DBF_ENABLE_HT_DUP		0x400000	/* Allow HT Duplicate mode in TX rate table */
#define DBF_ENABLE_CCK_5G		0x800000	/* Enable CCK rates in 5G band */
#define DBF_UNUSED0100000		0x0100000	/* Unused */
#define DBF_ENABLE_20MHZ_MCS8	0x02000000	/* Substitute 20MHz MCS8 for 40MHz MCS8 */
#define DBF_DISABLE_20MHZ_MCS0	0x04000000	/* Disable substitution of 20MHz MCS0 for 40MHz MCS32 */
#define DBF_DISABLE_20MHZ_MCS1	0x08000000	/* Disable substitution of 20MHz MCS1 for 40MHz MCS0 */
#endif /* DBG_CTRL_SUPPORT */

#ifdef CONFIG_STA_SUPPORT

/* Modified by Wu Xi-Kun 4/21/2006 */
/* STA configuration and status */
typedef struct _STA_ADMIN_CONFIG {
	struct wifi_dev wdev;

	/*
		GROUP 1 -
		User configuration loaded from Registry, E2PROM or OID_xxx. These settings describe
		the user intended configuration, but not necessary fully equal to the final
		settings in ACTIVE BSS after negotiation/compromize with the BSS holder (either
		AP or IBSS holder).
		Once initialized, user configuration can only be changed via OID_xxx
	*/
	u8 BssType;		/* BSS_INFRA or BSS_ADHOC */

#ifdef MONITOR_FLAG_11N_SNIFFER_SUPPORT
#define MONITOR_FLAG_11N_SNIFFER		0x01
	u8 BssMonitorFlag;	/* Specific flag for monitor */
#endif				/* MONITOR_FLAG_11N_SNIFFER_SUPPORT */

	unsigned short AtimWin;		/* used when starting a new IBSS */

	/*
		GROUP 2 -
		User configuration loaded from Registry, E2PROM or OID_xxx. These settings describe
		the user intended configuration, and should be always applied to the final
		settings in ACTIVE BSS without compromising with the BSS holder.
		Once initialized, user configuration can only be changed via OID_xxx
	*/
	u8 RssiTrigger;
	u8 RssiTriggerMode;	/* RSSI_TRIGGERED_UPON_BELOW_THRESHOLD or RSSI_TRIGGERED_UPON_EXCCEED_THRESHOLD */
	unsigned short DefaultListenCount;	/* default listen count; */
	unsigned long WindowsPowerMode;	/* Power mode for AC power */
	unsigned long WindowsBatteryPowerMode;	/* Power mode for battery if exists */
	bool bWindowsACCAMEnable;	/* Enable CAM power mode when AC on */
	unsigned long WindowsPowerProfile;	/* Windows power profile, for NDIS5.1 PnP */

	bool  FlgPsmCanNotSleep; /* true: can not switch ASIC to sleep */
	/* MIB:ieee802dot11.dot11smt(1).dot11StationConfigTable(1) */
	unsigned short Psm;		/* power management mode   (PWR_ACTIVE|PWR_SAVE) */
	unsigned short DisassocReason;
	u8 DisassocSta[ETH_ALEN];
	unsigned short DeauthReason;
	u8 DeauthSta[ETH_ALEN];
	unsigned short AuthFailReason;
	u8 AuthFailSta[ETH_ALEN];

	NDIS_802_11_PRIVACY_FILTER PrivacyFilter;	/* PrivacyFilter enum for 802.1X */
	NDIS_802_11_AUTHENTICATION_MODE AuthMode;	/* This should match to whatever microsoft defined */
	NDIS_802_11_WEP_STATUS WepStatus;

	/* Add to support different cipher suite for WPA2/WPA mode */
	NDIS_802_11_ENCRYPTION_STATUS GroupCipher;	/* Multicast cipher suite */
	NDIS_802_11_ENCRYPTION_STATUS PairCipher;	/* Unicast cipher suite */
	bool bMixCipher;	/* Indicate current Pair & Group use different cipher suites */
	unsigned short RsnCapability;

	NDIS_802_11_WEP_STATUS GroupKeyWepStatus;

	u8 WpaPassPhrase[64];	/* WPA PSK pass phrase */
	unsigned int WpaPassPhraseLen;	/* the length of WPA PSK pass phrase */
	u8 PMK[LEN_PMK];	/* WPA PSK mode PMK */
	u8 PTK[LEN_PTK];	/* WPA PSK mode PTK */
	u8 GMK[LEN_GMK];	/* WPA PSK mode GMK */
	u8 GTK[MAX_LEN_GTK];	/* GTK from authenticator */
	u8 GNonce[32];	/* GNonce for WPA2PSK from authenticator */
	CIPHER_KEY TxGTK;
	BSSID_INFO SavedPMK[PMKID_NO];
	unsigned int SavedPMKNum;	/* Saved PMKID number */

	u8 DefaultKeyId;


	/* WPA 802.1x port control, WPA_802_1X_PORT_SECURED, WPA_802_1X_PORT_NOT_SECURED */
	u8 PortSecured;

	/* For WPA countermeasures */
	unsigned long LastMicErrorTime;	/* record last MIC error time */
	unsigned long MicErrCnt;	/* Should be 0, 1, 2, then reset to zero (after disassoiciation). */
	bool bBlockAssoc;	/* Block associate attempt for 60 seconds after counter measure occurred. */
	/* For WPA-PSK supplicant state */
	u8 WpaState;		/* Default is SS_NOTUSE and handled by microsoft 802.1x */
	u8 ReplayCounter[8];
	u8 ANonce[32];	/* ANonce for WPA-PSK from aurhenticator */
	u8 SNonce[32];	/* SNonce for WPA-PSK */

	u8 LastSNR0;		/* last received BEACON's SNR */
	u8 LastSNR1;		/* last received BEACON's SNR for 2nd  antenna */
#ifdef DOT11N_SS3_SUPPORT
	u8 LastSNR2;		/* last received BEACON's SNR for 3nd  antenna */
	int32_t BF_SNR[3];	/* Last RXWI BF SNR. Units=0.25 dB */
#endif /* DOT11N_SS3_SUPPORT */
	RSSI_SAMPLE RssiSample;
	unsigned long NumOfAvgRssiSample;

	unsigned long LastBeaconRxTime;	/* OS's timestamp of the last BEACON RX time */
	unsigned long Last11bBeaconRxTime;	/* OS's timestamp of the last 11B BEACON RX time */
	unsigned long Last11gBeaconRxTime;	/* OS's timestamp of the last 11G BEACON RX time */
	unsigned long Last20NBeaconRxTime;	/* OS's timestamp of the last 20MHz N BEACON RX time */

	unsigned long LastScanTime;	/* Record last scan time for issue BSSID_SCAN_LIST */
	bool bNotFirstScan;	/* Sam add for ADHOC flag to do first scan when do initialization */
	bool bSwRadio;	/* Software controlled Radio On/Off, true: On */
	bool bHwRadio;	/* Hardware controlled Radio On/Off, true: On */
	bool bRadio;		/* Radio state, And of Sw & Hw radio state */
	bool bHardwareRadio;	/* Hardware controlled Radio enabled */
	bool bShowHiddenSSID;	/* Show all known SSID in SSID list get operation */

	/* New for WPA, windows want us to to keep association information and */
	/* Fixed IEs from last association response */
	NDIS_802_11_ASSOCIATION_INFORMATION AssocInfo;
	unsigned short ReqVarIELen;	/* Length of next VIE include EID & Length */
	u8 ReqVarIEs[MAX_VIE_LEN];	/* The content saved here should be little-endian format. */
	unsigned short ResVarIELen;	/* Length of next VIE include EID & Length */
	u8 ResVarIEs[MAX_VIE_LEN];

	u8 RSNIE_Len;
	u8 RSN_IE[MAX_LEN_OF_RSNIE];	/* The content saved here should be little-endian format. */

	unsigned long CLBusyBytes;	/* Save the total bytes received durning channel load scan time */
	unsigned short RPIDensity[8];	/* Array for RPI density collection */

	u8 RMReqCnt;		/* Number of measurement request saved. */
	u8 CurrentRMReqIdx;	/* Number of measurement request saved. */
	bool ParallelReq;	/* Parallel measurement, only one request performed, */
	/* It must be the same channel with maximum duration */
	unsigned short ParallelDuration;	/* Maximum duration for parallel measurement */
	u8 ParallelChannel;	/* Only one channel with parallel measurement */
	unsigned short IAPPToken;	/* IAPP dialog token */
	/* Hack for channel load and noise histogram parameters */
	u8 NHFactor;		/* Parameter for Noise histogram */
	u8 CLFactor;		/* Parameter for channel load */

	RALINK_TIMER_STRUCT StaQuickResponeForRateUpTimer;
	bool StaQuickResponeForRateUpTimerRunning;

	u8 DtimCount;	/* 0.. DtimPeriod-1 */
	u8 DtimPeriod;	/* default = 3 */

#ifdef QOS_DLS_SUPPORT
	RT_802_11_DLS DLSEntry[MAX_NUM_OF_DLS_ENTRY];
	u8 DlsReplayCounter[8];
#endif				/* QOS_DLS_SUPPORT */


	RALINK_TIMER_STRUCT WpaDisassocAndBlockAssocTimer;
	/* Fast Roaming */
	bool bAutoRoaming;	/* 0:disable auto roaming by RSSI, 1:enable auto roaming by RSSI */
	CHAR dBmToRoam;		/* the condition to roam when receiving Rssi less than this value. It's negative value. */

#ifdef WPA_SUPPLICANT_SUPPORT
	bool IEEE8021X;
	bool IEEE8021x_required_keys;
	CIPHER_KEY DesireSharedKey[4];	/* Record user desired WEP keys */
	u8 DesireSharedKeyId;

	/* 0x00: driver ignores wpa_supplicant */
	/* 0x01: wpa_supplicant initiates scanning and AP selection */
	/* 0x02: driver takes care of scanning, AP selection, and IEEE 802.11 association parameters */
	/* 0x80: wpa_supplicant trigger driver to do WPS */
	u8 WpaSupplicantUP;
	u8 WpaSupplicantScanCount;
	bool bRSN_IE_FromWpaSupplicant;
	bool bLostAp;
	u8 *pWpsProbeReqIe;
	unsigned int WpsProbeReqIeLen;
	u8 *pWpaAssocIe;
	unsigned int WpaAssocIeLen;
#endif /* WPA_SUPPLICANT_SUPPORT */

	CHAR dev_name[16];
	unsigned short OriDevType;

	bool bTGnWifiTest;
	bool bSkipAutoScanConn;

	HTTRANSMIT_SETTING HTPhyMode, MaxHTPhyMode, MinHTPhyMode;	/* For transmit phy setting in TXWI. */
	DESIRED_TRANSMIT_SETTING DesiredTransmitSetting;
	RT_PHY_INFO DesiredHtPhyInfo;
	bool bAutoTxRateSwitch;


#ifdef EXT_BUILD_CHANNEL_LIST
	u8 IEEE80211dClientMode;
	u8 StaOriCountryCode[3];
	u8 StaOriGeography;
#endif /* EXT_BUILD_CHANNEL_LIST */





	bool bAutoConnectByBssid;
	unsigned long BeaconLostTime;	/* seconds */
	bool bForceTxBurst;	/* 1: force enble TX PACKET BURST, 0: disable */
	bool bAutoConnectIfNoSSID;
#ifdef DOT11_N_SUPPORT
#ifdef DOT11N_DRAFT3
	u8 RegClass;		/*IE_SUPP_REG_CLASS: 2009 PF#3: For 20/40 Intolerant Channel Report */
#endif /* DOT11N_DRAFT3 */
	bool bAdhocN;
#endif /* DOT11_N_SUPPORT */
	bool bAdhocCreator;	/*true indicates divice is Creator. */


	/*
	   Enhancement Scanning Mechanism
	   To decrease the possibility of ping loss
	 */
	bool bImprovedScan;
	bool BssNr;
	u8 ScanChannelCnt;	/* 0 at the beginning of scan, stop at 7 */
	u8 LastScanChannel;
	/************************************/

	bool bFastConnect;

/*connectinfo  for tmp store connect info from UI*/
	bool Connectinfoflag;
	u8   ConnectinfoBssid[ETH_ALEN];
	u8   ConnectinfoChannel;
	u8   ConnectinfoSsidLen;
	CHAR    ConnectinfoSsid[MAX_LEN_OF_SSID];
	u8 ConnectinfoBssType;




	/* UAPSD information: such as enable or disable, do not remove */
	UAPSD_INFO UapsdInfo;

} STA_ADMIN_CONFIG, *PSTA_ADMIN_CONFIG;


/*
	This data structure keep the current active BSS/IBSS's configuration that
	this STA had agreed upon joining the network. Which means these parameters
	are usually decided by the BSS/IBSS creator instead of user configuration.
	Data in this data structurre is valid only when either ADHOC_ON()/INFRA_ON()
	is true. Normally, after SCAN or failed roaming attempts, we need to
	recover back to the current active settings
*/
typedef struct _STA_ACTIVE_CONFIG {
	unsigned short Aid;
	unsigned short AtimWin;		/* in kusec; IBSS parameter set element */
	unsigned short CapabilityInfo;
	EXT_CAP_INFO_ELEMENT ExtCapInfo;
	unsigned short CfpMaxDuration;
	unsigned short CfpPeriod;

	/* Copy supported rate from desired AP's beacon. We are trying to match */
	/* AP's supported and extended rate settings. */
	u8 SupRate[MAX_LEN_OF_SUPPORTED_RATES];
	u8 ExtRate[MAX_LEN_OF_SUPPORTED_RATES];
	u8 SupRateLen;
	u8 ExtRateLen;
	/* Copy supported ht from desired AP's beacon. We are trying to match */
	RT_PHY_INFO SupportedPhyInfo;
	RT_HT_CAPABILITY SupportedHtPhy;
	RT_VHT_CAP	SupVhtCap;
} STA_ACTIVE_CONFIG, *PSTA_ACTIVE_CONFIG;



#endif /* CONFIG_STA_SUPPORT */



/* Values of LastSecTxRateChangeAction */
#define RATE_NO_CHANGE	0		/* No change in rate */
#define RATE_UP			1		/* Trying higher rate or same rate with different BF */
#define RATE_DOWN		2		/* Trying lower rate */



#ifdef WFA_VHT_PF
#ifdef IP_ASSEMBLY
struct ip_frag_q{
	QUEUE_HEADER ip_queue[4];
	int32_t ip_id[4];
	int32_t ip_id_FragSize[4];
	unsigned long ip_pkt_jiffies[4];
};
#endif /* IP_ASSEMBLY */
#endif /* WFA_VHT_PF */

typedef struct _MAC_TABLE_ENTRY {
	/*
	   0:Invalid,
	   Bit 0: AsCli, Bit 1: AsWds, Bit 2: AsAPCLI,
	   Bit 3: AsMesh, Bit 4: AsDls, Bit 5: AsTDls
	 */
	u32 EntryType;

	bool isCached;
	bool bIAmBadAtheros;	/* Flag if this is Atheros chip that has IOT problem.  We need to turn on RTS/CTS protection. */
	u8 wcid;

	/* WPA/WPA2 4-way database */
	u8 EnqueueEapolStartTimerRunning;	/* Enqueue EAPoL-Start for triggering EAP SM */
	RALINK_TIMER_STRUCT EnqueueStartForPSKTimer;	/* A timer which enqueue EAPoL-Start for triggering PSK SM */

	/*jan for wpa */
	/* record which entry revoke MIC Failure , if it leaves the BSS itself, AP won't update aMICFailTime MIB */
	u8 CMTimerRunning;
	u8 apidx;		/* MBSS number */
	u8 RSNIE_Len;
	u8 RSN_IE[MAX_LEN_OF_RSNIE];
	u8 ANonce[LEN_KEY_DESC_NONCE];
	u8 SNonce[LEN_KEY_DESC_NONCE];
	u8 R_Counter[LEN_KEY_DESC_REPLAY];
	u8 PTK[64];
	u8 ReTryCounter;
	RALINK_TIMER_STRUCT RetryTimer;
	NDIS_802_11_AUTHENTICATION_MODE AuthMode;	/* This should match to whatever microsoft defined */
	NDIS_802_11_WEP_STATUS WepStatus;
	NDIS_802_11_WEP_STATUS GroupKeyWepStatus;
	u8 WpaState;
	u8 GTKState;
	unsigned short PortSecured;
	NDIS_802_11_PRIVACY_FILTER PrivacyFilter;	/* PrivacyFilter enum for 802.1X */
	CIPHER_KEY PairwiseKey;
	void *pAd;
	INT PMKID_CacheIdx;
	u8 PMKID[LEN_PMKID];
	u8 NegotiatedAKM[LEN_OUI_SUITE];	/* It indicate the negotiated AKM suite */


	u8 Addr[ETH_ALEN];
	u8 HdrAddr1[ETH_ALEN];
	u8 HdrAddr2[ETH_ALEN];
	u8 HdrAddr3[ETH_ALEN];
	u8 PsMode;
	u8 FlgPsModeIsWakeForAWhile; /* wake up for a while until a condition */
	u8 VirtualTimeout; /* peer power save virtual timeout */
	SST Sst;
	AUTH_STATE AuthState;	/* for SHARED KEY authentication state machine used only */
	bool IsReassocSta;	/* Indicate whether this is a reassociation procedure */
	unsigned short Aid;
	unsigned short CapabilityInfo;
	u8 LastRssi;
	unsigned long NoDataIdleCount;
	uint16_t StationKeepAliveCount;	/* unit: second */
	unsigned long PsQIdleCount;
	QUEUE_HEADER PsQueue;

	u32 StaConnectTime;	/* the live time of this station since associated with AP */
	u32 StaIdleTimeout;	/* idle timeout per entry */

#ifdef UAPSD_SUPPORT
	/* these UAPSD states are used on the fly */
	/* 0:AC_BK, 1:AC_BE, 2:AC_VI, 3:AC_VO */
	bool bAPSDCapablePerAC[4];	/* for trigger-enabled */
	bool bAPSDDeliverEnabledPerAC[4];	/* for delivery-enabled */


	u8 MaxSPLength;

	bool bAPSDAllAC;	/* 1: all AC are delivery-enabled U-APSD */

	QUEUE_HEADER UAPSDQueue[WMM_NUM_OF_AC];	/* queue for each U-APSD */
	unsigned short UAPSDQIdleCount;	/* U-APSD queue timeout */

	PQUEUE_ENTRY pUAPSDEOSPFrame;	/* the last U-APSD frame */
	unsigned short UAPSDTxNum;	/* total U-APSD frame number */
	bool bAPSDFlagEOSPOK;	/* 1: EOSP frame is tx by ASIC */
	bool bAPSDFlagSPStart;	/* 1: SP is started */

	/* need to use unsigned long, because time parameters in OS is defined as
	   unsigned long */
	unsigned long UAPSDTimeStampLast;	/* unit: 1000000/OS_HZ */
	bool bAPSDFlagSpRoughUse;	/* 1: use rough SP (default: accurate) */

	/* we will set the flag when PS-poll frame is received and
	   clear it when statistics handle.
	   if the flag is set when PS-poll frame is received then calling
	   statistics handler to clear it. */
	bool bAPSDFlagLegacySent;	/* 1: Legacy PS sent but
					   yet statistics handle */

#ifdef RTMP_MAC_USB
	u32 UAPSDTagOffset[WMM_NUM_OF_AC];
#endif /* RTMP_MAC_USB */
#endif /* UAPSD_SUPPORT */

#ifdef DOT11_N_SUPPORT
	bool bSendBAR;
	unsigned short NoBADataCountDown;

	u32 CachedBuf[16];	/* unsigned int (4 bytes) for alignment */

#endif /* DOT11_N_SUPPORT */

	unsigned int FIFOCount;
	unsigned int DebugFIFOCount;
	unsigned int DebugTxCount;
	bool bDlsInit;

/*==================================================== */
/* WDS entry needs these */
/* If ValidAsWDS==true, MatchWDSTabIdx is the index in WdsTab.MacTab */
	unsigned int MatchWDSTabIdx;
	u8 MaxSupportedRate;
	u8 CurrTxRate;
	u8 CurrTxRateIndex;
	u8 lastRateIdx;
	u8 *pTable;	/* Pointer to this entry's Tx Rate Table */

#ifdef NEW_RATE_ADAPT_SUPPORT
	u8 lowTrafficCount;
	u8 fewPktsCnt;
	bool perThrdAdj;
	u8 mcsGroup;/* the mcs group to be tried */
#endif /* NEW_RATE_ADAPT_SUPPORT */
	enum RATE_ADAPT_ALG rateAlg;

#ifdef MFB_SUPPORT
	u8 lastLegalMfb;	/* last legal mfb which is used to set rate */
	bool isMfbChanged;	/* purpose: true when mfb has changed but the new mfb is not adopted for Tx */
	struct _RTMP_RA_LEGACY_TB *LegalMfbRS;
	bool fLastChangeAccordingMfb;
	spinlock_t fLastChangeAccordingMfbLock;
/* Tx MRQ */
	bool toTxMrq;
	u8 msiToTx, mrqCnt;	/*mrqCnt is used to count down the inverted-BF mrq to be sent */
/* Rx mfb */
	u8 pendingMfsi;
/* Tx MFB */
	bool toTxMfb;
	u8 mfbToTx;
	u8 mfb0, mfb1;
#endif	/* MFB_SUPPORT */

	/* to record the each TX rate's quality. 0 is best, the bigger the worse. */
	unsigned short      TxQuality[MAX_TX_RATE_INDEX + 1];
	u32		OneSecTxNoRetryOkCount;
	u32      OneSecTxRetryOkCount;
	u32      OneSecTxFailCount;
	u32      OneSecRxLGICount;		/* unicast-to-me Long GI count */
	u32      OneSecRxSGICount;      	/* unicast-to-me Short GI count */

	bool fLastSecAccordingRSSI;
	u8 LastSecTxRateChangeAction;	/* 0: no change, 1:rate UP, 2:rate down */
	CHAR LastTimeTxRateChangeAction;	/* Keep last time value of LastSecTxRateChangeAction */
	unsigned long LastTxOkCount; /* TxSuccess count in last Rate Adaptation interval */
	u8 LastTxPER;	/* Tx PER in last Rate Adaptation interval */
	u8 PER[MAX_TX_RATE_INDEX + 1];

	u32 ContinueTxFailCnt;
	u32 CurrTxRateStableTime;	/* # of second in current TX rate */
	u8 TxRateUpPenalty;	/* extra # of second penalty due to last unstable condition */
	unsigned long TimeStamp_toTxRing;

/*==================================================== */



#ifdef CONFIG_STA_SUPPORT
#ifdef QOS_DLS_SUPPORT
	unsigned int MatchDlsEntryIdx;	/* indicate the index in pAd->StaCfg.DLSEntry */
#endif /* QOS_DLS_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */

	/*
		A bitmap of bool flags. each bit represent an operation status of a particular
		bool control, either ON or OFF. These flags should always be accessed via
		CLIENT_STATUS_TEST_FLAG(), CLIENT_STATUS_SET_FLAG(), CLIENT_STATUS_CLEAR_FLAG() macros.
		see fOP_STATUS_xxx in RTMP_DEF.C for detail bit definition. fCLIENT_STATUS_AMSDU_INUSED
	*/
	unsigned long ClientStatusFlags;

	HTTRANSMIT_SETTING HTPhyMode, MaxHTPhyMode, MinHTPhyMode;	/* For transmit phy setting in TXWI. */

#ifdef DOT11_N_SUPPORT
	/* HT EWC MIMO-N used parameters */
	unsigned short RXBAbitmap;	/* fill to on-chip  RXWI_BA_BITMASK in 8.1.3RX attribute entry format */
	unsigned short TXBAbitmap;	/* This bitmap as originator, only keep in software used to mark AMPDU bit in TXWI */
	unsigned short TXAutoBAbitmap;
	unsigned short BADeclineBitmap;
	unsigned short BARecWcidArray[NUM_OF_TID];	/* The mapping wcid of recipient session. if RXBAbitmap bit is masked */
	unsigned short BAOriWcidArray[NUM_OF_TID];	/* The mapping wcid of originator session. if TXBAbitmap bit is masked */
	unsigned short BAOriSequence[NUM_OF_TID];	/* The mapping wcid of originator session. if TXBAbitmap bit is masked */

	/* 802.11n features. */
	u8 MpduDensity;
	u8 MaxRAmpduFactor;
	u8 AMsduSize;
	u8 MmpsMode;		/* MIMO power save more. */

	HT_CAPABILITY_IE HTCapability;

#ifdef DOT11N_DRAFT3
	u8 BSS2040CoexistenceMgmtSupport;
	bool bForty_Mhz_Intolerant;
#endif /* DOT11N_DRAFT3 */

#ifdef DOT11_VHT_AC
	VHT_CAP_IE vht_cap_ie;
#endif /* DOT11_VHT_AC */

#endif /* DOT11_N_SUPPORT */


	bool bAutoTxRateSwitch;

	u8 RateLen;
	struct _MAC_TABLE_ENTRY *pNext;
	unsigned short TxSeq[NUM_OF_TID];
	unsigned short NonQosDataSeq;

	RSSI_SAMPLE RssiSample;
	u32 LastRxRate;
	short freqOffset;		/* Last RXWI FOFFSET */
	short freqOffsetValid;	/* Set when freqOffset field has been updated */


	bool bWscCapable;
	u8 Receive_EapolStart_EapRspId;

	u32 TXMCSExpected[MAX_MCS_SET];
	u32 TXMCSSuccessful[MAX_MCS_SET];
	u32 TXMCSFailed[MAX_MCS_SET];
	u32 TXMCSAutoFallBack[MAX_MCS_SET][MAX_MCS_SET];

#ifdef CONFIG_STA_SUPPORT
	unsigned long LastBeaconRxTime;
#endif /* CONFIG_STA_SUPPORT */



	unsigned long AssocDeadLine;




	unsigned long ChannelQuality;	/* 0..100, Channel Quality Indication for Roaming */


	/* total 128B, use u32 to avoid alignment problem */
	u32 HeaderBuf[32];	/* (total 128B) TempBuffer for TX_INFO + TX_WI + 802.11 Header + padding + AMSDU SubHeader + LLC/SNAP */

	u8 HdrPadLen;	/* recording Header Padding Length; */
	u8 MpduHeaderLen;
	uint16_t Protocol;


u8 SupportRateMode; /* 1: CCK 2:OFDM 4: HT, 8:VHT */
bool SupportCCKMCS[MAX_LEN_OF_CCK_RATES];
bool SupportOFDMMCS[MAX_LEN_OF_OFDM_RATES];
bool SupportHTMCS[MAX_LEN_OF_HT_RATES];


#ifdef DOT11_VHT_AC
	bool SupportVHTMCS[MAX_LEN_OF_VHT_RATES];
#endif /* DOT11_VHT_AC */

#ifdef WFA_VHT_PF
#ifdef IP_ASSEMBLY
	QUEUE_HEADER ip_queue1[4];
	int32_t ip_id1[4];
	int32_t ip_id1_FragSize[4];
	unsigned long ip_pkt1_jiffies[4];

	QUEUE_HEADER ip_queue2[4];
	int32_t ip_id2[4];
	int32_t ip_id2_FragSize[4];
	unsigned long ip_pkt2_jiffies[4];

	struct ip_frag_q ip_fragQ[2];
	bool ip_queue_inited;
#endif /* IP_ASSEMBLY */
#endif /* WFA_VHT_PF */

#ifdef MAC_REPEATER_SUPPORT
	u8 ExtAid;
	u8 ClientType; /* 0x00: apcli, 0x01: wireless station, 0x02: ethernet entry */
	bool bConnToRootAP;
#endif /* MAC_REPEATER_SUPPORT */
} MAC_TABLE_ENTRY, *PMAC_TABLE_ENTRY;


typedef struct _MAC_TABLE {
	MAC_TABLE_ENTRY *Hash[HASH_TABLE_SIZE];
	MAC_TABLE_ENTRY Content[MAX_LEN_OF_MAC_TABLE];
	unsigned short Size;
	QUEUE_HEADER McastPsQueue;
	unsigned long PsQIdleCount;
	bool fAnyStationInPsm;
	bool fAnyStationBadAtheros;	/* Check if any Station is atheros 802.11n Chip.  We need to use RTS/CTS with Atheros 802,.11n chip. */
	bool fAnyTxOPForceDisable;	/* Check if it is necessary to disable BE TxOP */
	bool fAllStationAsRalink;	/* Check if all stations are ralink-chipset */
#ifdef DOT11_N_SUPPORT
	bool fAnyStationIsLegacy;	/* Check if I use legacy rate to transmit to my BSS Station/ */
	bool fAnyStationNonGF;	/* Check if any Station can't support GF. */
	bool fAnyStation20Only;	/* Check if any Station can't support GF. */
	bool fAnyStationMIMOPSDynamic;	/* Check if any Station is MIMO Dynamic */
	bool fAnyBASession;	/* Check if there is BA session.  Force turn on RTS/CTS */
	bool fAnyStaFortyIntolerant;	/* Check if still has any station set the Intolerant bit on! */
	bool fAllStationGainGoodMCS; /* Check if all stations more than MCS threshold */

#endif				/* DOT11_N_SUPPORT */

	unsigned short			MsduLifeTime; /* life time for PS packet */

} MAC_TABLE, *PMAC_TABLE;



#ifdef BLOCK_NET_IF
typedef struct _BLOCK_QUEUE_ENTRY {
	bool SwTxQueueBlockFlag;
	LIST_HEADER NetIfList;
} BLOCK_QUEUE_ENTRY, *PBLOCK_QUEUE_ENTRY;
#endif /* BLOCK_NET_IF */


struct wificonf {
	bool bShortGI;
	bool bGreenField;
};

#ifdef DBG_DIAGNOSE
#define DIAGNOSE_TIME	10	/* 10 sec */
typedef struct _RtmpDiagStrcut_ {	/* Diagnosis Related element */
	unsigned char inited;
	unsigned char qIdx;
	unsigned char ArrayStartIdx;
	unsigned char ArrayCurIdx;
	/* Tx Related Count */
	unsigned short TxDataCnt[DIAGNOSE_TIME];
	unsigned short TxFailCnt[DIAGNOSE_TIME];
/*	unsigned short TxDescCnt[DIAGNOSE_TIME][16];		// TxDesc queue length in scale of 0~14, >=15 */
	unsigned short TxDescCnt[DIAGNOSE_TIME][24];	/* 3*3    // TxDesc queue length in scale of 0~14, >=15 */
/*	unsigned short TxMcsCnt[DIAGNOSE_TIME][16];			// TxDate MCS Count in range from 0 to 15, step in 1. */
	unsigned short TxMcsCnt[DIAGNOSE_TIME][MAX_MCS_SET];	/* 3*3 */
	unsigned short TxSWQueCnt[DIAGNOSE_TIME][9];	/* TxSwQueue length in scale of 0, 1, 2, 3, 4, 5, 6, 7, >=8 */

	unsigned short TxAggCnt[DIAGNOSE_TIME];
	unsigned short TxNonAggCnt[DIAGNOSE_TIME];
/*	unsigned short TxAMPDUCnt[DIAGNOSE_TIME][16];		// 10 sec, TxDMA APMDU Aggregation count in range from 0 to 15, in setp of 1. */
	unsigned short TxAMPDUCnt[DIAGNOSE_TIME][MAX_MCS_SET];	/* 3*3 // 10 sec, TxDMA APMDU Aggregation count in range from 0 to 15, in setp of 1. */
	unsigned short TxRalinkCnt[DIAGNOSE_TIME];	/* TxRalink Aggregation Count in 1 sec scale. */
	unsigned short TxAMSDUCnt[DIAGNOSE_TIME];	/* TxAMSUD Aggregation Count in 1 sec scale. */

	/* Rx Related Count */
	unsigned short RxDataCnt[DIAGNOSE_TIME];	/* Rx Total Data count. */
	unsigned short RxCrcErrCnt[DIAGNOSE_TIME];
/*	unsigned short			RxMcsCnt[DIAGNOSE_TIME][16];		// Rx MCS Count in range from 0 to 15, step in 1. */
	unsigned short RxMcsCnt[DIAGNOSE_TIME][MAX_MCS_SET];	/* 3*3 */
} RtmpDiagStruct;
#endif /* DBG_DIAGNOSE */

/* */
/* The entry of transmit power control over MAC */
/* */
typedef struct _TX_POWER_CONTROL_OVER_MAC_ENTRY {
	unsigned short MACRegisterOffset;	/* MAC register offset */
	unsigned long RegisterValue;	/* Register value */
} TX_POWER_CONTROL_OVER_MAC_ENTRY, *PTX_POWER_CONTROL_OVER_MAC_ENTRY;

/* */
/* The maximum registers of transmit power control */
/* */
#define MAX_TX_PWR_CONTROL_OVER_MAC_REGISTERS 5



#ifdef MT76x0
#undef MAX_TX_PWR_CONTROL_OVER_MAC_REGISTERS
#define MAX_TX_PWR_CONTROL_OVER_MAC_REGISTERS	6
#endif /* MT76x0 */

/* */
/* The configuration of the transmit power control over MAC */
/* */
typedef struct _CONFIGURATION_OF_TX_POWER_CONTROL_OVER_MAC {
	u8 NumOfEntries;	/* Number of entries */
	TX_POWER_CONTROL_OVER_MAC_ENTRY TxPwrCtrlOverMAC[MAX_TX_PWR_CONTROL_OVER_MAC_REGISTERS];
} CONFIGURATION_OF_TX_POWER_CONTROL_OVER_MAC, *PCONFIGURATION_OF_TX_POWER_CONTROL_OVER_MAC;

/* */
/* The extension of the transmit power control over MAC */
/* */
typedef struct _TX_POWER_CONTROL_EXT_OVER_MAC {
	struct {
		unsigned long TxPwrCfg0;	/* MAC 0x1314 */
		unsigned long TxPwrCfg0Ext;	/* MAC 0x1390 */
		unsigned long TxPwrCfg1;	/* MAC 0x1318 */
		unsigned long TxPwrCfg1Ext;	/* MAC 0x1394 */
		unsigned long TxPwrCfg2;	/* MAC 0x131C */
		unsigned long TxPwrCfg2Ext;	/* MAC 0x1398 */
		unsigned long TxPwrCfg3;	/* MAC 0x1320 */
		unsigned long TxPwrCfg3Ext;	/* MAC 0x139C */
		unsigned long TxPwrCfg4;	/* MAC 0x1324 */
		unsigned long TxPwrCfg4Ext;	/* MAC 0x13A0 */
		unsigned long TxPwrCfg5;	/* MAC 0x1384 */
		unsigned long TxPwrCfg6;	/* MAC 0x1388 */
		unsigned long TxPwrCfg7;	/* MAC 0x13D4 */
		unsigned long TxPwrCfg8;	/* MAC 0x13D8 */
		unsigned long TxPwrCfg9;	/* MAC 0x13DC */
	} BW20Over2Dot4G;

	struct {
		unsigned long TxPwrCfg0;	/* MAC 0x1314 */
		unsigned long TxPwrCfg0Ext;	/* MAC 0x1390 */
		unsigned long TxPwrCfg1;	/* MAC 0x1318 */
		unsigned long TxPwrCfg1Ext;	/* MAC 0x1394 */
		unsigned long TxPwrCfg2;	/* MAC 0x131C */
		unsigned long TxPwrCfg2Ext;	/* MAC 0x1398 */
		unsigned long TxPwrCfg3;	/* MAC 0x1320 */
		unsigned long TxPwrCfg3Ext;	/* MAC 0x139C */
		unsigned long TxPwrCfg4;	/* MAC 0x1324 */
		unsigned long TxPwrCfg4Ext;	/* MAC 0x13A0 */
		unsigned long TxPwrCfg5;	/* MAC 0x1384 */
		unsigned long TxPwrCfg6;	/* MAC 0x1388 */
		unsigned long TxPwrCfg7;	/* MAC 0x13D4 */
		unsigned long TxPwrCfg8;	/* MAC 0x13D8 */
		unsigned long TxPwrCfg9;	/* MAC 0x13DC */
	} BW40Over2Dot4G;

	struct {
		unsigned long TxPwrCfg0;	/* MAC 0x1314 */
		unsigned long TxPwrCfg0Ext;	/* MAC 0x1390 */
		unsigned long TxPwrCfg1;	/* MAC 0x1318 */
		unsigned long TxPwrCfg1Ext;	/* MAC 0x1394 */
		unsigned long TxPwrCfg2;	/* MAC 0x131C */
		unsigned long TxPwrCfg2Ext;	/* MAC 0x1398 */
		unsigned long TxPwrCfg3;	/* MAC 0x1320 */
		unsigned long TxPwrCfg3Ext;	/* MAC 0x139C */
		unsigned long TxPwrCfg4;	/* MAC 0x1324 */
		unsigned long TxPwrCfg4Ext;	/* MAC 0x13A0 */
		unsigned long TxPwrCfg5;	/* MAC 0x1384 */
		unsigned long TxPwrCfg6;	/* MAC 0x1388 */
		unsigned long TxPwrCfg7;	/* MAC 0x13D4 */
		unsigned long TxPwrCfg8;	/* MAC 0x13D8 */
		unsigned long TxPwrCfg9;	/* MAC 0x13DC */
	} BW20Over5G;

	struct {
		unsigned long TxPwrCfg0;	/* MAC 0x1314 */
		unsigned long TxPwrCfg0Ext;	/* MAC 0x1390 */
		unsigned long TxPwrCfg1;	/* MAC 0x1318 */
		unsigned long TxPwrCfg1Ext;	/* MAC 0x1394 */
		unsigned long TxPwrCfg2;	/* MAC 0x131C */
		unsigned long TxPwrCfg2Ext;	/* MAC 0x1398 */
		unsigned long TxPwrCfg3;	/* MAC 0x1320 */
		unsigned long TxPwrCfg3Ext;	/* MAC 0x139C */
		unsigned long TxPwrCfg4;	/* MAC 0x1324 */
		unsigned long TxPwrCfg4Ext;	/* MAC 0x13A0 */
		unsigned long TxPwrCfg5;	/* MAC 0x1384 */
		unsigned long TxPwrCfg6;	/* MAC 0x1388 */
		unsigned long TxPwrCfg7;	/* MAC 0x13D4 */
		unsigned long TxPwrCfg8;	/* MAC 0x13D8 */
		unsigned long TxPwrCfg9;	/* MAC 0x13DC */
	} BW40Over5G;
} TX_POWER_CONTROL_EXT_OVER_MAC, *PTX_POWER_CONTROL_EXT_OVER_MAC;

/*
	Packet drop reason code
*/
typedef enum{
	PKT_ATE_ON = 1 << 8,
	PKT_RADAR_ON = 2 << 8,
	PKT_RRM_QUIET = 3 << 8,
	PKT_TX_STOP = 4 <<8,
	PKT_TX_JAM = 5 << 8,

	PKT_NETDEV_DOWN = 6 < 8,
	PKT_NETDEV_NO_MATCH = 7 << 8,
	PKT_NOT_ALLOW_SEND = 8 << 8,

	PKT_INVALID_DST = 9<< 8,
	PKT_INVALID_SRC = 10 << 8,
	PKT_INVALID_PKT_DATA = 11 << 8,
	PKT_INVALID_PKT_LEN = 12 << 8,
	PKT_INVALID_ETH_TYPE = 13 << 8,
	PKT_INVALID_TXBLK_INFO = 14 << 8,
	PKT_INVALID_SW_ENCRYPT = 15 << 8,
	PKT_INVALID_PKT_TYPE = 16 << 8,
	PKT_INVALID_PKT_MIC = 17 << 8,

	PKT_PORT_NOT_SECURE = 18 << 8,
	PKT_TSPEC_NO_MATCH  = 19 << 8,
	PKT_NO_ASSOCED_STA = 20 << 8,
	PKT_INVALID_MAC_ENTRY = 21 << 8,

	PKT_TX_QUE_FULL = 22 << 8,
	PKT_TX_QUE_ADJUST = 23<<8,

	PKT_PS_QUE_TIMEOUT = 24 <<8,
	PKT_PS_QUE_CLEAN = 25 << 8,
	PKT_MCAST_PS_QUE_FULL = 26 << 8,
	PKT_UCAST_PS_QUE_FULL = 27 << 8,

	PKT_RX_EAPOL_SANITY_FAIL = 28 <<8,
	PKT_RX_NOT_TO_KERNEL = 29 << 8,
	PKT_RX_MESH_SIG_FAIL = 30 << 8,
	PKT_APCLI_FAIL = 31 << 8,
	PKT_ZERO_DATA = 32 <<8,
	PKT_SW_DECRYPT_FAIL = 33 << 8,
	PKT_TX_SW_ENC_FAIL = 34 << 8,

	PKT_ACM_FAIL = 35 << 8,
	PKT_IGMP_GRP_FAIL = 36 << 8,
	PKT_MGMT_FAIL = 37 << 8,
	PKT_AMPDU_OUT_ORDER = 38 << 8,
	PKT_UAPSD_EOSP = 39 << 8,
	PKT_UAPSD_Q_FULL = 40 << 8,

	PKT_DRO_REASON_MAX = 41,
}PKT_DROP_REASON;

/* Packet drop Direction code */
typedef enum{
	PKT_TX = 0,
	PKT_RX = 1 << 31,
}PKT_DROP_DIECTION;




typedef struct _BBP_RESET_CTL
{
#define BBP_RECORD_NUM	47
	REG_PAIR BBPRegDB[BBP_RECORD_NUM];
	bool AsicCheckEn;
} BBP_RESET_CTL, *PBBP_RESET_CTL;


typedef struct tx_agc_ctrl{
	bool bAutoTxAgc;	/* Enable driver auto Tx Agc control */
	u8 TssiRef;		/* Store Tssi reference value as 25 temperature. */
	u8 TssiPlusBoundary[5];	/* Tssi boundary for increase Tx power to compensate. */
	u8 TssiMinusBoundary[5];	/* Tssi boundary for decrease Tx power to compensate. */
	u8 TxAgcStep;	/* Store Tx TSSI delta increment / decrement value */
	CHAR TxAgcComp;	/* Store the compensation (TxAgcStep * (idx-1)) */
}TX_AGC_CTRL;


/*
	The miniport adapter structure
*/
struct rtmp_adapter {
	struct os_cookie *OS_Cookie;	/* save specific structure relative to OS */
	struct net_device *net_dev;
	unsigned long VirtualIfCnt;

	//bool PollIdle;

	struct rtmp_chip_ops  chipOps;
	struct rtmp_chip_cap chipCap;

#ifdef CONFIG_STA_SUPPORT
	unsigned short ThisTbttNumToNextWakeUp;
#endif /* CONFIG_STA_SUPPORT */

#ifdef HOSTAPD_SUPPORT
	u32 IoctlIF;
#endif /* HOSTAPD_SUPPORT */

	spinlock_t irq_lock;

	/*======Cmd Thread in PCI/RBUS/USB */
	struct rtmp_command_queue CmdQ;
	spinlock_t CmdQLock;	/* CmdQLock spinlock */
	RTMP_OS_TASK cmdQTask;

#ifdef RTMP_MAC_USB
/*****************************************************************************************/
/*      USB related parameters                                                           */
/*****************************************************************************************/
	unsigned int NumberOfPipes;
	unsigned short BulkOutMaxPacketSize;
	unsigned short BulkInMaxPacketSize;
	u8 BulkOutEpAddr[6];
	u8 BulkInEpAddr[2];

	/*======Control Flags */
	unsigned long BulkFlags;
	bool bUsbTxBulkAggre;	/* Flags for bulk out data priority */

	/*======Cmd Thread */
/*	CmdQ					CmdQ; */
/*	spinlock_t			CmdQLock;				// CmdQLock spinlock */
/*	RTMP_OS_TASK			cmdQTask; */

	/*======Semaphores (event) */
	struct semaphore UsbVendorReq_semaphore;
	struct semaphore reg_atomic;
	struct semaphore hw_atomic;
	struct semaphore cal_atomic;
	struct semaphore wlan_en_atomic;
	struct semaphore mcu_atomic;
	void *UsbVendorReqBuf;
/*	wait_queue_head_t	 *wait; */
	void *wait;

	/* lock for ATE */

#endif /* RTMP_MAC_USB */

/*****************************************************************************************/
/*      RBUS related parameters                                                           								  */
/*****************************************************************************************/

/*****************************************************************************************/
/*      Both PCI/USB related parameters                                                  							  */
/*****************************************************************************************/
	/*RTMP_DEV_INFO                 chipInfo; */
	RTMP_INF_TYPE infType;

/*****************************************************************************************/
/*      Driver Mgmt related parameters                                                  							  */
/*****************************************************************************************/
	RTMP_OS_TASK mlmeTask;
#ifdef RTMP_TIMER_TASK_SUPPORT
	/* If you want use timer task to handle the timer related jobs, enable this. */
	RTMP_TIMER_TASK_QUEUE TimerQ;
	spinlock_t TimerQLock;
	RTMP_OS_TASK timerTask;
#endif /* RTMP_TIMER_TASK_SUPPORT */

/*****************************************************************************************/
/*      Tx related parameters                                                           */
/*****************************************************************************************/
	bool DeQueueRunning[NUM_OF_TX_RING];	/* for ensuring RTUSBDeQueuePacket get call once */
	spinlock_t DeQueueLock[NUM_OF_TX_RING];

#ifdef RTMP_MAC_USB
	/* Data related context and AC specified, 4 AC supported */
	spinlock_t BulkOutLock[6];	/* BulkOut spinlock for 4 ACs */
	spinlock_t MLMEBulkOutLock;	/* MLME BulkOut lock */

	HT_TX_CONTEXT TxContext[NUM_OF_TX_RING];
	spinlock_t TxContextQueueLock[NUM_OF_TX_RING];	/* TxContextQueue spinlock */

	/* 4 sets of Bulk Out index and pending flag */
	/*
	   array size of NextBulkOutIndex must be larger than or equal to 5;
	   Or BulkOutPending[0] will be overwrited in NICInitTransmit().
	 */
	u8 NextBulkOutIndex[NUM_OF_TX_RING];	/* only used for 4 EDCA bulkout pipe */

	bool BulkOutPending[6];	/* used for total 6 bulkout pipe */
	u8 bulkResetPipeid;
	bool MgmtBulkPending;
	unsigned long bulkResetReq[6];

#ifdef CONFIG_STA_SUPPORT
	unsigned short CountDowntoPsm;
#endif /* CONFIG_STA_SUPPORT */

#endif /* RTMP_MAC_USB */

	/* resource for software backlog queues */
	QUEUE_HEADER TxSwQueue[NUM_OF_TX_RING];	/* 4 AC + 1 HCCA */
	spinlock_t TxSwQueueLock[NUM_OF_TX_RING];	/* TxSwQueue spinlock */

	/* Maximum allowed tx software Queue length */
	u32					TxSwQMaxLen;

	RTMP_DMABUF MgmtDescRing;	/* Shared memory for MGMT descriptors */
	RTMP_MGMT_RING MgmtRing;
	spinlock_t MgmtRingLock;	/* Prio Ring spinlock */

#ifdef CONFIG_ANDES_SUPPORT
	RTMP_CTRL_RING CtrlRing;
	spinlock_t CtrlRingLock;	/* Ctrl Ring spinlock */
#endif

	u8 LastMCUCmd;

/*****************************************************************************************/
/*      Rx related parameters                                                           */
/*****************************************************************************************/


#ifdef RTMP_MAC_USB
	RX_CONTEXT RxContext[RX_RING_SIZE];	/* 1 for redundant multiple IRP bulk in. */
	spinlock_t BulkInLock;	/* BulkIn spinlock for 4 ACs */
	spinlock_t CmdRspLock;
	u8 PendingRx;	/* The Maximum pending Rx value should be       RX_RING_SIZE. */
	u8 NextRxBulkInIndex;	/* Indicate the current RxContext Index which hold by Host controller. */
	u8 NextRxBulkInReadIndex;	/* Indicate the current RxContext Index which driver can read & process it. */
	unsigned long NextRxBulkInPosition;	/* Want to contatenate 2 URB buffer while 1st is bulkin failed URB. This Position is 1st URB TransferLength. */
	unsigned long TransferBufferLength;	/* current length of the packet buffer */
	unsigned long ReadPosition;	/* current read position in a packet buffer */

	CMD_RSP_CONTEXT CmdRspEventContext;
#endif /* RTMP_MAC_USB */

/*****************************************************************************************/
/*      ASIC related parameters                                                          */
/*****************************************************************************************/
	u32 MACVersion;	/* MAC version. Record rt2860C(0x28600100) or rt2860D (0x28600101).. */

	/* --------------------------- */
	/* E2PROM */
	/* --------------------------- */
	unsigned long EepromVersion;	/* byte 0: version, byte 1: revision, byte 2~3: unused */
	unsigned long FirmwareVersion;	/* byte 0: Minor version, byte 1: Major version, otherwise unused. */
	unsigned short EEPROMDefaultValue[NUM_EEPROM_BBP_PARMS];
	u8 EEPROMAddressNum;	/* 93c46=6  93c66=8 */
	bool EepromAccess;
	u8 EFuseTag;

	/* --------------------------- */
	/* BBP Control */
	/* --------------------------- */
	u8 BbpWriteLatch[MAX_BBP_ID + 1];	/* record last BBP register value written via BBP_IO_WRITE/BBP_IO_WRITE_VY_REG_ID */
	CHAR BbpRssiToDbmDelta;	/* change from u8 to CHAR for high power */
	BBP_R66_TUNING BbpTuning;

	/* ---------------------------- */
	/* RFIC control */
	/* ---------------------------- */
	u8 RfIcType;		/* RFIC_xxx */
	unsigned long RfFreqOffset;	/* Frequency offset for channel switching */


	RTMP_RF_REGS LatchRfRegs;	/* latch th latest RF programming value since RF IC doesn't support READ */

	EEPROM_ANTENNA_STRUC Antenna;	/* Since ANtenna definition is different for a & g. We need to save it for future reference. */
	EEPROM_NIC_CONFIG2_STRUC NicConfig2;

	/* This soft Rx Antenna Diversity mechanism is used only when user set */
	/* RX Antenna = DIVERSITY ON */
	SOFT_RX_ANT_DIVERSITY RxAnt;

	CHANNEL_TX_POWER TxPower[MAX_NUM_OF_CHANNELS];	/* Store Tx power value for all channels. */
	CHANNEL_TX_POWER ChannelList[MAX_NUM_OF_CHANNELS];	/* list all supported channels for site survey */



	u8 ChannelListNum;	/* number of channel in ChannelList[] */
	u8 Bbp94;
	bool BbpForCCK;
#ifdef DOT11_VHT_AC
	unsigned long Tx80MPwrCfgABand[MAX_TXPOWER_ARRAY_SIZE]; // Per-rate Tx power control for VHT BW80 (5GHz only)
#endif /* DOT11_VHT_AC */


	bool bAutoTxAgcA;	/* Enable driver auto Tx Agc control */
	u8 TssiRefA;		/* Store Tssi reference value as 25 temperature. */
	u8 TssiPlusBoundaryA[2][8];	/* Tssi boundary for increase Tx power to compensate. [Group][Boundary Index]*/
	u8 TssiMinusBoundaryA[2][8];	/* Tssi boundary for decrease Tx power to compensate. [Group][Boundary Index]*/
	u8 TxAgcStepA;	/* Store Tx TSSI delta increment / decrement value */
	CHAR TxAgcCompensateA;	/* Store the compensation (TxAgcStep * (idx-1)) */

	bool bAutoTxAgcG;	/* Enable driver auto Tx Agc control */
	u8 TssiRefG;		/* Store Tssi reference value as 25 temperature. */
	u8 TssiPlusBoundaryG[8];	/* Tssi boundary for increase Tx power to compensate. */
	u8 TssiMinusBoundaryG[8];	/* Tssi boundary for decrease Tx power to compensate. */
	u8 TxAgcStepG;	/* Store Tx TSSI delta increment / decrement value */
	CHAR TxAgcCompensateG;	/* Store the compensation (TxAgcStep * (idx-1)) */

	CHAR TssiCalibratedOffset;	/* reference temperature(e2p[D1h]) */
	u8 ChBndryIdx;			/* 5G Channel Group Boundary Index for Temperature Compensation */

	CHAR mp_delta_pwr;			 /* calculated by MP ATE temperature */
	CHAR CurrTemperature;
	CHAR DeltaPwrBeforeTempComp;
	CHAR LastTempCompDeltaPwr;

	signed char BGRssiOffset[3]; /* Store B/G RSSI #0/1/2 Offset value on EEPROM 0x46h */
	signed char ARssiOffset[3]; /* Store A RSSI 0/1/2 Offset value on EEPROM 0x4Ah */

	CHAR BLNAGain;		/* Store B/G external LNA#0 value on EEPROM 0x44h */
	CHAR ALNAGain0;		/* Store A external LNA#0 value for ch36~64 */
	CHAR ALNAGain1;		/* Store A external LNA#1 value for ch100~128 */
	CHAR ALNAGain2;		/* Store A external LNA#2 value for ch132~165 */


#ifdef LED_CONTROL_SUPPORT
	/* LED control */
	struct mt7610u_led_control LedCntl;
#endif /* LED_CONTROL_SUPPORT */

	/* ---------------------------- */
	/* MAC control */
	/* ---------------------------- */

#if defined(RT65xx)

	union rtmp_wlan_func_ctrl WlanFunCtrl;
#endif /* defined(RT65xx) */

	struct hw_setting hw_cfg;

/*****************************************************************************************/
/*      802.11 related parameters                                                        */
/*****************************************************************************************/
	/* outgoing BEACON frame buffer and corresponding TXD */
	struct txwi_nmac BeaconTxWI;
	u8 *BeaconBuf;
	unsigned short BeaconOffset[HW_BEACON_MAX_NUM];

	/* pre-build PS-POLL and NULL frame upon link up. for efficiency purpose. */
#ifdef CONFIG_STA_SUPPORT
	PSPOLL_FRAME PsPollFrame;
#endif /* CONFIG_STA_SUPPORT */
	HEADER_802_11 NullFrame;

#ifdef RTMP_MAC_USB
	TX_CONTEXT NullContext;
	TX_CONTEXT PsPollContext;
#endif /* RTMP_MAC_USB */


#ifdef UAPSD_SUPPORT
	spinlock_t UAPSDEOSPLock;	/* EOSP frame access lock use */
	bool bAPSDFlagSPSuspend;	/* 1: SP is suspended; 0: SP is not */
#endif /* UAPSD_SUPPORT */

/*=======STA=========== */
#ifdef CONFIG_STA_SUPPORT
	/* ----------------------------------------------- */
	/* STA specific configuration & operation status */
	/* used only when pAd->OpMode == OPMODE_STA */
	/* ----------------------------------------------- */
	STA_ADMIN_CONFIG StaCfg;	/* user desired settings */
	STA_ACTIVE_CONFIG StaActive;	/* valid only when ADHOC_ON(pAd) || INFRA_ON(pAd) */
	NDIS_MEDIA_STATE PreMediaState;
#endif /* CONFIG_STA_SUPPORT */

/*=======Common=========== */
	/* OP mode: either AP or STA */
	u8 OpMode;		/* OPMODE_STA, OPMODE_AP */

	enum RATE_ADAPT_ALG rateAlg;		/* Rate adaptation algorithm */

	NDIS_MEDIA_STATE IndicateMediaState;	/* Base on Indication state, default is NdisMediaStateDisConnected */

	/* MAT related parameters */


	/*
		Frequency setting for rate adaptation
			@ra_interval: 		for baseline time interval
			@ra_fast_interval:	for quick response time interval
	*/
	u32			ra_interval;
	u32			ra_fast_interval;

	/* configuration: read from Registry & E2PROM */
	bool bLocalAdminMAC;	/* Use user changed MAC */
	u8 PermanentAddress[ETH_ALEN];	/* Factory default MAC address */
	u8 CurrentAddress[ETH_ALEN];	/* User changed MAC address */

	/* ------------------------------------------------------ */
	/* common configuration to both OPMODE_STA and OPMODE_AP */
	/* ------------------------------------------------------ */
	struct common_config CommonCfg;
	MLME_STRUCT Mlme;

	/* AP needs those vaiables for site survey feature. */
	MLME_AUX MlmeAux;	/* temporary settings used during MLME state machine */
#if defined(AP_SCAN_SUPPORT) || defined(CONFIG_STA_SUPPORT)
	BSS_TABLE ScanTab;	/* store the latest SCAN result */
#endif /* defined(AP_SCAN_SUPPORT) || defined(CONFIG_STA_SUPPORT) */

	/*About MacTab, the sta driver will use #0 and #1 for multicast and AP. */
	MAC_TABLE MacTab;	/* ASIC on-chip WCID entry table.  At TX, ASIC always use key according to this on-chip table. */
	spinlock_t MacTabLock;

#ifdef DOT11_N_SUPPORT
	BA_TABLE BATable;
	spinlock_t BATabLock;
	RALINK_TIMER_STRUCT RECBATimer;
#endif /* DOT11_N_SUPPORT */

	/* DOT11_H */
	DOT11_H Dot11_H;

	/* encryption/decryption KEY tables */
	CIPHER_KEY SharedKey[HW_BEACON_MAX_NUM + MAX_P2P_NUM][4];	/* STA always use SharedKey[BSS0][0..3] */

	/* RX re-assembly buffer for fragmentation */
	FRAGMENT_FRAME FragFrame;	/* Frame storage for fragment frame */

	/* various Counters */
	COUNTER_802_3 Counters8023;	/* 802.3 counters */
	COUNTER_802_11 WlanCounters;	/* 802.11 MIB counters */
	COUNTER_RALINK RalinkCounters;	/* Ralink propriety counters */
	/* COUNTER_DRS DrsCounters;	*/ /* counters for Dynamic TX Rate Switching */
	PRIVATE_STRUC PrivateInfo;	/* Private information & counters */

	/* flags, see fRTMP_ADAPTER_xxx flags */
	unsigned long Flags;		/* Represent current device status */
	unsigned long PSFlags;		/* Power Save operation flag. */
	unsigned long MoreFlags;	/* Represent specific requirement */

	/* current TX sequence # */
	unsigned short Sequence;

	/* Control disconnect / connect event generation */
	/*+++Didn't used anymore */
	unsigned long LinkDownTime;
	/*--- */
	unsigned long LastRxRate;
	unsigned long LastTxRate;
	/*+++Used only for Station */
	bool bConfigChanged;	/* Config Change flag for the same SSID setting */
	/*--- */

	unsigned long ExtraInfo;	/* Extra information for displaying status */
	unsigned long SystemErrorBitmap;	/* b0: E2PROM version error */

	bool HTCEnable;

	/*****************************************************************************************/
	/*      Statistic related parameters                                                     */
	/*****************************************************************************************/
#ifdef RTMP_MAC_USB
	unsigned long BulkOutDataOneSecCount;
	unsigned long BulkInDataOneSecCount;
	unsigned long BulkLastOneSecCount;	/* BulkOutDataOneSecCount + BulkInDataOneSecCount */
	unsigned long watchDogRxCnt;
	unsigned long watchDogRxOverFlowCnt;
	unsigned long watchDogTxPendingCnt[NUM_OF_TX_RING];
#endif /* RTMP_MAC_USB */

	bool bUpdateBcnCntDone;

	unsigned long macwd;
	/* ---------------------------- */
	/* DEBUG paramerts */
	/* ---------------------------- */

	/* ---------------------------- */
	/* rt2860c emulation-use Parameters */
	/* ---------------------------- */
	/*unsigned long         rtsaccu[30]; */
	/*unsigned long         ctsaccu[30]; */
	/*unsigned long         cfendaccu[30]; */
	/*unsigned long         bacontent[16]; */
	/*unsigned long         rxint[RX_RING_SIZE+1]; */
	/*u8         rcvba[60]; */
	bool bLinkAdapt;
	bool bForcePrintTX;
	bool bForcePrintRX;
	/*bool               bDisablescanning;               //defined in RT2870 USB */
	bool bStaFifoTest;
	bool bProtectionTest;
	bool bHCCATest;
	bool bGenOneHCCA;
	bool bBroadComHT;
	/*+++Following add from RT2870 USB. */
	unsigned long BulkOutReq;
	unsigned long BulkOutComplete;
	unsigned long BulkOutCompleteOther;
	unsigned long BulkOutCompleteCancel;	/* seems not use now? */
	unsigned long BulkInReq;
	unsigned long BulkInComplete;
	unsigned long BulkInCompleteFail;
	/*--- */

	struct wificonf WIFItestbed;

	u8 	TssiGain;

#ifdef DOT11_N_SUPPORT
	struct reordering_mpdu_pool mpdu_blk_pool;
#endif /* DOT11_N_SUPPORT */

	/* statistics count */

	void *iw_stats;
	void *stats;

#ifdef BLOCK_NET_IF
	BLOCK_QUEUE_ENTRY blockQueueTab[NUM_OF_TX_RING];
#endif /* BLOCK_NET_IF */

	unsigned long TbttTickCount;	/* beacon timestamp work-around */
#ifdef PCI_MSI_SUPPORT
	bool HaveMsi;
#endif /* PCI_MSI_SUPPORT */


	/* for detect_wmm_traffic() BE TXOP use */
	unsigned long OneSecondnonBEpackets;	/* record non BE packets per second */
	u8 is_on;

	/* for detect_wmm_traffic() BE/BK TXOP use */
#define TIME_BASE			(1000000/OS_HZ)
#define TIME_ONE_SECOND		(1000000/TIME_BASE)
	u8 flg_be_adjust;
	unsigned long be_adjust_last_time;

#ifdef NINTENDO_AP
	NINDO_CTRL_BLOCK nindo_ctrl_block;
#endif /* NINTENDO_AP */

#ifdef DBG_DIAGNOSE
	RtmpDiagStruct DiagStruct;
#endif /* DBG_DIAGNOSE */


	u8 FlgCtsEnabled;
	u8 PM_FlgSuspend;

#ifdef CONFIG_STA_SUPPORT
#endif /* CONFIG_STA_SUPPORT */

	EXT_CAP_INFO_ELEMENT ExtCapInfo;


	u8 FifoUpdateDone, FifoUpdateRx;

	u8 RFICType;

#ifdef LINUX
#ifdef RT_CFG80211_SUPPORT
	void *pCfgDev;
	void *pCfg80211_CB;

	bool FlgCfg80211Scanning;
	bool FlgCfg80211Connecting;
	u8 Cfg80211_Alpha2[2];
#endif /* RT_CFG80211_SUPPORT */
#endif /* LINUX */


	u32 ContinueMemAllocFailCount;

	struct {
		INT IeLen;
		u8 *pIe;
	} ProbeRespIE[MAX_LEN_OF_BSS_TABLE];

	/* purpose: We free all kernel resources when module is removed */
	LIST_HEADER RscTimerMemList;	/* resource timers memory */
	LIST_HEADER RscTaskMemList;	/* resource tasks memory */
	LIST_HEADER RscLockMemList;	/* resource locks memory */
	LIST_HEADER RscTaskletMemList;	/* resource tasklets memory */
	LIST_HEADER RscSemMemList;	/* resource semaphore memory */
	LIST_HEADER RscAtomicMemList;	/* resource atomic memory */

	/* purpose: Cancel all timers when module is removed */
	LIST_HEADER RscTimerCreateList;	/* timers list */


#ifdef WLAN_SKB_RECYCLE
    struct sk_buff_head rx0_recycle;
#endif /* WLAN_SKB_RECYCLE */

#ifdef WFA_VHT_PF
	bool force_amsdu;
	bool force_noack;
	bool vht_force_sgi;
	bool vht_force_tx_stbc;
#ifdef IP_ASSEMBLY
	bool ip_assemble;
#endif /* IP_ASSEMBLY */
#endif /* WFA_VHT_PF */

	u8 bloopBackTest;
	bool bHwTxLookupRate;
	struct txwi_nmac NullTxWI;
	bool TestMulMac;

	struct mt7610u_mcu_ctrl MCUCtrl;
};


/***************************************************************************
  *	Rx Path software control block related data structures
  **************************************************************************/
typedef struct _RX_BLK_
{
	u8 hw_rx_info[RXD_SIZE]; /* include "RXD_STRUC RxD" and "RXINFO_STRUC rx_info " */
	struct rtmp_rxinfo *pRxInfo;
	RXFCE_INFO *pRxFceInfo;
	struct rxwi_nmac *pRxWI;
	PHEADER_802_11 pHeader;
	struct sk_buff * pRxPacket;
	u8 *pData;
	unsigned short DataSize;
	unsigned short Flags;
	u8 UserPriority;	/* for calculate TKIP MIC using */
	u8 OpMode;	/* 0:OPMODE_STA 1:OPMODE_AP */
	u8 wcid;		/* copy of pRxWI->RxWIWirelessCliID */
	u8 mcs;
	u8 U2M;
} RX_BLK;


#define RX_BLK_SET_FLAG(_pRxBlk, _flag)		(_pRxBlk->Flags |= _flag)
#define RX_BLK_TEST_FLAG(_pRxBlk, _flag)		(_pRxBlk->Flags & _flag)
#define RX_BLK_CLEAR_FLAG(_pRxBlk, _flag)	(_pRxBlk->Flags &= ~(_flag))


#define fRX_WDS			0x0001
#define fRX_AMSDU		0x0002
#define fRX_ARALINK		0x0004
#define fRX_HTC			0x0008
#define fRX_PAD			0x0010
#define fRX_AMPDU		0x0020
#define fRX_QOS			0x0040
#define fRX_INFRA		0x0080
#define fRX_EAP			0x0100
#define fRX_MESH		0x0200
#define fRX_APCLI		0x0400
#define fRX_DLS			0x0800
#define fRX_WPI			0x1000
#define fRX_P2PGO		0x2000
#define fRX_P2PCLI		0x4000

#define LENGTH_AMSDU_SUBFRAMEHEAD	14
#define LENGTH_ARALINK_SUBFRAMEHEAD	14
#define LENGTH_ARALINK_HEADER_FIELD	 2


/***************************************************************************
  *	Tx Path software control block related data structures
  **************************************************************************/
#define TX_UNKOWN_FRAME		0x00
#define TX_MCAST_FRAME			0x01
#define TX_LEGACY_FRAME		0x02
#define TX_AMPDU_FRAME		0x04
#define TX_AMSDU_FRAME		0x08
#define TX_RALINK_FRAME		0x10
#define TX_FRAG_FRAME			0x20


/*	Currently the sizeof(TX_BLK) is 148 bytes. */
typedef struct _TX_BLK_
{
	u8 			QueIdx;
	u8 			TxFrameType;				/* Indicate the Transmission type of the all frames in one batch */
	u8 			TotalFrameNum;				/* Total frame number want to send-out in one batch */
	unsigned short				TotalFragNum;				/* Total frame fragments required in one batch */
	unsigned short				TotalFrameLen;				/* Total length of all frames want to send-out in one batch */

	QUEUE_HEADER		TxPacketList;
	MAC_TABLE_ENTRY	*pMacEntry;					/* NULL: packet with 802.11 RA field is multicast/broadcast address */
	HTTRANSMIT_SETTING	*pTransmit;

	/* Following structure used for the characteristics of a specific packet. */
	struct sk_buff *		pPacket;
	u8 *			pSrcBufHeader;				/* Reference to the head of sk_buff->data */
	u8 *			pSrcBufData;				/* Reference to the sk_buff->data, will changed depends on hanlding progresss */
	unsigned int				SrcBufLen;					/* Length of packet payload which not including Layer 2 header */

	u8 *			pExtraLlcSnapEncap;			/* NULL means no extra LLC/SNAP is required */
	u32				HeaderBuffer[32];			/* total 128B, use u32 to avoid alignment problem */
	u8 			*HeaderBuf;
	u8 			MpduHeaderLen;				/* 802.11 header length NOT including the padding */
	u8 			HdrPadLen;					/* recording Header Padding Length; */
	u8 			apidx;						/* The interface associated to this packet */
	u8 			Wcid;						/* The MAC entry associated to this packet */
	u8 			UserPriority;				/* priority class of packet */
	u8 			FrameGap;					/* what kind of IFS this packet use */
	u8 			MpduReqNum;					/* number of fragments of this frame */
	u8 			TxRate;						/* TODO: Obsoleted? Should change to MCS? */
	u8 			CipherAlg;					/* cipher alogrithm */
	PCIPHER_KEY			pKey;
	u8 			KeyIdx;						/* Indicate the transmit key index */


	u32				Flags;						/*See following definitions for detail. */

	/*YOU SHOULD NOT TOUCH IT! Following parameters are used for hardware-depended layer. */
	unsigned long				Priv;						/* Hardware specific value saved in here. */

	u8 			naf_type;
#ifdef TX_PKT_SG
	PACKET_INFO pkt_info;
#endif /* TX_PKT_SG */
	u8 			OpMode;

} TX_BLK, *PTX_BLK;


#define fTX_bRtsRequired			0x0001	/* Indicate if need send RTS frame for protection. Not used in RT2860/RT2870. */
#define fTX_bAckRequired			0x0002	/* the packet need ack response */
#define fTX_bPiggyBack			0x0004	/* Legacy device use Piggback or not */
#define fTX_bHTRate				0x0008	/* allow to use HT rate */
#define fTX_bForceNonQoS		0x0010	/* force to transmit frame without WMM-QoS in HT mode */
#define fTX_bAllowFrag			0x0020	/* allow to fragment the packet, A-MPDU, A-MSDU, A-Ralink is not allowed to fragment */
#define fTX_bMoreData			0x0040	/* there are more data packets in PowerSave Queue */
#define fTX_bWMM				0x0080	/* QOS Data */
#define fTX_bClearEAPFrame		0x0100

#define	fTX_bSwEncrypt			0x0400	/* this packet need to be encrypted by software before TX */

#ifdef UAPSD_SUPPORT
#define	fTX_bWMM_UAPSD_EOSP	0x0800	/* Used when UAPSD_SUPPORT */
#endif /* UAPSD_SUPPORT */

#ifdef CONFIG_STA_SUPPORT
#endif /* CONFIG_STA_SUPPORT */



#ifdef CLIENT_WDS
#define fTX_bClientWDSFrame		0x10000
#endif /* CLIENT_WDS */


#define TX_BLK_SET_FLAG(_pTxBlk, _flag)		(_pTxBlk->Flags |= _flag)
#define TX_BLK_TEST_FLAG(_pTxBlk, _flag)	(((_pTxBlk->Flags & _flag) == _flag) ? 1 : 0)
#define TX_BLK_CLEAR_FLAG(_pTxBlk, _flag)	(_pTxBlk->Flags &= ~(_flag))


static inline void RTMPWIEndianChange(u8 *pData, int size)
{
	int i;

	for(i=0; i < size/4 ; i++)
			*(((u32 *)pData) +i) = SWAP32(*(((u32 *)pData)+i));
}


#ifdef RT_BIG_ENDIAN
/***************************************************************************
  *	Endian conversion related functions
  **************************************************************************/
/*
	========================================================================

	Routine Description:
		Endian conversion of Tx/Rx descriptor .

	Arguments:
		pAd 	Pointer to our adapter
		pData			Pointer to Tx/Rx descriptor
		DescriptorType	Direction of the frame

	Return Value:
		None

	Note:
		Call this function when read or update descriptor
	========================================================================
*/
static inline void RTMPWIEndianChange(u8 *pData, int size)
{
	int i;

	for(i=0; i < size/4 ; i++)
			*(((u32 *)pData) +i) = SWAP32(*(((u32 *)pData)+i));
}




/*
	========================================================================

	Routine Description:
		Endian conversion of Tx/Rx descriptor .

	Arguments:
		pAd 	Pointer to our adapter
		pData			Pointer to Tx/Rx descriptor
		DescriptorType	Direction of the frame

	Return Value:
		None

	Note:
		Call this function when read or update descriptor
	========================================================================
*/

#ifdef RTMP_MAC_USB
static inline void RTMPDescriptorEndianChange(u8 *pData, unsigned long DescType)
{
	*((u32 *)(pData)) = SWAP32(*((u32 *)(pData)));
}
#endif /* RTMP_MAC_USB */
/*
	========================================================================

	Routine Description:
		Endian conversion of all kinds of 802.11 frames .

	Arguments:
		pAd 	Pointer to our adapter
		pData			Pointer to the 802.11 frame structure
		Dir 			Direction of the frame
		FromRxDoneInt	Caller is from RxDone interrupt

	Return Value:
		None

	Note:
		Call this function when read or update buffer data
	========================================================================
*/
static inline void RTMPFrameEndianChange(
	struct rtmp_adapter *pAd,
	u8 *		pData,
	unsigned long			Dir,
	bool 		FromRxDoneInt)
{
	PHEADER_802_11 pFrame;
	u8 *pMacHdr;

	/* swab 16 bit fields - Frame Control field */
	if(Dir == DIR_READ)
	{
		*(unsigned short *)pData = SWAP16(*(unsigned short *)pData);
	}

	pFrame = (PHEADER_802_11) pData;
	pMacHdr = (u8 *) pFrame;

	/* swab 16 bit fields - Duration/ID field */
	*(unsigned short *)(pMacHdr + 2) = SWAP16(*(unsigned short *)(pMacHdr + 2));

	if (pFrame->FC.Type != BTYPE_CNTL)
	{
		/* swab 16 bit fields - Sequence Control field */
		*(unsigned short *)(pMacHdr + 22) = SWAP16(*(unsigned short *)(pMacHdr + 22));
	}

	if(pFrame->FC.Type == BTYPE_MGMT)
	{
		switch(pFrame->FC.SubType)
		{
			case SUBTYPE_ASSOC_REQ:
			case SUBTYPE_REASSOC_REQ:
				/* swab 16 bit fields - CapabilityInfo field */
				pMacHdr += sizeof(HEADER_802_11);
				*(unsigned short *)pMacHdr = SWAP16(*(unsigned short *)pMacHdr);

				/* swab 16 bit fields - Listen Interval field */
				pMacHdr += 2;
				*(unsigned short *)pMacHdr = SWAP16(*(unsigned short *)pMacHdr);
				break;

			case SUBTYPE_ASSOC_RSP:
			case SUBTYPE_REASSOC_RSP:
				/* swab 16 bit fields - CapabilityInfo field */
				pMacHdr += sizeof(HEADER_802_11);
				*(unsigned short *)pMacHdr = SWAP16(*(unsigned short *)pMacHdr);

				/* swab 16 bit fields - Status Code field */
				pMacHdr += 2;
				*(unsigned short *)pMacHdr = SWAP16(*(unsigned short *)pMacHdr);

				/* swab 16 bit fields - AID field */
				pMacHdr += 2;
				*(unsigned short *)pMacHdr = SWAP16(*(unsigned short *)pMacHdr);
				break;

			case SUBTYPE_AUTH:
				 /* When the WEP bit is on, don't do the conversion here.
					This is only shared WEP can hit this condition.
					For AP, it shall do conversion after decryption.
					For STA, it shall do conversion before encryption. */
				if (pFrame->FC.Wep == 1)
					break;
				else
				{
					/* swab 16 bit fields - Auth Alg No. field */
					pMacHdr += sizeof(HEADER_802_11);
					*(unsigned short *)pMacHdr = SWAP16(*(unsigned short *)pMacHdr);

					/* swab 16 bit fields - Auth Seq No. field */
					pMacHdr += 2;
					*(unsigned short *)pMacHdr = SWAP16(*(unsigned short *)pMacHdr);

					/* swab 16 bit fields - Status Code field */
					pMacHdr += 2;
					*(unsigned short *)pMacHdr = SWAP16(*(unsigned short *)pMacHdr);
				}
				break;

			case SUBTYPE_BEACON:
			case SUBTYPE_PROBE_RSP:
				/* swab 16 bit fields - BeaconInterval field */
				pMacHdr += (sizeof(HEADER_802_11) + TIMESTAMP_LEN);
				*(unsigned short *)pMacHdr = SWAP16(*(unsigned short *)pMacHdr);

				/* swab 16 bit fields - CapabilityInfo field */
				pMacHdr += sizeof(unsigned short);
				*(unsigned short *)pMacHdr = SWAP16(*(unsigned short *)pMacHdr);
				break;

			case SUBTYPE_DEAUTH:
			case SUBTYPE_DISASSOC:
				/* If the PMF is negotiated, those frames shall be encrypted */
				if(!FromRxDoneInt && pFrame->FC.Wep == 1)
					break;
				else
				{
					/* swab 16 bit fields - Reason code field */
					pMacHdr += sizeof(HEADER_802_11);
					*(unsigned short *)pMacHdr = SWAP16(*(unsigned short *)pMacHdr);
				}
				break;
		}
	}
	else if( pFrame->FC.Type == BTYPE_DATA )
	{
	}
	else if(pFrame->FC.Type == BTYPE_CNTL)
	{
		switch(pFrame->FC.SubType)
		{
			case SUBTYPE_BLOCK_ACK_REQ:
				{
					PFRAME_BA_REQ pBAReq = (PFRAME_BA_REQ)pFrame;
					*(unsigned short *)(&pBAReq->BARControl) = SWAP16(*(unsigned short *)(&pBAReq->BARControl));
					pBAReq->BAStartingSeq.word = SWAP16(pBAReq->BAStartingSeq.word);
				}
				break;
			case SUBTYPE_BLOCK_ACK:
				/* For Block Ack packet, the HT_CONTROL field is in the same offset with Addr3 */
				*(u32 *)(&pFrame->Addr3[0]) = SWAP32(*(u32 *)(&pFrame->Addr3[0]));
				break;

			case SUBTYPE_ACK:
				/*For ACK packet, the HT_CONTROL field is in the same offset with Addr2 */
				*(u32 *)(&pFrame->Addr2[0])=	SWAP32(*(u32 *)(&pFrame->Addr2[0]));
				break;
		}
	}
	else
	{
		DBGPRINT(RT_DEBUG_ERROR,("Invalid Frame Type!!!\n"));
	}

	/* swab 16 bit fields - Frame Control */
	if(Dir == DIR_WRITE)
	{
		*(unsigned short *)pData = SWAP16(*(unsigned short *)pData);
	}
}
#endif /* RT_BIG_ENDIAN */


/***************************************************************************
  *	Other static inline function definitions
  **************************************************************************/
static inline void ConvertMulticastIP2MAC(
	u8 *pIpAddr,
	u8 **ppMacAddr,
	uint16_t ProtoType)
{
	if (pIpAddr == NULL)
		return;

	if (ppMacAddr == NULL || *ppMacAddr == NULL)
		return;

	switch (ProtoType)
	{
		case ETH_P_IPV6:
/*			memset(*ppMacAddr, 0, ETH_LENGTH_OF_ADDRESS); */
			*(*ppMacAddr) = 0x33;
			*(*ppMacAddr + 1) = 0x33;
			*(*ppMacAddr + 2) = pIpAddr[12];
			*(*ppMacAddr + 3) = pIpAddr[13];
			*(*ppMacAddr + 4) = pIpAddr[14];
			*(*ppMacAddr + 5) = pIpAddr[15];
			break;

		case ETH_P_IP:
		default:
/*			memset(*ppMacAddr, 0, ETH_LENGTH_OF_ADDRESS); */
			*(*ppMacAddr) = 0x01;
			*(*ppMacAddr + 1) = 0x00;
			*(*ppMacAddr + 2) = 0x5e;
			*(*ppMacAddr + 3) = pIpAddr[1] & 0x7f;
			*(*ppMacAddr + 4) = pIpAddr[2];
			*(*ppMacAddr + 5) = pIpAddr[3];
			break;
	}

	return;
}


char *get_phymode_str(int phy_mode);
char *get_bw_str(int bandwidth);

/*
	Private routines in rtmp_init.c
*/
int RTMPAllocTxRxRingMemory(
	struct rtmp_adapter *  pAd);

#ifdef RESOURCE_PRE_ALLOC
int RTMPInitTxRxRingMemory(
	struct rtmp_adapter*pAd);
#endif /* RESOURCE_PRE_ALLOC */

int	RTMPReadParametersHook(
	struct rtmp_adapter *pAd);

int	RTMPSetProfileParameters(
	struct rtmp_adapter*pAd,
	char *	pBuffer);

INT RTMPGetKeyParameter(
    char *key,
    char *dest,
    INT destsize,
    char *buffer,
    bool bTrimSpace);




#ifdef RLT_RF
int rlt_rf_write(
	struct rtmp_adapter*pAd,
	u8 bank,
	u8 regID,
	u8 value);

int rlt_rf_read(
	struct rtmp_adapter*pAd,
	u8 bank,
	u8 regID,
	u8 *pValue);
#endif /* RLT_RF */

void NICReadEEPROMParameters(
	struct rtmp_adapter *pAd);

void NICInitAsicFromEEPROM(
	struct rtmp_adapter *      pAd);

int NICInitializeAdapter(
	struct rtmp_adapter *  pAd,
	bool    bHardReset);

int NICInitializeAsic(
	struct rtmp_adapter *  pAd,
	bool 	bHardReset);


void RTMPRingCleanUp(
	struct rtmp_adapter *  pAd,
	u8           RingType);

void UserCfgExit(
	struct rtmp_adapter*pAd);

void UserCfgInit(
	struct rtmp_adapter *  pAd);

int NICLoadFirmware(
	struct rtmp_adapter *  pAd);

void NICUpdateFifoStaCounters(
	struct rtmp_adapter *pAd);

void NICUpdateRawCounters(
	struct rtmp_adapter *  pAd);

void NicResetRawCounters(struct rtmp_adapter*pAd);

void NicGetTxRawCounters(
	struct rtmp_adapter*pAd,
	TX_STA_CNT0_STRUC *pStaTxCnt0,
	TX_STA_CNT1_STRUC *pStaTxCnt1);

unsigned long RTMPCompareMemory(
	void *  pSrc1,
	void *  pSrc2,
	unsigned long   Length);

void AtoH(
	char *src,
	u8 *dest,
	int		destlen);

u8 BtoH(
	char ch);

void RTMP_TimerListAdd(
	struct rtmp_adapter *		pAd,
	void 				*pRsc);

void RTMP_TimerListRelease(
	struct rtmp_adapter *		pAd);

void RTMPInitTimer(
	struct rtmp_adapter *          pAd,
	PRALINK_TIMER_STRUCT    pTimer,
	void *                  pTimerFunc,
	void *				pData,
	bool                 Repeat);

void RTMPSetTimer(
	PRALINK_TIMER_STRUCT    pTimer,
	unsigned long                   Value);


void RTMPModTimer(
	PRALINK_TIMER_STRUCT	pTimer,
	unsigned long					Value);

void RTMPCancelTimer(
	PRALINK_TIMER_STRUCT    pTimer,
	bool                 *pCancelled);

void RTMPReleaseTimer(
	PRALINK_TIMER_STRUCT    pTimer,
	bool                 *pCancelled);

void RTMPEnableRxTx(
	struct rtmp_adapter *pAd);

void AntCfgInit(
	struct rtmp_adapter *  pAd);

/* */
/* prototype in action.c */
/* */
void ActionStateMachineInit(
    struct rtmp_adapter *pAd,
    STATE_MACHINE *S,
    STATE_MACHINE_FUNC Trans[]);

void MlmeADDBAAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

void MlmeDELBAAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

void MlmeDLSAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

void MlmeInvalidAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

void MlmeQOSAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

#ifdef DOT11_N_SUPPORT
void PeerAddBAReqAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerAddBARspAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerDelBAAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerBAAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);
#endif /* DOT11_N_SUPPORT */

void SendPSMPAction(
	struct rtmp_adapter *pAd,
	u8 		Wcid,
	u8 		Psmp);


void PeerRMAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerPublicAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

#ifdef CONFIG_STA_SUPPORT
void StaPublicAction(
	struct rtmp_adapter *pAd,
	BSS_2040_COEXIST_IE *pBss2040CoexIE);
#endif /* CONFIG_STA_SUPPORT */


void PeerBSSTranAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

#ifdef DOT11_N_SUPPORT
void PeerHTAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);
#endif /* DOT11_N_SUPPORT */

void PeerQOSAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

#ifdef QOS_DLS_SUPPORT
void PeerDLSAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);
#endif /* QOS_DLS_SUPPORT */

#ifdef CONFIG_STA_SUPPORT
#ifdef QOS_DLS_SUPPORT
void DlsParmFill(
	struct rtmp_adapter *pAd,
	MLME_DLS_REQ_STRUCT *pDlsReq,
	PRT_802_11_DLS pDls,
	unsigned short reason);
#endif /* QOS_DLS_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */

#ifdef DOT11_N_SUPPORT
void RECBATimerTimeout(
    void *SystemSpecific1,
    void *FunctionContext,
    void *SystemSpecific2,
    void *SystemSpecific3);

void ORIBATimerTimeout(
	struct rtmp_adapter *pAd);

void SendRefreshBAR(
	struct rtmp_adapter *pAd,
	MAC_TABLE_ENTRY	*pEntry);

#ifdef DOT11N_DRAFT3
void RTMP_11N_D3_TimerInit(
	struct rtmp_adapter *pAd);

void SendBSS2040CoexistMgmtAction(
	struct rtmp_adapter *pAd,
	u8 Wcid,
	u8 apidx,
	u8 InfoReq);

void SendNotifyBWActionFrame(
	struct rtmp_adapter *pAd,
	u8  Wcid,
	u8 apidx);

bool ChannelSwitchSanityCheck(
	struct rtmp_adapter *pAd,
	u8  Wcid,
	u8  NewChannel,
	u8  Secondary);

void ChannelSwitchAction(
	struct rtmp_adapter *pAd,
	u8  Wcid,
	u8  Channel,
	u8  Secondary);

unsigned long BuildIntolerantChannelRep(
	struct rtmp_adapter *pAd,
	u8 * pDest);

void Update2040CoexistFrameAndNotify(
	struct rtmp_adapter *pAd,
	u8  Wcid,
	bool bAddIntolerantCha);

void Send2040CoexistAction(
	struct rtmp_adapter *pAd,
	u8  Wcid,
	bool bAddIntolerantCha);

void UpdateBssScanParm(
	struct rtmp_adapter *pAd,
	OVERLAP_BSS_SCAN_IE APBssScan);
#endif /* DOT11N_DRAFT3 */

void AsicEnableRalinkBurstMode(
	struct rtmp_adapter *pAd);

void AsicDisableRalinkBurstMode(
	struct rtmp_adapter *pAd);
#endif /* DOT11_N_SUPPORT */

void ActHeaderInit(
    struct rtmp_adapter *pAd,
    PHEADER_802_11 pHdr80211,
    u8 *Addr1,
    u8 *Addr2,
    u8 *Addr3);

void BarHeaderInit(
	struct rtmp_adapter *pAd,
	PFRAME_BAR pCntlBar,
	u8 *pDA,
	u8 *pSA);

void InsertActField(
	struct rtmp_adapter *pAd,
	u8 *pFrameBuf,
	unsigned long *pFrameLen,
	u8 Category,
	u8 ActCode);

bool QosBADataParse(
	struct rtmp_adapter *pAd,
	bool bAMSDU,
	u8 *p8023Header,
	u8 WCID,
	u8 TID,
	unsigned short Sequence,
	u8 DataOffset,
	unsigned short Datasize,
	unsigned int   CurRxIndex);

#ifdef DOT11_N_SUPPORT
bool CntlEnqueueForRecv(
    struct rtmp_adapter *pAd,
	unsigned long Wcid,
    unsigned long MsgLen,
	PFRAME_BA_REQ pMsg);

void BaAutoManSwitch(
	struct rtmp_adapter *pAd);
#endif /* DOT11_N_SUPPORT */

void HTIOTCheck(
	struct rtmp_adapter *pAd,
	u8     BatRecIdx);

/* */
/* Private routines in rtmp_data.c */
/* */
bool RTMPHandleTxRingDmaDoneInterrupt(
	struct rtmp_adapter *pAd,
	u32 int_reg);

void RTMPHandleMgmtRingDmaDoneInterrupt(
	struct rtmp_adapter *pAd);

void RTMPHandleTBTTInterrupt(
	struct rtmp_adapter *pAd);

void RTMPHandlePreTBTTInterrupt(
	struct rtmp_adapter *pAd);

void RTMPHandleTwakeupInterrupt(
	struct rtmp_adapter *pAd);

void RTMPHandleRxCoherentInterrupt(
	struct rtmp_adapter *pAd);



int STASendPacket(
	struct rtmp_adapter *pAd,
	struct sk_buff *pPacket);

void STASendPackets(
	struct rtmp_adapter *pAd,
	struct sk_buff *pPacketArray);

void RTMPDeQueuePacket(
	struct rtmp_adapter*pAd,
   	bool bIntContext,
	u8 QueIdx,
	INT Max_Tx_Packets);

int	RTMPHardTransmit(
	struct rtmp_adapter *pAd,
	struct sk_buff *		pPacket,
	u8 		QueIdx,
	unsigned long			*pFreeTXDLeft);

int	STAHardTransmit(
	struct rtmp_adapter *pAd,
	TX_BLK			*pTxBlk,
	u8 		QueIdx);

void STARxEAPOLFrameIndicate(
	struct rtmp_adapter *pAd,
	MAC_TABLE_ENTRY	*pEntry,
	RX_BLK			*pRxBlk,
	u8 		FromWhichBSSID);

int RTMPFreeTXDRequest(
	struct rtmp_adapter *  pAd,
	u8           RingType,
	u8           NumberRequired,
	u8 *         FreeNumberIs);

int MlmeHardTransmit(
	struct rtmp_adapter *  pAd,
	u8 QueIdx,
	struct sk_buff *    pPacket,
	bool 		FlgDataQForce,
	bool 		FlgIsLocked);

int MlmeHardTransmitMgmtRing(
	struct rtmp_adapter *  pAd,
	u8 QueIdx,
	struct sk_buff *    pPacket);


unsigned short RTMPCalcDuration(
	struct rtmp_adapter*pAd,
	u8 Rate,
	unsigned long Size);

void RTMPWriteTxWI(
	struct rtmp_adapter*pAd,
	struct txwi_nmac *pTxWI,
	bool FRAG,
	bool CFACK,
	bool InsTimestamp,
	bool AMPDU,
	bool Ack,
	bool NSeq, /* HW new a sequence. */
	u8 BASize,
	u8 WCID,
	unsigned long Length,
	u8 PID,
	u8 TID,
	u8 TxRate,
	u8 Txopmode,
	bool CfAck,
	HTTRANSMIT_SETTING *pTransmit);


void RTMPWriteTxWI_Data(
	struct rtmp_adapter*pAd,
	struct txwi_nmac *pTxWI,
	TX_BLK *pTxBlk);


void RTMPWriteTxWI_Cache(
	struct rtmp_adapter*pAd,
	struct txwi_nmac *pTxWI,
	TX_BLK *pTxBlk);

void RTMPSuspendMsduTransmission(
	struct rtmp_adapter*pAd);

void RTMPResumeMsduTransmission(
	struct rtmp_adapter*pAd);

int MiniportMMRequest(
	struct rtmp_adapter*pAd,
	u8 QueIdx,
	u8 *pData,
	unsigned int Length);

void RTMPSendNullFrame(
	struct rtmp_adapter*pAd,
	u8 TxRate,
	bool bQosNull,
	unsigned short PwrMgmt);

#ifdef CONFIG_STA_SUPPORT
void RTMPReportMicError(
	struct rtmp_adapter *  pAd,
	PCIPHER_KEY     pWpaKey);

void WpaMicFailureReportFrame(
	struct rtmp_adapter *   pAd,
	MLME_QUEUE_ELEM *Elem);

void    WpaDisassocApAndBlockAssoc(
    void *SystemSpecific1,
    void *FunctionContext,
    void *SystemSpecific2,
    void *SystemSpecific3);

void WpaStaPairwiseKeySetting(
	struct rtmp_adapter *pAd);

void WpaStaGroupKeySetting(
	struct rtmp_adapter *pAd);

void    WpaSendEapolStart(
	struct rtmp_adapter *pAdapter,
	u8 *         pBssid);

#endif /* CONFIG_STA_SUPPORT */



bool RTMPFreeTXDUponTxDmaDone(
	struct rtmp_adapter *   pAd,
	u8            QueIdx);

bool RTMPCheckEtherType(
	struct rtmp_adapter *pAd,
	struct sk_buff *	pPacket,
	PMAC_TABLE_ENTRY pMacEntry,
	u8 		OpMode,
	u8 *pUserPriority,
	u8 *pQueIdx);


void RTMPCckBbpTuning(
	struct rtmp_adapter *pAd,
	unsigned int			TxRate);
/* */
/* MLME routines */
/* */


void AsicExtraPowerOverMAC(struct rtmp_adapter*pAd);

void AsicPercentageDeltaPower(
	struct rtmp_adapter *		pAd,
	CHAR				Rssi,
	char *			pDeltaPwr,
	char *			pDeltaPowerByBbpR1);

void AsicCompensatePowerViaBBP(
	struct rtmp_adapter *		pAd,
	char *			pTotalDeltaPower);

void AsicAdjustTxPower(
	struct rtmp_adapter *pAd);

void 	AsicUpdateProtect(
	struct rtmp_adapter *pAd,
	unsigned short			OperaionMode,
	u8 		SetMask,
	bool 		bDisableBGProtect,
	bool 		bNonGFExist);

void AsicSwitchChannel(
	struct rtmp_adapter *  pAd,
	u8 		Channel,
	bool 		bScan);

INT AsicSetChannel(
	struct rtmp_adapter*pAd,
	u8 ch,
	u8 bw,
	u8 ext_ch,
	bool bScan);

void AsicLockChannel(
	struct rtmp_adapter *pAd,
	u8 Channel) ;

void AsicAntennaSelect(
	struct rtmp_adapter *  pAd,
	u8           Channel);

void AsicResetBBPAgent(
	struct rtmp_adapter *pAd);

#ifdef CONFIG_STA_SUPPORT
void AsicSleepThenAutoWakeup(
	struct rtmp_adapter *  pAd,
	unsigned short TbttNumToNextWakeUp);

void AsicForceSleep(
	struct rtmp_adapter *pAd);

void AsicForceWakeup(
	struct rtmp_adapter *pAd,
	bool    bFromTx);
#endif /* CONFIG_STA_SUPPORT */

void AsicSetBssid(
	struct rtmp_adapter *  pAd,
	u8 *pBssid);

void AsicDelWcidTab(
	struct rtmp_adapter *pAd,
	u8 Wcid);

void AsicSetApCliBssid(
	struct rtmp_adapter *pAd,
	u8 *pBssid,
	u8 index);

#ifdef MAC_REPEATER_SUPPORT
void AsicSetExtendedMacAddr(
	struct rtmp_adapter *pAd,
	u8 *pMacAddr,
	u32 Idx);
#endif /* MAC_REPEATER_SUPPORT */

#ifdef DOT11_N_SUPPORT
void AsicEnableRDG(
	struct rtmp_adapter *pAd);

void AsicDisableRDG(
	struct rtmp_adapter *pAd);
#endif /* DOT11_N_SUPPORT */

void AsicDisableSync(
	struct rtmp_adapter *  pAd);

void AsicEnableBssSync(
	struct rtmp_adapter *  pAd);

void AsicEnableIbssSync(
	struct rtmp_adapter *  pAd);

void AsicSetEdcaParm(
	struct rtmp_adapter *pAd,
	PEDCA_PARM    pEdcaParm);

void AsicSetSlotTime(
	struct rtmp_adapter *pAd,
	bool bUseShortSlotTime);

void AsicAddSharedKeyEntry(
	struct rtmp_adapter *pAd,
	u8         BssIndex,
	u8         KeyIdx,
	PCIPHER_KEY	 pCipherKey);

void AsicRemoveSharedKeyEntry(
	struct rtmp_adapter *pAd,
	u8         BssIndex,
	u8         KeyIdx);

void AsicUpdateWCIDIVEIV(
	struct rtmp_adapter *pAd,
	unsigned short		WCID,
	unsigned long        uIV,
	unsigned long        uEIV);

void AsicUpdateRxWCIDTable(
	struct rtmp_adapter *pAd,
	unsigned short		WCID,
	u8 *       pAddr);

void AsicUpdateWcidAttributeEntry(
	struct rtmp_adapter *pAd,
	u8 		BssIdx,
	u8 	 	KeyIdx,
	u8 	 	CipherAlg,
	u8				Wcid,
	u8				KeyTabFlag);

void AsicAddPairwiseKeyEntry(
	struct rtmp_adapter *	pAd,
	u8 		WCID,
	PCIPHER_KEY		pCipherKey);

void AsicRemovePairwiseKeyEntry(
	struct rtmp_adapter * pAd,
	u8 	 Wcid);

void MacAddrRandomBssid(
	struct rtmp_adapter *  pAd,
	u8 *pAddr);

void MgtMacHeaderInit(
	struct rtmp_adapter *    pAd,
	PHEADER_802_11 pHdr80211,
	u8 SubType,
	u8 ToDs,
	u8 *pDA,
	u8 *pBssid);

void MlmeRadioOff(
	struct rtmp_adapter *pAd);

void MlmeRadioOn(
	struct rtmp_adapter *pAd);


void BssTableInit(
	BSS_TABLE *Tab);

#ifdef DOT11_N_SUPPORT
void BATableInit(
	struct rtmp_adapter *pAd,
    BA_TABLE *Tab);

void BATableExit(
	struct rtmp_adapter*pAd);
#endif /* DOT11_N_SUPPORT */

unsigned long BssTableSearch(
	BSS_TABLE *Tab,
	u8 *pBssid,
	u8 Channel);

unsigned long BssSsidTableSearch(
	BSS_TABLE *Tab,
	u8 *   pBssid,
	u8 *   pSsid,
	u8     SsidLen,
	u8     Channel);

unsigned long BssTableSearchWithSSID(
	BSS_TABLE *Tab,
	u8 *   Bssid,
	u8 *   pSsid,
	u8     SsidLen,
	u8     Channel);

unsigned long BssSsidTableSearchBySSID(
	BSS_TABLE *Tab,
	u8 * pSsid,
	u8  SsidLen);

void BssTableDeleteEntry(
	PBSS_TABLE pTab,
	u8 *pBssid,
	u8 Channel);

unsigned long BssTableSetEntry(
	struct rtmp_adapter *pAd,
	BSS_TABLE *Tab,
	BCN_IE_LIST *ie_list,
	CHAR Rssi,
	unsigned short LengthVIE,
	PNDIS_802_11_VARIABLE_IEs pVIE);


#ifdef DOT11_N_SUPPORT
void BATableInsertEntry(
    struct rtmp_adapter *pAd,
	unsigned short Aid,
    unsigned short		TimeOutValue,
	unsigned short		StartingSeq,
    u8 TID,
	u8 BAWinSize,
	u8 OriginatorStatus,
    bool IsRecipient);

#ifdef DOT11N_DRAFT3
void Bss2040CoexistTimeOut(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);


void  TriEventInit(
	struct rtmp_adapter *pAd);

INT TriEventTableSetEntry(
	struct rtmp_adapter *pAd,
	TRIGGER_EVENT_TAB *Tab,
	u8 *pBssid,
	HT_CAPABILITY_IE *pHtCapability,
	u8 		HtCapabilityLen,
	u8 		RegClass,
	u8 ChannelNo);

#endif /* DOT11N_DRAFT3 */
#endif /* DOT11_N_SUPPORT */

void BssTableSsidSort(
	struct rtmp_adapter *  pAd,
	BSS_TABLE *OutTab,
	CHAR Ssid[],
	u8 SsidLen);

void  BssTableSortByRssi(
	BSS_TABLE *OutTab);

void BssCipherParse(
	PBSS_ENTRY  pBss);

int  MlmeQueueInit(
	struct rtmp_adapter *pAd,
	MLME_QUEUE *Queue);

void  MlmeQueueDestroy(
	MLME_QUEUE *Queue);

bool MlmeEnqueue(
	struct rtmp_adapter *pAd,
	unsigned long Machine,
	unsigned long MsgType,
	unsigned long MsgLen,
	void *Msg,
	unsigned long Priv);

bool MlmeEnqueueForRecv(
	struct rtmp_adapter *  pAd,
	unsigned long Wcid,
	unsigned long TimeStampHigh,
	unsigned long TimeStampLow,
	u8 Rssi0,
	u8 Rssi1,
	u8 Rssi2,
	unsigned long MsgLen,
	void *Msg,
	u8 Signal,
	u8 OpMode);


bool MlmeDequeue(
	MLME_QUEUE *Queue,
	MLME_QUEUE_ELEM **Elem);

void    MlmeRestartStateMachine(
	struct rtmp_adapter *  pAd);

bool  MlmeQueueEmpty(
	MLME_QUEUE *Queue);

bool  MlmeQueueFull(
	MLME_QUEUE *Queue,
	u8 SendId);

bool  MsgTypeSubst(
	struct rtmp_adapter *pAd,
	PFRAME_802_11 pFrame,
	INT *Machine,
	INT *MsgType);

void StateMachineInit(
	STATE_MACHINE *Sm,
	STATE_MACHINE_FUNC Trans[],
	unsigned long StNr,
	unsigned long MsgNr,
	STATE_MACHINE_FUNC DefFunc,
	unsigned long InitState,
	unsigned long Base);

void StateMachineSetAction(
	STATE_MACHINE *S,
	unsigned long St,
	unsigned long Msg,
	STATE_MACHINE_FUNC F);

void StateMachinePerformAction(
	struct rtmp_adapter *  pAd,
	STATE_MACHINE *S,
	MLME_QUEUE_ELEM *Elem,
	unsigned long CurrState);

void Drop(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void AssocStateMachineInit(
	struct rtmp_adapter *  pAd,
	STATE_MACHINE *Sm,
	STATE_MACHINE_FUNC Trans[]);

void ReassocTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void AssocTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void DisassocTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

/*---------------------------------------------- */
void MlmeDisassocReqAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void MlmeAssocReqAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void MlmeReassocReqAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void MlmeDisassocReqAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerAssocRspAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerReassocRspAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerDisassocAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void DisassocTimeoutAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void AssocTimeoutAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void  ReassocTimeoutAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void  Cls3errAction(
	struct rtmp_adapter *  pAd,
	u8 *pAddr);

void  InvalidStateWhenAssoc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void  InvalidStateWhenReassoc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void InvalidStateWhenDisassociate(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

#ifdef RTMP_MAC_USB
void MlmeCntlConfirm(
	struct rtmp_adapter *pAd,
	unsigned long MsgType,
	unsigned short Msg);
#endif /* RTMP_MAC_USB */

void  ComposePsPoll(
	struct rtmp_adapter *  pAd);

void  ComposeNullFrame(
	struct rtmp_adapter *pAd);

void  AssocPostProc(
	struct rtmp_adapter *pAd,
	u8 *pAddr2,
	unsigned short CapabilityInfo,
	unsigned short Aid,
	u8 SupRate[],
	u8 SupRateLen,
	u8 ExtRate[],
	u8 ExtRateLen,
	PEDCA_PARM pEdcaParm,
	IE_LISTS *ie_list,
	HT_CAPABILITY_IE *pHtCapability,
	u8 HtCapabilityLen,
	ADD_HT_INFO_IE *pAddHtInfo);

void AuthStateMachineInit(
	struct rtmp_adapter *  pAd,
	PSTATE_MACHINE sm,
	STATE_MACHINE_FUNC Trans[]);

void AuthTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void MlmeAuthReqAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerAuthRspAtSeq2Action(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerAuthRspAtSeq4Action(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void AuthTimeoutAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void Cls2errAction(
	struct rtmp_adapter *  pAd,
	u8 *pAddr);

void MlmeDeauthReqAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void InvalidStateWhenAuth(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

/*============================================= */

void AuthRspStateMachineInit(
	struct rtmp_adapter *  pAd,
	PSTATE_MACHINE Sm,
	STATE_MACHINE_FUNC Trans[]);

void PeerDeauthAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerAuthSimpleRspGenAndSend(
	struct rtmp_adapter *  pAd,
	PHEADER_802_11  pHdr80211,
	unsigned short Alg,
	unsigned short Seq,
	unsigned short Reason,
	unsigned short Status);

/* */
/* Private routines in dls.c */
/* */

#ifdef CONFIG_STA_SUPPORT
#ifdef QOS_DLS_SUPPORT
void DlsStateMachineInit(
    struct rtmp_adapter *pAd,
    STATE_MACHINE *Sm,
    STATE_MACHINE_FUNC Trans[]);

void MlmeDlsReqAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

void PeerDlsReqAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM	*Elem);

void PeerDlsRspAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM	*Elem);

void MlmeDlsTearDownAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM *Elem);

void PeerDlsTearDownAction(
    struct rtmp_adapter *pAd,
    MLME_QUEUE_ELEM	*Elem);

void RTMPCheckDLSTimeOut(
	struct rtmp_adapter *pAd);

bool RTMPRcvFrameDLSCheck(
	struct rtmp_adapter*pAd,
	PHEADER_802_11 pHeader,
	unsigned long Len,
	RXD_STRUC *pRxD);

INT	RTMPCheckDLSFrame(
	struct rtmp_adapter*pAd,
	u8 *pDA);

void RTMPSendDLSTearDownFrame(
	struct rtmp_adapter *pAd,
	u8 *         pDA);

int RTMPSendSTAKeyRequest(
	struct rtmp_adapter *pAd,
	u8 *		pDA);

int RTMPSendSTAKeyHandShake(
	struct rtmp_adapter *pAd,
	u8 *		pDA);

void DlsTimeoutAction(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

bool MlmeDlsReqSanity(
	struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    PRT_802_11_DLS *pDLS,
    unsigned short *pReason);

INT Set_DlsEntryInfo_Display_Proc(
	struct rtmp_adapter *pAd,
	u8 *arg);

MAC_TABLE_ENTRY *MacTableInsertDlsEntry(
	struct rtmp_adapter *  pAd,
	u8 *pAddr,
	unsigned int	DlsEntryIdx);

bool MacTableDeleteDlsEntry(
	struct rtmp_adapter *pAd,
	unsigned short wcid,
	u8 *pAddr);

MAC_TABLE_ENTRY *DlsEntryTableLookup(
	struct rtmp_adapter *pAd,
	u8 *pAddr,
	bool bResetIdelCount);

MAC_TABLE_ENTRY *DlsEntryTableLookupByWcid(
	struct rtmp_adapter *pAd,
	u8 wcid,
	u8 *pAddr,
	bool bResetIdelCount);

INT	Set_DlsAddEntry_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_DlsTearDownEntry_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);
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
    HT_CAPABILITY_IE *pHtCapability);

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
    HT_CAPABILITY_IE *pHtCapability);

bool PeerDlsTearDownSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pDA,
    u8 *pSA,
    unsigned short *pReason);
#endif /* QOS_DLS_SUPPORT */

bool PeerProbeReqSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pAddr2,
    CHAR Ssid[],
    u8 *SsidLen,
    bool *bRequestRssi);

/*======================================== */

void SyncStateMachineInit(
	struct rtmp_adapter *  pAd,
	STATE_MACHINE *Sm,
	STATE_MACHINE_FUNC Trans[]);

void BeaconTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void ScanTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void MlmeScanReqAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void InvalidStateWhenScan(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void InvalidStateWhenJoin(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void InvalidStateWhenStart(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerBeacon(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void EnqueueProbeRequest(
	struct rtmp_adapter *pAd);

bool ScanRunning(
		struct rtmp_adapter *pAd);
/*========================================= */

void MlmeCntlInit(
	struct rtmp_adapter *  pAd,
	STATE_MACHINE *S,
	STATE_MACHINE_FUNC Trans[]);

void MlmeCntlMachinePerformAction(
	struct rtmp_adapter *  pAd,
	STATE_MACHINE *S,
	MLME_QUEUE_ELEM *Elem);

void CntlIdleProc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void CntlOidScanProc(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void CntlOidSsidProc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM * Elem);

void CntlOidRTBssidProc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM * Elem);

void CntlMlmeRoamingProc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM * Elem);

void CntlWaitDisassocProc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void CntlWaitJoinProc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void CntlWaitReassocProc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void CntlWaitStartProc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void CntlWaitAuthProc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void CntlWaitAuthProc2(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void CntlWaitAssocProc(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

#ifdef QOS_DLS_SUPPORT
void CntlOidDLSSetupProc(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);
#endif /* QOS_DLS_SUPPORT */


void LinkUp(
	struct rtmp_adapter *  pAd,
	u8 BssType);

void LinkDown(
	struct rtmp_adapter *  pAd,
	bool         IsReqFromAP);

void IterateOnBssTab(
	struct rtmp_adapter *  pAd);

void IterateOnBssTab2(
	struct rtmp_adapter *  pAd);;

void JoinParmFill(
	struct rtmp_adapter *  pAd,
	MLME_JOIN_REQ_STRUCT *JoinReq,
	unsigned long BssIdx);

void AssocParmFill(
	struct rtmp_adapter *  pAd,
	MLME_ASSOC_REQ_STRUCT *AssocReq,
	u8 *pAddr,
	unsigned short CapabilityInfo,
	unsigned long Timeout,
	unsigned short ListenIntv);

void ScanParmFill(
	struct rtmp_adapter *  pAd,
	MLME_SCAN_REQ_STRUCT *ScanReq,
	char Ssid[],
	u8 SsidLen,
	u8 BssType,
	u8 ScanType);

void DisassocParmFill(
	struct rtmp_adapter *  pAd,
	MLME_DISASSOC_REQ_STRUCT *DisassocReq,
	u8 *pAddr,
	unsigned short Reason);

void StartParmFill(
	struct rtmp_adapter *  pAd,
	MLME_START_REQ_STRUCT *StartReq,
	CHAR Ssid[],
	u8 SsidLen);

void AuthParmFill(
	struct rtmp_adapter *  pAd,
	MLME_AUTH_REQ_STRUCT *AuthReq,
	u8 *pAddr,
	unsigned short Alg);

void EnqueuePsPoll(
	struct rtmp_adapter *  pAd);

void EnqueueBeaconFrame(
	struct rtmp_adapter *  pAd);

void MlmeJoinReqAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void MlmeScanReqAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void MlmeStartReqAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void MlmeForceJoinReqAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void MlmeForceScanReqAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void ScanTimeoutAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void BeaconTimeoutAtJoinAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerBeaconAtScanAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerBeaconAtJoinAction(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerBeacon(
	struct rtmp_adapter *  pAd,
	MLME_QUEUE_ELEM *Elem);

void PeerProbeReqAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem);

void ScanNextChannel(
	struct rtmp_adapter *  pAd,
	u8 OpMode);


unsigned long MakeIbssBeacon(
	struct rtmp_adapter *  pAd);

#ifdef CONFIG_STA_SUPPORT
void InitChannelRelatedValue(
	struct rtmp_adapter *  pAd);

void AdjustChannelRelatedValue(
	struct rtmp_adapter *pAd,
	u8 *pBwFallBack,
	unsigned short ifIndex,
	bool BandWidth,
	u8 PriCh,
	u8 ExtraCh);
#endif /* CONFIG_STA_SUPPORT */

bool MlmeScanReqSanity(
	struct rtmp_adapter *  pAd,
	void *Msg,
	unsigned long MsgLen,
	u8 *BssType,
	CHAR ssid[],
	u8 *SsidLen,
	u8 *ScanType);


bool PeerBeaconAndProbeRspSanity_Old(
	struct rtmp_adapter *  pAd,
	void *Msg,
	unsigned long MsgLen,
	u8 MsgChannel,
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
	PEDCA_PARM       pEdcaParm,
	PQBSS_LOAD_PARM  pQbssLoad,
	PQOS_CAPABILITY_PARM pQosCapability,
	unsigned long *pRalinkIe,
	u8 	 *pHtCapabilityLen,
#ifdef CONFIG_STA_SUPPORT
	u8 	 *pPreNHtCapabilityLen,
#endif /* CONFIG_STA_SUPPORT */
	HT_CAPABILITY_IE *pHtCapability,
	EXT_CAP_INFO_ELEMENT *pExtCapInfo,
	u8 	 *AddHtInfoLen,
	ADD_HT_INFO_IE *AddHtInfo,
	u8 *NewExtChannel,
	unsigned short *LengthVIE,
	PNDIS_802_11_VARIABLE_IEs pVIE);


bool PeerBeaconAndProbeRspSanity(
	struct rtmp_adapter *pAd,
	void *Msg,
	unsigned long MsgLen,
	u8  MsgChannel,
	BCN_IE_LIST *ie_list,
	unsigned short *LengthVIE,
	PNDIS_802_11_VARIABLE_IEs pVIE);


#ifdef DOT11_N_SUPPORT
#ifdef DOT11N_DRAFT3
bool PeerBeaconAndProbeRspSanity2(
	struct rtmp_adapter *pAd,
	void *Msg,
	unsigned long MsgLen,
	OVERLAP_BSS_SCAN_IE *BssScan,
	u8 	*RegClass);
#endif /* DOT11N_DRAFT3 */
#endif /* DOT11_N_SUPPORT */

bool PeerAddBAReqActionSanity(
    struct rtmp_adapter *pAd,
    void *pMsg,
    unsigned long MsgLen,
	u8 *pAddr2);

bool PeerAddBARspActionSanity(
    struct rtmp_adapter *pAd,
    void *pMsg,
    unsigned long MsgLen);

bool PeerDelBAActionSanity(
    struct rtmp_adapter *pAd,
    u8 Wcid,
    void *pMsg,
    unsigned long MsgLen);

bool MlmeAssocReqSanity(
	struct rtmp_adapter *  pAd,
	void *Msg,
	unsigned long MsgLen,
	u8 *pApAddr,
	unsigned short *CapabilityInfo,
	unsigned long *Timeout,
	unsigned short *ListenIntv);

bool MlmeAuthReqSanity(
	struct rtmp_adapter *  pAd,
	void *Msg,
	unsigned long MsgLen,
	u8 *pAddr,
	unsigned long *Timeout,
	unsigned short *Alg);

bool MlmeStartReqSanity(
	struct rtmp_adapter *  pAd,
	void *Msg,
	unsigned long MsgLen,
	CHAR Ssid[],
	u8 *Ssidlen);

bool PeerAuthSanity(
	struct rtmp_adapter *  pAd,
	void *Msg,
	unsigned long MsgLen,
	u8 *pAddr,
	unsigned short *Alg,
	unsigned short *Seq,
	unsigned short *Status,
	CHAR ChlgText[]);

bool PeerAssocRspSanity(
	struct rtmp_adapter *  pAd,
    void *pMsg,
	unsigned long MsgLen,
	u8 *pAddr2,
	unsigned short *pCapabilityInfo,
	unsigned short *pStatus,
	unsigned short *pAid,
	u8 SupRate[],
	u8 *pSupRateLen,
	u8 ExtRate[],
	u8 *pExtRateLen,
    HT_CAPABILITY_IE		*pHtCapability,
    ADD_HT_INFO_IE		*pAddHtInfo,	/* AP might use this additional ht info IE */
    u8 		*pHtCapabilityLen,
    u8 		*pAddHtInfoLen,
    u8 		*pNewExtChannelOffset,
	PEDCA_PARM pEdcaParm,
	EXT_CAP_INFO_ELEMENT *pExtCapInfo,
	u8 *pCkipFlag,
	IE_LISTS *ie_list);

bool PeerDisassocSanity(
	struct rtmp_adapter *  pAd,
	void *Msg,
	unsigned long MsgLen,
	u8 *pAddr2,
	unsigned short *Reason);

bool PeerDeauthSanity(
	struct rtmp_adapter *  pAd,
	void *Msg,
	unsigned long MsgLen,
	u8 *pAddr1,
	u8 *pAddr2,
	u8 *pAddr3,
	unsigned short *Reason);

bool GetTimBit(
	CHAR *Ptr,
	unsigned short Aid,
	u8 *TimLen,
	u8 *BcastFlag,
	u8 *DtimCount,
	u8 *DtimPeriod,
	u8 *MessageToMe);

u8 ChannelSanity(
	struct rtmp_adapter *pAd,
	u8 channel);

NDIS_802_11_NETWORK_TYPE NetworkTypeInUseSanity(
	PBSS_ENTRY pBss);

bool MlmeDelBAReqSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen);

bool MlmeAddBAReqSanity(
    struct rtmp_adapter *pAd,
    void *Msg,
    unsigned long MsgLen,
    u8 *pAddr2);

unsigned long MakeOutgoingFrame(
	u8 *Buffer,
	unsigned long *Length, ...);

u8 RandomByte(
	struct rtmp_adapter *  pAd);

void AsicUpdateAutoFallBackTable(
	struct rtmp_adapter *pAd,
	u8 *		pTxRate);



void  MlmePeriodicExec(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void LinkDownExec(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void LinkUpExec(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void STAMlmePeriodicExec(
	struct rtmp_adapter *pAd);

void MlmeAutoScan(
	struct rtmp_adapter *pAd);

bool MlmeValidateSSID(
	u8 *pSsid,
	u8  SsidLen);

void MlmeCheckForRoaming(
	struct rtmp_adapter *pAd,
	unsigned long    Now32);

bool MlmeCheckForFastRoaming(
	struct rtmp_adapter *  pAd);


void MlmeCalculateChannelQuality(
	struct rtmp_adapter *pAd,
	PMAC_TABLE_ENTRY pMacEntry,
	unsigned long Now);

void MlmeCheckPsmChange(
	struct rtmp_adapter *pAd,
	unsigned long    Now32);

void MlmeSetPsmBit(
	struct rtmp_adapter *pAd,
	unsigned short psm);

void MlmeSetTxPreamble(
	struct rtmp_adapter *pAd,
	unsigned short TxPreamble);

void UpdateBasicRateBitmap(
	struct rtmp_adapter *pAd);

void MlmeUpdateTxRates(
	struct rtmp_adapter *	pAd,
	bool 	 	bLinkUp,
	u8 		apidx);

#ifdef DOT11_N_SUPPORT
void MlmeUpdateHtTxRates(
	struct rtmp_adapter *		pAd,
	u8 			apidx);
#endif /* DOT11_N_SUPPORT */

void    RTMPCheckRates(
	struct rtmp_adapter *  pAd,
	u8           SupRate[],
	u8           *SupRateLen);

#ifdef CONFIG_STA_SUPPORT
bool RTMPCheckChannel(
	struct rtmp_adapter *pAd,
	u8 	CentralChannel,
	u8 	Channel);
#endif /* CONFIG_STA_SUPPORT */

bool RTMPCheckHt(
	struct rtmp_adapter*pAd,
	u8 Wcid,
	HT_CAPABILITY_IE *pHtCapability,
	ADD_HT_INFO_IE *pAddHtInfo);

#ifdef DOT11_VHT_AC
bool RTMPCheckVht(
	struct rtmp_adapter*pAd,
	u8 Wcid,
	VHT_CAP_IE *vht_cap,
	VHT_OP_IE *vht_op);
#endif /* DOT11_VHT_AC */

void RTMPUpdateMlmeRate(
	struct rtmp_adapter *pAd);

CHAR RTMPMaxRssi(
	struct rtmp_adapter *pAd,
	CHAR				Rssi0,
	CHAR				Rssi1,
	CHAR				Rssi2);

CHAR RTMPAvgRssi(
        struct rtmp_adapter *pAd,
        RSSI_SAMPLE		*pRssi);


CHAR RTMPMinSnr(
	struct rtmp_adapter *pAd,
	CHAR				Snr0,
	CHAR				Snr1);

void eFusePhysicalReadRegisters(
	struct rtmp_adapter *pAd,
	unsigned short Offset,
	unsigned short Length,
	unsigned short* pData);

void AsicEvaluateRxAnt(
	struct rtmp_adapter *pAd);

void AsicRxAntEvalTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void APSDPeriodicExec(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

bool RTMPCheckEntryEnableAutoRateSwitch(
	struct rtmp_adapter *   pAd,
	PMAC_TABLE_ENTRY	pEntry);

u8 RTMPStaFixedTxMode(
	struct rtmp_adapter *   pAd,
	PMAC_TABLE_ENTRY	pEntry);

void RTMPUpdateLegacyTxSetting(
		u8 			fixed_tx_mode,
		PMAC_TABLE_ENTRY	pEntry);

bool RTMPAutoRateSwitchCheck(
	struct rtmp_adapter *   pAd);

int MlmeInit(
	struct rtmp_adapter *  pAd);


#ifdef CONFIG_STA_SUPPORT
#endif /* CONFIG_STA_SUPPORT */

void MlmeHandler(
	struct rtmp_adapter *  pAd);

void MlmeHalt(
	struct rtmp_adapter *  pAd);

void MlmeResetRalinkCounters(
	struct rtmp_adapter *  pAd);

void BuildChannelList(
	struct rtmp_adapter *pAd);

u8 FirstChannel(
	struct rtmp_adapter *  pAd);

u8 NextChannel(
	struct rtmp_adapter *  pAd,
	u8 channel);

void ChangeToCellPowerLimit(
	struct rtmp_adapter *pAd,
	u8         AironetCellPowerLimit);

/* */
/* Prototypes of function definition in cmm_tkip.c */
/* */
void    RTMPInitMICEngine(
	struct rtmp_adapter *  pAd,
	u8 *         pKey,
	u8 *         pDA,
	u8 *         pSA,
	u8           UserPriority,
	u8 *         pMICKey);

bool RTMPTkipCompareMICValue(
	struct rtmp_adapter *  pAd,
	u8 *         pSrc,
	u8 *         pDA,
	u8 *         pSA,
	u8 *         pMICKey,
	u8 		UserPriority,
	unsigned int            Len);

void    RTMPCalculateMICValue(
	struct rtmp_adapter *  pAd,
	struct sk_buff *    pPacket,
	u8 *         pEncap,
	PCIPHER_KEY     pKey,
	u8 		apidx);

void    RTMPTkipAppendByte(
	PTKIP_KEY_INFO  pTkip,
	u8           uChar);

void    RTMPTkipAppend(
	PTKIP_KEY_INFO  pTkip,
	u8 *         pSrc,
	unsigned int            nBytes);

void    RTMPTkipGetMIC(
	PTKIP_KEY_INFO  pTkip);

/* */
/* Prototypes of function definition in cmm_cfg.c */
/* */
INT RT_CfgSetCountryRegion(
	struct rtmp_adapter *pAd,
	char *		arg,
	INT				band);

INT RT_CfgSetWirelessMode(
	struct rtmp_adapter *pAd,
	char *		arg);

u8 cfgmode_2_wmode(u8 cfg_mode);
u8 *wmode_2_str(u8 wmode);


INT RT_CfgSetShortSlot(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	RT_CfgSetWepKey(
	struct rtmp_adapter *pAd,
	char *		keyString,
	CIPHER_KEY		*pSharedKey,
	INT				keyIdx);

INT RT_CfgSetWPAPSKKey(
	struct rtmp_adapter*pAd,
	char *	keyString,
	INT			keyStringLen,
	u8 	*pHashStr,
	INT			hashStrLen,
	u8 *	pPMKBuf);

INT	RT_CfgSetFixedTxPhyMode(
	char *		arg);

INT	RT_CfgSetMacAddress(
	struct rtmp_adapter *	pAd,
	char *		arg);

INT	RT_CfgSetTxMCSProc(
	char *		arg,
	bool 		*pAutoRate);

INT	RT_CfgSetAutoFallBack(
	struct rtmp_adapter *	pAd,
	char *		arg);

/* */
/* Prototypes of function definition in cmm_info.c */
/* */
int RTMPWPARemoveKeyProc(
	struct rtmp_adapter *  pAd,
	void *          pBuf);

void    RTMPWPARemoveAllKeys(
	struct rtmp_adapter *  pAd);

bool RTMPCheckStrPrintAble(
    CHAR *pInPutStr,
    u8 strLen);

void    RTMPSetPhyMode(
	struct rtmp_adapter *  pAd,
	unsigned long phymode);

void RTMPUpdateHTIE(
	RT_HT_CAPABILITY	*pRtHt,
	u8 			*pMcsSet,
	HT_CAPABILITY_IE *pHtCapability,
	ADD_HT_INFO_IE		*pAddHtInfo);

void RTMPAddWcidAttributeEntry(
	struct rtmp_adapter *pAd,
	u8 		BssIdx,
	u8 	 	KeyIdx,
	u8 	 	CipherAlg,
	MAC_TABLE_ENTRY *pEntry);

char *GetEncryptType(
	CHAR enc);

char *GetAuthMode(
	CHAR auth);

#ifdef DOT11_N_SUPPORT
void RTMPSetHT(
	struct rtmp_adapter *pAd,
	OID_SET_HT_PHYMODE *pHTPhyMode);

void RTMPSetIndividualHT(
	struct rtmp_adapter *	pAd,
	u8 			apidx);

u8 get_cent_ch_by_htinfo(
	struct rtmp_adapter*pAd,
	ADD_HT_INFO_IE *ht_op,
	HT_CAPABILITY_IE *ht_cap);

INT get_ht_cent_ch(struct rtmp_adapter*pAd, u8 *rf_bw, u8 *ext_ch);
INT ht_mode_adjust(struct rtmp_adapter*pAd, MAC_TABLE_ENTRY *pEntry, HT_CAPABILITY_IE *peer, RT_HT_CAPABILITY *my);
INT set_ht_fixed_mcs(struct rtmp_adapter*pAd, MAC_TABLE_ENTRY *pEntry, u8 fixed_mcs, u8 mcs_bound);
INT get_ht_max_mcs(struct rtmp_adapter*pAd, u8 *desire_mcs, u8 *cap_mcs);
#endif /* DOT11_N_SUPPORT */

void RTMPDisableDesiredHtInfo(
	struct rtmp_adapter *pAd);

CHAR    ConvertToRssi(
	struct rtmp_adapter * pAd,
	CHAR				Rssi,
	u8    RssiNumber);

CHAR    ConvertToSnr(
	struct rtmp_adapter * pAd,
	u8 			Snr);

#ifdef DOT11N_DRAFT3
void BuildEffectedChannelList(
	struct rtmp_adapter *pAd);


void DeleteEffectedChannelList(
	struct rtmp_adapter *pAd);

void CntlChannelWidth(
	struct rtmp_adapter *pAd,
	u8 		PrimaryChannel,
	u8 		CentralChannel,
	u8 		ChannelWidth,
	u8 		SecondaryChannelOffset);

#endif /* DOT11N_DRAFT3 */


void APAsicEvaluateRxAnt(
	struct rtmp_adapter *pAd);


void APAsicRxAntEvalTimeout(
	struct rtmp_adapter *pAd);


/* */
/* function prototype in ap_wpa.c */
/* */
void RTMPGetTxTscFromAsic(
	struct rtmp_adapter *  pAd,
	u8 		apidx,
	u8 *		pTxTsc);

MAC_TABLE_ENTRY *PACInquiry(
	struct rtmp_adapter *  pAd,
	unsigned long           Wcid);

unsigned int	APValidateRSNIE(
	struct rtmp_adapter *   pAd,
	PMAC_TABLE_ENTRY pEntry,
	u8 *		pRsnIe,
	u8 		rsnie_len);

void HandleCounterMeasure(
	struct rtmp_adapter *pAd,
	MAC_TABLE_ENTRY  *pEntry);

void WPAStart4WayHS(
	struct rtmp_adapter *  pAd,
	MAC_TABLE_ENTRY *pEntry,
	unsigned long			TimeInterval);

void WPAStart2WayGroupHS(
	struct rtmp_adapter *  pAd,
	MAC_TABLE_ENTRY *pEntry);

void PeerPairMsg1Action(
	struct rtmp_adapter *pAd,
	MAC_TABLE_ENTRY  *pEntry,
	MLME_QUEUE_ELEM *Elem);

void PeerPairMsg2Action(
	struct rtmp_adapter *pAd,
	MAC_TABLE_ENTRY  *pEntry,
	MLME_QUEUE_ELEM *Elem);

void PeerPairMsg3Action(
	struct rtmp_adapter *pAd,
	MAC_TABLE_ENTRY  *pEntry,
	MLME_QUEUE_ELEM *Elem);

void PeerPairMsg4Action(
	struct rtmp_adapter *pAd,
	MAC_TABLE_ENTRY  *pEntry,
	MLME_QUEUE_ELEM *Elem);

void PeerGroupMsg1Action(
	struct rtmp_adapter *   pAd,
	PMAC_TABLE_ENTRY pEntry,
    MLME_QUEUE_ELEM  *Elem);

void PeerGroupMsg2Action(
	struct rtmp_adapter *   pAd,
	PMAC_TABLE_ENTRY pEntry,
	void             *Msg,
	unsigned int             MsgLen);

void CMTimerExec(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void WPARetryExec(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void EnqueueStartForPSKExec(
    void *SystemSpecific1,
    void *FunctionContext,
    void *SystemSpecific2,
    void *SystemSpecific3);


void RTMPHandleSTAKey(
    struct rtmp_adapter *   pAdapter,
    MAC_TABLE_ENTRY  *pEntry,
    MLME_QUEUE_ELEM  *Elem);

void MlmeDeAuthAction(
	struct rtmp_adapter *   pAd,
	PMAC_TABLE_ENTRY pEntry,
	unsigned short           Reason,
	bool          bDataFrameFirst);


void GREKEYPeriodicExec(
	void *  SystemSpecific1,
	void *  FunctionContext,
	void *  SystemSpecific2,
	void *  SystemSpecific3);

void AES_128_CMAC(
	u8 *key,
	u8 *input,
	INT		len,
	u8 *mac);

#ifdef DOT1X_SUPPORT
void    WpaSend(
    struct rtmp_adapter *  pAdapter,
    u8 *         pPacket,
    unsigned long           Len);

void RTMPAddPMKIDCache(
	struct rtmp_adapter *  		pAd,
	INT						apidx,
	u8 *			pAddr,
	u8 				*PMKID,
	u8 				*PMK);

INT RTMPSearchPMKIDCache(
	struct rtmp_adapter *  pAd,
	INT				apidx,
	u8 *	pAddr);

void RTMPDeletePMKIDCache(
	struct rtmp_adapter *  pAd,
	INT				apidx,
	INT				idx);

void RTMPMaintainPMKIDCache(
	struct rtmp_adapter *  pAd);
#else
#define RTMPMaintainPMKIDCache(_pAd)
#endif /* DOT1X_SUPPORT */

#ifdef RESOURCE_PRE_ALLOC
void RTMPResetTxRxRingMemory(
	struct rtmp_adapter  *pAd);
#endif /* RESOURCE_PRE_ALLOC */

void RTMPFreeTxRxRingMemory(
    struct rtmp_adapter *  pAd);

bool RTMP_FillTxBlkInfo(
	struct rtmp_adapter*pAd,
	TX_BLK *pTxBlk);

 void announce_802_3_packet(
	void 		*pAdSrc,
	struct sk_buff *	pPacket,
	u8 		OpMode);

#ifdef DOT11_N_SUPPORT
unsigned int BA_Reorder_AMSDU_Annnounce(
	struct rtmp_adapter *pAd,
	struct sk_buff *	pPacket,
	u8 		OpMode);
#endif /* DOT11_N_SUPPORT */

struct net_device *get_netdev_from_bssid(
	struct rtmp_adapter *pAd,
	u8 		FromWhichBSSID);


#ifdef DOT11_N_SUPPORT
void ba_flush_reordering_timeout_mpdus(
	struct rtmp_adapter *pAd,
	PBA_REC_ENTRY	pBAEntry,
	unsigned long			Now32);


void BAOriSessionSetUp(
			struct rtmp_adapter *   pAd,
			MAC_TABLE_ENTRY	*pEntry,
			u8 		TID,
			unsigned short			TimeOut,
			unsigned long			DelayTime,
			bool 	isForced);

void BASessionTearDownALL(
	struct rtmp_adapter *pAd,
	u8 Wcid);

void BAOriSessionTearDown(
	struct rtmp_adapter *pAd,
	u8 		Wcid,
	u8 		TID,
	bool 		bPassive,
	bool 		bForceSend);

void BARecSessionTearDown(
	struct rtmp_adapter *pAd,
	u8 		Wcid,
	u8 		TID,
	bool 		bPassive);
#endif /* DOT11_N_SUPPORT */

bool ba_reordering_resource_init(struct rtmp_adapter *pAd, int num);
void ba_reordering_resource_release(struct rtmp_adapter *pAd);

INT ComputeChecksum(
	unsigned int PIN);

unsigned int GenerateWpsPinCode(
	struct rtmp_adapter *pAd,
    bool         bFromApcli,
	u8 apidx);




#ifdef NINTENDO_AP
void InitNINTENDO_TABLE(
	struct rtmp_adapter *pAd);

u8 CheckNINTENDO_TABLE(
	struct rtmp_adapter *pAd,
	char *pDS_Ssid,
	u8 DS_SsidLen,
	u8 *pDS_Addr);

u8 DelNINTENDO_ENTRY(
	struct rtmp_adapter *pAd,
	u8 * pDS_Addr);

void RTMPIoctlNintendoCapable(
	struct rtmp_adapter *pAd,
	RTMP_IOCTL_INPUT_STRUCT			*wrq);

void RTMPIoctlNintendoGetTable(
	struct rtmp_adapter *pAd,
	RTMP_IOCTL_INPUT_STRUCT			*wrq);

void RTMPIoctlNintendoSetTable(
	struct rtmp_adapter *pAd,
	RTMP_IOCTL_INPUT_STRUCT			*wrq);

#endif /* NINTENDO_AP */

bool rtstrmactohex(
	char *s1,
	char *s2);

bool rtstrcasecmp(
	char *s1,
	char *s2);

char *rtstrstruncasecmp(
	char *s1,
	char *s2);

char *rtstrstr(
	const char *s1,
	const char *s2);

char *rstrtok(
	char *s,
	const char *ct);

int rtinet_aton(
	const char *cp,
	unsigned int *addr);

/*//////// common ioctl functions ////////*/
INT Set_DriverVersion_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT Set_CountryRegion_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT Set_CountryRegionABand_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT Set_WirelessMode_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT Set_MBSS_WirelessMode_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT Set_Channel_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);
INT	Set_ShortSlot_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_TxPower_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT Set_BGProtection_Proc(
	struct rtmp_adapter *	pAd,
	char *		arg);

INT Set_TxPreamble_Proc(
	struct rtmp_adapter *	pAd,
	char *		arg);

INT Set_RTSThreshold_Proc(
	struct rtmp_adapter *	pAd,
	char *		arg);

INT Set_FragThreshold_Proc(
	struct rtmp_adapter *	pAd,
	char *		arg);

INT Set_TxBurst_Proc(
	struct rtmp_adapter *	pAd,
	char *		arg);


#ifdef AGGREGATION_SUPPORT
INT	Set_PktAggregate_Proc(
	struct rtmp_adapter *	pAd,
	char *		arg);
#endif /* AGGREGATION_SUPPORT */

INT	Set_IEEE80211H_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

#ifdef EXT_BUILD_CHANNEL_LIST
INT Set_ExtCountryCode_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

INT Set_ExtDfsType_Proc(
    struct rtmp_adapter *  pAd,
    char *        arg);

INT Set_ChannelListAdd_Proc(
    struct rtmp_adapter *  pAd,
    char *        arg);

INT Set_ChannelListShow_Proc(
    struct rtmp_adapter *pAd,
    char *		arg);
INT Set_ChannelListDel_Proc(
    struct rtmp_adapter *pAd,
    char *		arg);
#endif /* EXT_BUILD_CHANNEL_LIST */

#ifdef DBG
INT	Set_Debug_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_DebugFunc_Proc(
	struct rtmp_adapter*pAd,
	char *arg);
#endif

INT Set_RateAdaptInterval(
	struct rtmp_adapter*pAd,
	char *arg);


#ifdef CFO_TRACK
INT Set_CFOTrack_Proc(
    struct rtmp_adapter *  pAd,
    char *        arg);

#ifdef CFO_TRACK
#endif /* CFO_TRACK */

#endif // CFO_TRACK //

#ifdef DBG_CTRL_SUPPORT
INT Set_DebugFlags_Proc(
    struct rtmp_adapter *  pAd,
    char *         arg);

#ifdef INCLUDE_DEBUG_QUEUE
INT Set_DebugQueue_Proc(
    struct rtmp_adapter *  pAd,
    char *        arg);

void dbQueueEnqueue(
	u8 type,
	u8 *data);

void dbQueueEnqueueTxFrame(
	u8 *pTxWI,
	u8 *pHeader_802_11);

void dbQueueEnqueueRxFrame(
	u8 *pRxWI,
	u8 *pHeader_802_11,
	unsigned long flags);
#endif /* INCLUDE_DEBUG_QUEUE */
#endif /* DBG_CTRL_SUPPORT */

INT	Show_DescInfo_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT Show_MacTable_Proc(struct rtmp_adapter*pAd, char **arg);
INT show_devinfo_proc(struct rtmp_adapter*pAd, char *arg);
INT show_trinfo_proc(struct rtmp_adapter*pAd, char *arg);

INT	Set_ResetStatCounter_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

#ifdef DOT11_N_SUPPORT
INT	Set_BASetup_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_BADecline_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_BAOriTearDown_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_BARecTearDown_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtBw_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtMcs_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtGi_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtOpMode_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtStbc_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtHtc_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtExtcha_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtMpduDensity_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtBaWinSize_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtRdg_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtLinkAdapt_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtAmsdu_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtAutoBa_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtProtect_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtMimoPs_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

#ifdef DOT11N_DRAFT3
INT Set_HT_BssCoex_Proc(
	struct rtmp_adapter *	pAd,
	char *			pParam);

INT Set_HT_BssCoexApCntThr_Proc(
	struct rtmp_adapter *	pAd,
	char *			pParam);
#endif /* DOT11N_DRAFT3 */



INT	Set_ForceShortGI_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_ForceGF_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	SetCommonHT(struct rtmp_adapter*pAd);

INT	Set_SendPSMPAction_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

void convert_reordering_packet_to_preAMSDU_or_802_3_packet(
	struct rtmp_adapter *pAd,
	RX_BLK			*pRxBlk,
	u8 		FromWhichBSSID);

INT	Set_HtMIMOPSmode_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);


INT	Set_HtTxBASize_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_HtDisallowTKIP_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_BurstMode_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);
#endif /* DOT11_N_SUPPORT */


#ifdef DOT11_VHT_AC
INT Set_VhtBw_Proc(struct rtmp_adapter*pAd, char *arg);
INT Set_VhtStbc_Proc(struct rtmp_adapter*pAd, char *arg);
INT Set_VhtBwSignal_Proc(struct rtmp_adapter*pAd, char *arg);
#endif /* DOT11_VHT_AC */


#ifdef APCLI_SUPPORT
INT RTMPIoctlConnStatus(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

#endif /*APCLI_SUPPORT*/




#ifdef CONFIG_STA_SUPPORT
void RTMPSendDLSTearDownFrame(
	struct rtmp_adapter *pAd,
	u8 *		pDA);

#ifdef DOT11_N_SUPPORT
void QueryBATABLE(
	struct rtmp_adapter *pAd,
	PQUERYBA_TABLE pBAT);
#endif /* DOT11_N_SUPPORT */

#ifdef WPA_SUPPLICANT_SUPPORT
INT	    WpaCheckEapCode(
	struct rtmp_adapter *  	pAd,
	u8 *			pFrame,
	unsigned short				FrameLen,
	unsigned short				OffSet);
#endif /* WPA_SUPPLICANT_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */



#ifdef DOT11_N_SUPPORT
void Handle_BSS_Width_Trigger_Events(struct rtmp_adapter*pAd);

void build_ext_channel_switch_ie(
	struct rtmp_adapter*pAd,
	HT_EXT_CHANNEL_SWITCH_ANNOUNCEMENT_IE *pIE);

void assoc_ht_info_debugshow(
	struct rtmp_adapter*pAd,
	MAC_TABLE_ENTRY *pEntry,
	u8 ht_cap_len,
	HT_CAPABILITY_IE *pHTCapability);
#endif /* DOT11_N_SUPPORT */

bool APRxDoneInterruptHandle(struct rtmp_adapter*pAd);
bool STARxDoneInterruptHandle(struct rtmp_adapter*pAd, bool argc);
bool RxDoneInterruptHandle(struct rtmp_adapter*pAd);

#ifdef DOT11_N_SUPPORT
/* AMPDU packet indication */
void Indicate_AMPDU_Packet(
	struct rtmp_adapter *pAd,
	RX_BLK			*pRxBlk,
	u8 		FromWhichBSSID);

/* AMSDU packet indication */
void Indicate_AMSDU_Packet(
	struct rtmp_adapter *pAd,
	RX_BLK			*pRxBlk,
	u8 		FromWhichBSSID);

void BaReOrderingBufferMaintain(
    struct rtmp_adapter *pAd);
#endif /* DOT11_N_SUPPORT */

/* Normal legacy Rx packet indication */
void Indicate_Legacy_Packet(
	struct rtmp_adapter *pAd,
	RX_BLK			*pRxBlk,
	u8 		FromWhichBSSID);

void Indicate_EAPOL_Packet(
	struct rtmp_adapter *pAd,
	RX_BLK			*pRxBlk,
	u8 		FromWhichBSSID);

unsigned int deaggregate_AMSDU_announce(
	struct rtmp_adapter *pAd,
	struct sk_buff *		pPacket,
	u8 *		pData,
	unsigned long			DataSize,
	u8 		OpMode);

bool CmdRspEventCallbackHandle(struct rtmp_adapter *pAd, u8 *pRspBuffer);


#ifdef CONFIG_STA_SUPPORT
/* remove LLC and get 802_3 Header */
#define  RTMP_802_11_REMOVE_LLC_AND_CONVERT_TO_802_3(_pRxBlk, _pHeader802_3)	\
{																				\
	u8 *_pRemovedLLCSNAP = NULL, *_pDA, *_pSA;                                 \
																				\
	if (RX_BLK_TEST_FLAG(_pRxBlk, fRX_WDS) || RX_BLK_TEST_FLAG(_pRxBlk, fRX_MESH)) \
	{                                                                           \
		_pDA = _pRxBlk->pHeader->Addr3;                                         \
		_pSA = (u8 *)_pRxBlk->pHeader + sizeof(HEADER_802_11);                \
	}                                                                           \
	else                                                                        \
	{                                                                           \
		if (RX_BLK_TEST_FLAG(_pRxBlk, fRX_INFRA))                              	\
		{                                                                       \
			_pDA = _pRxBlk->pHeader->Addr1;                                     \
		if (RX_BLK_TEST_FLAG(_pRxBlk, fRX_DLS))									\
			_pSA = _pRxBlk->pHeader->Addr2;										\
		else																	\
			_pSA = _pRxBlk->pHeader->Addr3;                                     \
		}                                                                       \
		else                                                                    \
		{                                                                       \
			_pDA = _pRxBlk->pHeader->Addr1;                                     \
			_pSA = _pRxBlk->pHeader->Addr2;                                     \
		}                                                                       \
	}                                                                           \
																				\
	CONVERT_TO_802_3(_pHeader802_3, _pDA, _pSA, _pRxBlk->pData, 				\
		_pRxBlk->DataSize, _pRemovedLLCSNAP);                                   \
}
#endif /* CONFIG_STA_SUPPORT */


bool APFowardWirelessStaToWirelessSta(
	struct rtmp_adapter *pAd,
	struct sk_buff *	pPacket,
	unsigned long			FromWhichBSSID);

void Announce_or_Forward_802_3_Packet(
	struct rtmp_adapter *pAd,
	struct sk_buff *	pPacket,
	u8 		FromWhichBSSID);

void Sta_Announce_or_Forward_802_3_Packet(
	struct rtmp_adapter *pAd,
	struct sk_buff *	pPacket,
	u8 		FromWhichBSSID);


#ifdef CONFIG_STA_SUPPORT
#define ANNOUNCE_OR_FORWARD_802_3_PACKET(_pAd, _pPacket, _FromWhichBSS)\
			Sta_Announce_or_Forward_802_3_Packet(_pAd, _pPacket, _FromWhichBSS);
			/*announce_802_3_packet(_pAd, _pPacket); */
#endif /* CONFIG_STA_SUPPORT */




/* Normal, AMPDU or AMSDU */
void CmmRxnonRalinkFrameIndicate(
	struct rtmp_adapter*pAd,
	RX_BLK *pRxBlk,
	u8 FromWhichBSSID);

void CmmRxRalinkFrameIndicate(
	struct rtmp_adapter*pAd,
	MAC_TABLE_ENTRY *pEntry,
	RX_BLK *pRxBlk,
	u8 FromWhichBSSID);

void Update_Rssi_Sample(
	struct rtmp_adapter*pAd,
	RSSI_SAMPLE *pRssi,
	struct rxwi_nmac *pRxWI);

struct sk_buff * GetPacketFromRxRing(
	struct rtmp_adapter*pAd,
	RX_BLK *pRxBlk,
	bool  *pbReschedule,
	u32 *pRxPending,
	bool *bCmdRspPacket);

struct sk_buff * RTMPDeFragmentDataFrame(
	struct rtmp_adapter*pAd,
	RX_BLK *pRxBlk);

/*////////////////////////////////////*/

#ifdef CONFIG_STA_SUPPORT

/* The radio capture header precedes the 802.11 header. */
typedef struct __attribute__ ((packed)) _ieee80211_radiotap_header {
    u8	it_version;	/* Version 0. Only increases
				 * for drastic changes,
				 * introduction of compatible
				 * new fields does not count.
				 */
    u8	it_pad;
    uint16_t     it_len;         /* length of the whole
				 * header in bytes, including
				 * it_version, it_pad,
				 * it_len, and data fields.
				 */
    u32   it_present;	/* A bitmap telling which
					 * fields are present. Set bit 31
					 * (0x80000000) to extend the
					 * bitmap by another 32 bits.
					 * Additional extensions are made
					 * by setting bit 31.
					 */
}ieee80211_radiotap_header ;

enum ieee80211_radiotap_type {
    IEEE80211_RADIOTAP_TSFT = 0,
    IEEE80211_RADIOTAP_FLAGS = 1,
    IEEE80211_RADIOTAP_RATE = 2,
    IEEE80211_RADIOTAP_CHANNEL = 3,
    IEEE80211_RADIOTAP_FHSS = 4,
    IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
    IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
    IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
    IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
    IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
    IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
    IEEE80211_RADIOTAP_ANTENNA = 11,
    IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
    IEEE80211_RADIOTAP_DB_ANTNOISE = 13
};

#define WLAN_RADIOTAP_PRESENT (			\
	(1 << IEEE80211_RADIOTAP_TSFT)	|	\
	(1 << IEEE80211_RADIOTAP_FLAGS) |	\
	(1 << IEEE80211_RADIOTAP_RATE)  | 	\
	 0)

typedef struct _wlan_radiotap_header {
	ieee80211_radiotap_header wt_ihdr;
	int64_t wt_tsft;
	u8 wt_flags;
	u8 wt_rate;
} wlan_radiotap_header;
/* Definition from madwifi */


void STA_MonPktSend(
	struct rtmp_adapter *pAd,
	RX_BLK			*pRxBlk);

void    RTMPSetDesiredRates(
    struct rtmp_adapter *  pAdapter,
    long            Rates);

#endif /* CONFIG_STA_SUPPORT */

INT	Set_FixedTxMode_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT Set_LongRetryLimit_Proc(
	struct rtmp_adapter *pAdapter,
	char *		arg);

INT Set_ShortRetryLimit_Proc(
	struct rtmp_adapter *pAdapter,
	char *		arg);

INT Set_AutoFallBack_Proc(
	struct rtmp_adapter *pAdapter,
	char *		arg);


void RT28XXDMADisable(
	struct rtmp_adapter		*pAd);

void RT28XXDMAEnable(
	struct rtmp_adapter		*pAd);

void RT28xx_UpdateBeaconToAsic(
	struct rtmp_adapter* pAd,
	INT apidx,
	unsigned long BeaconLen,
	unsigned long UpdatePos);

void CfgInitHook(struct rtmp_adapter *pAd);


int RtmpNetTaskInit(
	struct rtmp_adapter*pAd);

void RtmpNetTaskExit(
	struct rtmp_adapter *pAd);

int RtmpMgmtTaskInit(
	struct rtmp_adapter*pAd);

void RtmpMgmtTaskExit(
	struct rtmp_adapter*pAd);

void tbtt_tasklet(unsigned long data);





void AsicTurnOffRFClk(
	struct rtmp_adapter *   pAd,
	u8           Channel);



#ifdef RTMP_TIMER_TASK_SUPPORT
INT RtmpTimerQThread(
	unsigned long Context);

RTMP_TIMER_TASK_ENTRY *RtmpTimerQInsert(
	struct rtmp_adapter*pAd,
	RALINK_TIMER_STRUCT *pTimer);

bool RtmpTimerQRemove(
	struct rtmp_adapter*pAd,
	RALINK_TIMER_STRUCT *pTimer);

void RtmpTimerQExit(
	struct rtmp_adapter*pAd);

void RtmpTimerQInit(
	struct rtmp_adapter*pAd);
#endif /* RTMP_TIMER_TASK_SUPPORT */


#ifdef RTMP_MAC_USB

int RTUSBMultiWrite(
	struct rtmp_adapter *pAd,
	unsigned short			Offset,
	u8 *		pData,
	unsigned short			length);

int RTUSBMultiWrite_OneByte(
	struct rtmp_adapter *pAd,
	unsigned short			Offset,
	u8 *		pData);

int RTUSBWriteRFRegister(
	struct rtmp_adapter *pAd,
	u32			Value);

int RTUSB_VendorRequest(
	struct rtmp_adapter *pAd,
	u8 		ReservedBits,
	u8 		Request,
	u16		Value,
	u16		Index,
	void *		TransferBuffer,
	u32		TransferBufferLength);

void RTUSBDequeueCmd(struct rtmp_command_queue *cmdq,
	struct rtmp_queue_elem	*pcmdqelmt);

INT RTUSBCmdThread(
	unsigned long Context);

void RTUSBBssBeaconExit(
	struct rtmp_adapter*pAd);

void RTUSBBssBeaconStop(
	struct rtmp_adapter*pAd);

void RTUSBBssBeaconStart(
	struct rtmp_adapter* pAd);

void RTUSBBssBeaconInit(
	struct rtmp_adapter*pAd);

int mt7610u_write32(
	struct rtmp_adapter *pAd,
	unsigned short			Offset,
	u32			Value);

u32 mt7610u_read32(struct rtmp_adapter *pAd, unsigned short Offset);

int RTUSBSingleWrite(
	struct rtmp_adapter	*pAd,
	unsigned short			Offset,
	unsigned short			Value);

int	RTUSBVenderReset(
	struct rtmp_adapter *pAd);

int RTUSBSetHardWareRegister(
	struct rtmp_adapter *pAdapter,
	void *		pBuf);

int RTUSBQueryHardWareRegister(
	struct rtmp_adapter *pAdapter,
	void *		pBuf);

/*void CMDHandler( */
/*    struct rtmp_adapter *pAd); */

int	RTUSBWriteHWMACAddress(
	struct rtmp_adapter*pAd);

void MlmeSetPsm(
	struct rtmp_adapter*pAd,
	unsigned short psm);

int RTMPWPAAddKeyProc(
	struct rtmp_adapter*pAd,
	void *pBuf);

void AsicRxAntEvalAction(
	struct rtmp_adapter*pAd);

void append_pkt(
	struct rtmp_adapter*pAd,
	u8 *pHeader802_3,
	unsigned int HdrLen,
	u8 *pData,
	unsigned long DataSize,
	struct sk_buff * *ppPacket);


void RTUSBMlmeHardTransmit(
	struct rtmp_adapter*pAd,
	MGMT_STRUC *pMgmt);

INT MlmeThread(unsigned long Context);


/*
	Function Prototype in rtusb_data.c
*/
int	RTUSBFreeDescRequest(
	struct rtmp_adapter*pAd,
	u8 BulkOutPipeId,
	u32 req_cnt);


bool RTUSBNeedQueueBackForAgg(
	struct rtmp_adapter*pAd,
	u8 	BulkOutPipeId);


unsigned short RtmpUSB_WriteSingleTxResource(
	struct rtmp_adapter *pAd,
	TX_BLK			*pTxBlk,
	bool 		bIsLast,
	unsigned short			*FreeNumber);

unsigned short	RtmpUSB_WriteFragTxResource(
	struct rtmp_adapter *pAd,
	TX_BLK			*pTxBlk,
	u8 		fragNum,
	unsigned short			*FreeNumber);

unsigned short RtmpUSB_WriteMultiTxResource(
	struct rtmp_adapter *pAd,
	TX_BLK			*pTxBlk,
	u8 		frameNum,
	unsigned short			*FreeNumber);

void RtmpUSB_FinalWriteTxResource(
	struct rtmp_adapter *pAd,
	TX_BLK			*pTxBlk,
	unsigned short			totalMPDUSize,
	unsigned short			TxIdx);

void RtmpUSBDataLastTxIdx(
	struct rtmp_adapter *pAd,
	u8 		QueIdx,
	unsigned short			TxIdx);

void RtmpUSBDataKickOut(
	struct rtmp_adapter *pAd,
	TX_BLK			*pTxBlk,
	u8 		QueIdx);

int RtmpUSBMgmtKickOut(
	struct rtmp_adapter	*pAd,
	u8 			QueIdx,
	struct sk_buff *		pPacket,
	u8 *		pSrcBufVA,
	unsigned int 			SrcBufLen);

void RtmpUSBNullFrameKickOut(
	struct rtmp_adapter*pAd,
	u8 	QueIdx,
	u8 	*pNullFrame,
	u32		frameLen);

void RtmpUsbStaAsicForceWakeupTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void RT28xxUsbStaAsicForceWakeup(
	struct rtmp_adapter *pAd,
	bool       bFromTx);

void RT28xxUsbStaAsicSleepThenAutoWakeup(
	struct rtmp_adapter *pAd,
	unsigned short TbttNumToNextWakeUp);

void RT28xxUsbMlmeRadioOn(
	struct rtmp_adapter *pAd);

void RT28xxUsbMlmeRadioOFF(
	struct rtmp_adapter *pAd);

void RT28xxUsbAsicRadioOff(
	struct rtmp_adapter *pAd);

bool AsicCheckCommandOk(
	struct rtmp_adapter *pAd,
	u8 	 Command);

void RT28xxUsbAsicWOWEnable(
	struct rtmp_adapter *pAd);

void RT28xxUsbAsicWOWDisable(
	struct rtmp_adapter *pAd);

#endif /* RTMP_MAC_USB */

int RTMPCheckRxError(
	struct rtmp_adapter*pAd,
	PHEADER_802_11 pHeader,
	struct rxwi_nmac *pRxWI,
	struct rtmp_rxinfo *pRxInfo);


/*////////////////////////////////////*/

#ifdef AP_QLOAD_SUPPORT
void QBSS_LoadInit(
 	struct rtmp_adapter*pAd);

void QBSS_LoadAlarmReset(
 	struct rtmp_adapter*pAd);

void QBSS_LoadAlarmResume(
 	struct rtmp_adapter*pAd);

u32 QBSS_LoadBusyTimeGet(
 	struct rtmp_adapter*pAd);

bool QBSS_LoadIsAlarmIssued(
 	struct rtmp_adapter*pAd);

bool QBSS_LoadIsBusyTimeAccepted(
 	struct rtmp_adapter*pAd,
	u32			BusyTime);

u32 QBSS_LoadElementAppend(
 	struct rtmp_adapter*pAd,
	u8			*buf_p);

u32 QBSS_LoadElementParse(
 	struct rtmp_adapter*pAd,
	u8			*pElement,
	uint16_t			*pStationCount,
	u8			*pChanUtil,
	uint16_t			*pAvalAdmCap);

void QBSS_LoadUpdate(
 	struct rtmp_adapter*pAd,
	unsigned long			UpTime);

void QBSS_LoadStatusClear(
 	struct rtmp_adapter*pAd);

INT	Show_QoSLoad_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);
#endif /* AP_QLOAD_SUPPORT */

char *RTMPGetRalinkAuthModeStr(
    NDIS_802_11_AUTHENTICATION_MODE authMode);

char *RTMPGetRalinkEncryModeStr(
    unsigned short encryMode);
/*//////////////////////////////////*/

#ifdef CONFIG_STA_SUPPORT
void AsicStaBbpTuning(
	struct rtmp_adapter *pAd);

bool StaAddMacTableEntry(
	struct rtmp_adapter *	pAd,
	PMAC_TABLE_ENTRY	pEntry,
	u8 			MaxSupportedRateIn500Kbps,
	HT_CAPABILITY_IE	*pHtCapability,
	u8 			HtCapabilityLen,
	ADD_HT_INFO_IE		*pAddHtInfo,
	u8 			AddHtInfoLen,
	IE_LISTS *ie_list,
	unsigned short        		CapabilityInfo);


bool AUTH_ReqSend(
	struct rtmp_adapter *		pAd,
	PMLME_QUEUE_ELEM	pElem,
	PRALINK_TIMER_STRUCT pAuthTimer,
	char *			pSMName,
	unsigned short				SeqNo,
	u8 *			pNewElement,
	unsigned long				ElementLen);
#endif /* CONFIG_STA_SUPPORT */


void ReSyncBeaconTime(struct rtmp_adapter*pAd);

#ifdef MFB_SUPPORT
void MFB_PerPareMRQ(
	struct rtmp_adapter *pAd,
	void *pBuf,
	PMAC_TABLE_ENTRY pEntry);

void MFB_PerPareMFB(
	struct rtmp_adapter *pAd,
	void *pBuf,
	PMAC_TABLE_ENTRY pEntry);
#endif /* MFB_SUPPORT */

#define VIRTUAL_IF_INC(__pAd) ((__pAd)->VirtualIfCnt++)
#define VIRTUAL_IF_DEC(__pAd) ((__pAd)->VirtualIfCnt--)
#define VIRTUAL_IF_NUM(__pAd) ((__pAd)->VirtualIfCnt)



#ifdef RTMP_USB_SUPPORT
/*
 * Function Prototype in rtusb_bulk.c
 */

void RTUSBInitTxDesc(
	struct rtmp_adapter *pAd,
	PTX_CONTEXT		pTxContext,
	u8 		BulkOutPipeId,
	usb_complete_t	Func);

void RTUSBInitHTTxDesc(
	struct rtmp_adapter *pAd,
	PHT_TX_CONTEXT	pTxContext,
	u8 		BulkOutPipeId,
	unsigned long			BulkOutSize,
	usb_complete_t	Func);

void RTUSBInitRxDesc(
	struct rtmp_adapter *pAd,
	PRX_CONTEXT		pRxContext);

void RTUSBCleanUpDataBulkOutQueue(
	struct rtmp_adapter *pAd);

void RTUSBCancelPendingBulkOutIRP(
	struct rtmp_adapter *pAd);

void RTUSBBulkOutDataPacket(
	struct rtmp_adapter *pAd,
	u8 		BulkOutPipeId,
	u8 		Index);

void RTUSBBulkOutNullFrame(
	struct rtmp_adapter *pAd);

void RTUSBBulkOutRTSFrame(
	struct rtmp_adapter *pAd);

void RTUSBCancelPendingBulkInIRP(
	struct rtmp_adapter *pAd);

void RTUSBCancelPendingIRPs(
	struct rtmp_adapter *pAd);

void RTUSBBulkOutMLMEPacket(
	struct rtmp_adapter *pAd,
	u8 		Index);

void RTUSBBulkOutPsPoll(
	struct rtmp_adapter *pAd);

void RTUSBCleanUpMLMEBulkOutQueue(
	struct rtmp_adapter *pAd);

void RTUSBKickBulkOut(
	struct rtmp_adapter *pAd);

void RTUSBBulkReceive(
	struct rtmp_adapter *pAd);

void RTUSBBulkCmdRspEventReceive(
	struct rtmp_adapter *pAd);

void DoBulkIn(
	struct rtmp_adapter*pAd);

void RTUSBInitRxDesc(
	struct rtmp_adapter *pAd,
	PRX_CONTEXT		pRxContext);

void RTUSBBulkRxHandle(
	unsigned long data);
#endif /* RTMP_USB_SUPPORT */


#ifdef SOFT_ENCRYPT
bool RTMPExpandPacketForSwEncrypt(
	struct rtmp_adapter *  pAd,
	PTX_BLK			pTxBlk);

void RTMPUpdateSwCacheCipherInfo(
	struct rtmp_adapter *  pAd,
	PTX_BLK			pTxBlk,
	u8 *		pHdr);
#endif /* SOFT_ENCRYPT */


/*
	OS Related funciton prototype definitions.
	TODO: Maybe we need to move these function prototypes to other proper place.
*/

void RTInitializeCmdQ(struct rtmp_command_queue *cmdq);

INT RTPCICmdThread(
	unsigned long Context);

void CMDHandler(
    struct rtmp_adapter *pAd);

void RTThreadDequeueCmd(struct rtmp_command_queue *cmdq,
	struct rtmp_queue_elem **pcmdqelmt);

int RTEnqueueInternalCmd(
	struct rtmp_adapter *pAd,
	NDIS_OID			Oid,
	void *		pInformationBuffer,
	u32			InformationBufferLength);

#ifdef HOSTAPD_SUPPORT
void ieee80211_notify_michael_failure(
	struct rtmp_adapter *   pAd,
	PHEADER_802_11   pHeader,
	unsigned int            keyix,
	INT              report);

const CHAR* ether_sprintf(const u8 *mac);
#endif/*HOSTAPD_SUPPORT*/

INT WaitForAsicReady(
	struct rtmp_adapter*pAd);

bool CHAN_PropertyCheck(
	struct rtmp_adapter *pAd,
	u32			ChanNum,
	u8 		Property);

#ifdef CONFIG_STA_SUPPORT

/* command */
INT Set_SSID_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

INT Set_NetworkType_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

INT Set_AuthMode_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

INT Set_EncrypType_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

INT Set_DefaultKeyID_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

INT Set_Wep_Key_Proc(struct rtmp_adapter *pAd, char *Key, INT KeyLen, INT KeyId);

INT Set_Key1_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

INT Set_Key2_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

INT Set_Key3_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

INT Set_Key4_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

INT Set_WPAPSK_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);


INT Set_PSMode_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

#ifdef WPA_SUPPLICANT_SUPPORT
INT Set_Wpa_Support(
    struct rtmp_adapter *pAd,
	char *		arg);
#endif /* WPA_SUPPLICANT_SUPPORT */

#ifdef DBG

void RTMPIoctlMAC(
	struct rtmp_adapter *pAdapter,
	RTMP_IOCTL_INPUT_STRUCT	*wrq);

#endif /* DBG */


int RTMPWPANoneAddKeyProc(
    struct rtmp_adapter *  pAd,
    void *		pBuf);

INT Set_FragTest_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);

#ifdef DOT11_N_SUPPORT
INT Set_TGnWifiTest_Proc(
    struct rtmp_adapter *  pAd,
    char *         arg);
#endif /* DOT11_N_SUPPORT */

INT Set_LongRetryLimit_Proc(
	struct rtmp_adapter *pAdapter,
	char *		arg);

INT Set_ShortRetryLimit_Proc(
	struct rtmp_adapter *pAdapter,
	char *		arg);

#ifdef EXT_BUILD_CHANNEL_LIST
INT Set_Ieee80211dClientMode_Proc(
    struct rtmp_adapter *  pAdapter,
    char *         arg);
#endif /* EXT_BUILD_CHANNEL_LIST */

INT	Show_Adhoc_MacTable_Proc(
	struct rtmp_adapter *pAd,
	char *		extra,
	u32			size);



INT Set_BeaconLostTime_Proc(
    struct rtmp_adapter *  pAd,
    char *        arg);

INT Set_AutoRoaming_Proc(
    struct rtmp_adapter *  pAd,
    char *        arg);

INT Set_SiteSurvey_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT Set_ForceTxBurst_Proc(
    struct rtmp_adapter *  pAd,
    char *        arg);

void RTMPAddKey(
	struct rtmp_adapter *    pAd,
	PNDIS_802_11_KEY    pKey);


void StaSiteSurvey(
	struct rtmp_adapter * 		pAd,
	PNDIS_802_11_SSID	pSsid,
	u8 			ScanType);

void MaintainBssTable(
	struct rtmp_adapter *pAd,
	BSS_TABLE *Tab,
	unsigned long	MaxRxTimeDiff,
	u8 MaxSameRxTimeCount);
#endif /* CONFIG_STA_SUPPORT */

void  getRate(
    HTTRANSMIT_SETTING HTSetting,
    unsigned long* fLastTxRxRate);


#ifdef APCLI_SUPPORT
#ifdef APCLI_WPA_SUPPLICANT_SUPPORT
void    ApcliSendAssocIEsToWpaSupplicant(
    struct rtmp_adapter *pAd,
    unsigned int ifIndex);

INT	    ApcliWpaCheckEapCode(
	struct rtmp_adapter *  		pAd,
	u8 *			pFrame,
	unsigned short				FrameLen,
	unsigned short				OffSet);

void    ApcliWpaSendEapolStart(
	struct rtmp_adapter *pAd,
	u8 *         pBssid,
	PMAC_TABLE_ENTRY pMacEntry,
	PAPCLI_STRUCT pApCliEntry);


void ApCliRTMPSendNullFrame(
	struct rtmp_adapter *pAd,
	u8 		TxRate,
	bool 		bQosNull,
	PMAC_TABLE_ENTRY pMacEntry);

#endif/*APCLI_WPA_SUPPLICANT_SUPPORT*/
#endif/*APCLI_SUPPORT*/


void RTMP_IndicateMediaState(
	struct rtmp_adapter *	pAd,
	NDIS_MEDIA_STATE	media_state);

#if defined(RT3350) || defined(RT33xx)
void RTMP_TxEvmCalibration(
	struct rtmp_adapter *pAd);
#endif /* defined(RT3350) || defined(RT33xx) */

INT RTMP_COM_IoctlHandle(
	struct rtmp_adapter *pAd,
	RTMP_IOCTL_INPUT_STRUCT *wrq,
	INT cmd,
	unsigned short subcmd,
	void *pData,
	unsigned long Data);



INT Set_VcoPeriod_Proc(
	struct rtmp_adapter*pAd,
	char *arg);

void RtmpEnqueueNullFrame(
	struct rtmp_adapter *pAd,
	u8 *       pAddr,
	u8         TxRate,
	u8         PID,
	u8         apidx,
    bool       bQosNull,
    bool       bEOSP,
    u8         OldUP);

void RtmpCleanupPsQueue(
	struct rtmp_adapter *  pAd,
	PQUEUE_HEADER   pQueue);

#ifdef CONFIG_STA_SUPPORT
bool RtmpPktPmBitCheck(
    struct rtmp_adapter *      pAd);

void RtmpPsActiveExtendCheck(
	struct rtmp_adapter *	pAd);

void RtmpPsModeChange(
	struct rtmp_adapter *	pAd,
	u32				PsMode);
#endif /* CONFIG_STA_SUPPORT */

u8 dot11_2_ra_rate(u8 MaxSupportedRateIn500Kbps);
u8 dot11_max_sup_rate(INT SupRateLen, u8 *SupRate, INT ExtRateLen, u8 *ExtRate);

void mgmt_tb_set_mcast_entry(struct rtmp_adapter*pAd);
void set_entry_phy_cfg(struct rtmp_adapter*pAd, MAC_TABLE_ENTRY *pEntry);
void MacTableReset(struct rtmp_adapter*pAd);
MAC_TABLE_ENTRY *MacTableLookup(struct rtmp_adapter*pAd, u8 *pAddr);
bool MacTableDeleteEntry(struct rtmp_adapter*pAd, unsigned short wcid, u8 *pAddr);
MAC_TABLE_ENTRY *MacTableInsertEntry(
    struct rtmp_adapter*pAd,
    u8 *pAddr,
	u8 apidx,
	u8 OpMode,
	bool CleanAll);

#ifdef MAC_REPEATER_SUPPORT
MAC_TABLE_ENTRY *InsertMacRepeaterEntry(
	struct rtmp_adapter *  pAd,
	u8 *		pAddr,
	u8 		IfIdx);
#endif /* MAC_REPEATER_SUPPORT */

void dumpTxWI(struct rtmp_adapter*pAd, struct txwi_nmac *pTxWI);
void dump_rxwi(struct rtmp_adapter*pAd, struct rxwi_nmac *pRxWI);
void dump_txinfo(struct rtmp_adapter*pAd, struct txinfo_nmac_pkt *pTxInfo);
void dump_rxinfo(struct rtmp_adapter*pAd, struct rtmp_rxinfo *pRxInfo);
void dumpRxFCEInfo(struct rtmp_adapter*pAd, RXFCE_INFO *pRxFceInfo);

#ifdef WFA_VHT_PF
INT set_force_amsdu(struct rtmp_adapter*pAd, char *arg);
INT set_force_noack(struct rtmp_adapter*pAd, char *arg);
INT set_force_vht_sgi(struct rtmp_adapter*pAd, char *arg);
INT set_force_vht_tx_stbc(struct rtmp_adapter*pAd, char *arg);
INT set_force_ext_cca(struct rtmp_adapter*pAd, char *arg);
#ifdef IP_ASSEMBLY
INT set_force_ip_assemble(struct rtmp_adapter*pAd, char *arg);
#endif /* IP_ASSEMBLY */
#endif /* WFA_VHT_PF */



#ifdef RLT_RF
INT set_rf(struct rtmp_adapter*pAd, char *arg);
#endif /* RLT_RF */

#ifdef RTMP_MAC_USB
bool CmdRspEventHandle(struct rtmp_adapter*pAd);
#endif /* RTMP_MAC_USB */

#endif  /* __RTMP_H__ */

#ifdef MT76x0
INT set_temp_sensor_proc(
	struct rtmp_adapter	*pAd,
	char *		arg);
#endif /* MT76x0 */
