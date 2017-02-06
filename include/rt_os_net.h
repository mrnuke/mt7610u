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


#ifndef __RT_OS_NET_H__
#define __RT_OS_NET_H__

#include "chip/chip_id.h"

typedef void *(*RTMP_NET_ETH_CONVERT_DEV_SEARCH)(void *net_dev, u8 *pData);
typedef int (*RTMP_NET_PACKET_TRANSMIT)(void *pPacket);

/* ========================================================================== */
/* operators used in DRIVER module */
typedef void (*RTMP_DRV_USB_COMPLETE_HANDLER)(void *pURB);

typedef struct _RTMP_NET_ABL_OPS {

#ifdef RTMP_USB_SUPPORT
/* net complete handlers */
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpNetUsbBulkOutDataPacketComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpNetUsbBulkOutMLMEPacketComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpNetUsbBulkOutNullFrameComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpNetUsbBulkOutRTSFrameComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpNetUsbBulkOutPsPollComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpNetUsbBulkRxComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpNetUsbBulkCmdRspEventComplete;

/* drv complete handlers */
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpDrvUsbBulkOutDataPacketComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpDrvUsbBulkOutMLMEPacketComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpDrvUsbBulkOutNullFrameComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpDrvUsbBulkOutRTSFrameComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpDrvUsbBulkOutPsPollComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpDrvUsbBulkRxComplete;
RTMP_DRV_USB_COMPLETE_HANDLER	RtmpDrvUsbBulkCmdRspEventComplete;

#endif /* RTMP_USB_SUPPORT */

} RTMP_NET_ABL_OPS;

extern RTMP_NET_ABL_OPS *pRtmpDrvNetOps;

void RtmpNetOpsInit(void *pNetOpsOrg);
void RtmpNetOpsSet(void *pNetOpsOrg);


/* ========================================================================== */

int RTMPAllocAdapterBlock(struct os_cookie *handle, struct rtmp_adapter **ppAdapter);
void RTMPFreeAdapter(struct rtmp_adapter *pAd);
bool RtmpRaDevCtrlExit(struct rtmp_adapter *pAd);
int RtmpRaDevCtrlInit(struct rtmp_adapter *pAd, RTMP_INF_TYPE infType);
void RTMPHandleInterrupt(struct rtmp_adapter *pAd);

int RTMP_COM_IoctlHandle(
	struct rtmp_adapter *pAd,
	RTMP_IOCTL_INPUT_STRUCT	*wrq,
	int						cmd,
	unsigned short					subcmd,
	void 				*pData,
	unsigned long					Data);

int	RTMPSendPackets(
	struct rtmp_adapter	*pAd,
	struct sk_buff 		*pPacket);

int MBSS_PacketSend(
	struct sk_buff *				pPktSrc,
	struct net_device *				pDev,
	RTMP_NET_PACKET_TRANSMIT	Func);

int WDS_PacketSend(
	struct sk_buff *				pPktSrc,
	struct net_device *				pDev,
	RTMP_NET_PACKET_TRANSMIT	Func);

int APC_PacketSend(
	struct sk_buff *				pPktSrc,
	struct net_device *				pDev,
	RTMP_NET_PACKET_TRANSMIT	Func);

int MESH_PacketSend(
	struct sk_buff *				pPktSrc,
	struct net_device *				pDev,
	RTMP_NET_PACKET_TRANSMIT	Func);

int P2P_PacketSend(
	struct sk_buff *				pPktSrc,
	struct net_device *				pDev,
	RTMP_NET_PACKET_TRANSMIT	Func);


#ifdef CONFIG_STA_SUPPORT
int RTMP_STA_IoctlHandle(
	void 				*pAd,
	RTMP_IOCTL_INPUT_STRUCT	*wrq,
	int						cmd,
	unsigned short					subcmd,
	void 				*pData,
	unsigned long					Data,
	unsigned short                  priv_flags );
#endif /* CONFIG_STA_SUPPORT */

void RTMPDrvSTAOpen(struct rtmp_adapter *pAd);
void RTMPDrvAPOpen(struct rtmp_adapter *pAd);
void RTMPDrvSTAClose(struct rtmp_adapter *pAd, struct net_device *net_dev);
void RTMPDrvAPClose(struct rtmp_adapter *pAd, struct net_device *net_dev);
void RTMPInfClose(struct rtmp_adapter *pAd);

int rt28xx_init(struct rtmp_adapter *pAd);

struct net_device *RtmpPhyNetDevMainCreate(struct rtmp_adapter *pAd);

/* ========================================================================== */
int rt28xx_close(struct net_device *net_dev);
int rt28xx_open(struct net_device *net_dev);

#ifdef RTMP_MODULE_OS


#ifdef CONFIG_STA_SUPPORT
int rt28xx_sta_ioctl(
	struct net_device *	net_dev,
	struct ifreq	*rq,
	int			cmd);
#endif /* CONFIG_STA_SUPPORT */

struct net_device *RtmpPhyNetDevInit(
	void 					*pAd,
	RTMP_OS_NETDEV_OP_HOOK	*pNetHook);

bool RtmpPhyNetDevExit(
	void 					*pAd,
	struct net_device *				net_dev);

#endif /* RTMP_MODULE_OS && OS_ABL_FUNC_SUPPORT */


void RT28xx_MBSS_Init(
	void *pAd,
	struct net_device *main_dev_p);
void RT28xx_MBSS_Remove(
	void *pAd);
int MBSS_VirtualIF_Open(
	struct net_device *		dev_p);
int MBSS_VirtualIF_Close(
	struct net_device *		dev_p);
int MBSS_VirtualIF_PacketSend(
	struct sk_buff *			skb_p,
	struct net_device *			dev_p);
int MBSS_VirtualIF_Ioctl(
	struct net_device *			dev_p,
	void 			*rq_p,
	int cmd);

void RT28xx_WDS_Init(
	void 				*pAd,
	struct net_device *			net_dev);
int WdsVirtualIFSendPackets(
	struct sk_buff *			pSkb,
	struct net_device *			dev);
int WdsVirtualIF_open(
	struct net_device *		dev);
int WdsVirtualIF_close(
	struct net_device *			dev);
int WdsVirtualIF_ioctl(
	struct net_device *			net_dev,
	void 			*rq,
	int					cmd);
void RT28xx_WDS_Remove(
	void 				*pAd);

void RT28xx_ApCli_Init(
	void 				*pAd,
	struct net_device *			main_dev_p);
int ApCli_VirtualIF_Open(
	struct net_device *			dev_p);
int ApCli_VirtualIF_Close(
	struct net_device *		dev_p);
int ApCli_VirtualIF_PacketSend(
	struct sk_buff * 		pPktSrc,
	struct net_device *			pDev);
int ApCli_VirtualIF_Ioctl(
	struct net_device *			dev_p,
	void 			*rq_p,
	int 					cmd);
void RT28xx_ApCli_Remove(
	void 				*pAd);

void RTMP_Mesh_Init(
	void 				*pAd,
	struct net_device *			main_dev_p,
	char *			pHostName);
void RTMP_Mesh_Remove(
	void 				*pAd);
int Mesh_VirtualIF_Open(
	struct net_device *			pDev);
int Mesh_VirtualIF_Close(
	struct net_device *		pDev);
int Mesh_VirtualIF_PacketSend(
	struct sk_buff * 		pPktSrc,
	struct net_device *			pDev);
int Mesh_VirtualIF_Ioctl(
	struct net_device *			dev_p,
	void 			*rq_p,
	int 					cmd);

void RTMP_P2P_Init(
		 void 		 *pAd,
		 struct net_device *main_dev_p);

 int P2P_VirtualIF_Open(
	 struct net_device * dev_p);

 int P2P_VirtualIF_Close(
	 struct net_device * dev_p);

 int P2P_VirtualIF_PacketSend(
	 struct sk_buff *	 skb_p,
	 struct net_device *	 dev_p);

 int P2P_VirtualIF_Ioctl(
	 struct net_device *		 dev_p,
	 void  *rq_p,
	 int cmd);

void RTMP_P2P_Remove(
	void 			*pAd);


/* communication with RALINK DRIVER module in NET module */
/* general */
#define RTMP_DRIVER_NET_DEV_GET(__pAd, __pNetDev)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_NETDEV_GET, 0, __pNetDev, 0)

#define RTMP_DRIVER_NET_DEV_SET(__pAd, __pNetDev)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_NETDEV_SET, 0, __pNetDev, 0)

#define RTMP_DRIVER_OP_MODE_GET(__pAd, __pOpMode)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_OPMODE_GET, 0, __pOpMode, 0)

#define RTMP_DRIVER_IW_STATS_GET(__pAd, __pIwStats)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_INF_IW_STATUS_GET, 0, __pIwStats, 0)

#define RTMP_DRIVER_INF_STATS_GET(__pAd, __pInfStats)						\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_INF_STATS_GET, 0, __pInfStats, 0)

#define RTMP_DRIVER_INF_TYPE_GET(__pAd, __pInfType)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_INF_TYPE_GET, 0, __pInfType, 0)

#define RTMP_DRIVER_TASK_LIST_GET(__pAd, __pList)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_TASK_LIST_GET, 0, __pList, 0)

#define RTMP_DRIVER_NIC_NOT_EXIST_SET(__pAd)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_NIC_NOT_EXIST, 0, NULL, 0)

#define RTMP_DRIVER_MCU_SLEEP_CLEAR(__pAd)	\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_MCU_SLEEP_CLEAR, 0, NULL, 0)


//#ifdef CONFIG_STA_SUPPORT

#define RTMP_DRIVER_ADAPTER_SUSPEND_SET(__pAd)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_ADAPTER_SUSPEND_SET, 0, NULL, 0)

#define RTMP_DRIVER_ADAPTER_SUSPEND_CLEAR(__pAd)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_ADAPTER_SUSPEND_CLEAR, 0, NULL, 0)

#define RTMP_DRIVER_ADAPTER_END_DISSASSOCIATE(__pAd)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_ADAPTER_SEND_DISSASSOCIATE, 0, NULL, 0)

#define RTMP_DRIVER_ADAPTER_SUSPEND_TEST(__pAd, __flag)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_ADAPTER_SUSPEND_TEST, 0,  __flag, 0)

#define RTMP_DRIVER_ADAPTER_IDLE_RADIO_OFF_TEST(__pAd, __flag)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_ADAPTER_IDLE_RADIO_OFF_TEST, 0,  __flag, 0)

#define RTMP_DRIVER_ADAPTER_RT28XX_USB_ASICRADIO_OFF(__pAd)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_ADAPTER_RT28XX_USB_ASICRADIO_OFF, 0, NULL, 0)

#define RTMP_DRIVER_ADAPTER_RT28XX_USB_ASICRADIO_ON(__pAd)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_ADAPTER_RT28XX_USB_ASICRADIO_ON, 0, NULL, 0)


#define RTMP_DRIVER_AP_SSID_GET(__pAd, pData)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_AP_BSSID_GET, 0, pData, 0)
//#endif /* CONFIG_STA_SUPPORT */

#define RTMP_DRIVER_VIRTUAL_INF_NUM_GET(__pAd, __pIfNum)					\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_VIRTUAL_INF_GET, 0, __pIfNum, 0)

#define RTMP_DRIVER_CHANNEL_GET(__pAd, __Channel)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_SIOCGIWFREQ, 0, __Channel, 0)

#define RTMP_DRIVER_IOCTL_SANITY_CHECK(__pAd, __SetCmd)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_SANITY_CHECK, 0, __SetCmd, 0)

#define RTMP_DRIVER_BITRATE_GET(__pAd, __pBitRate)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_AP_SIOCGIWRATEQ, 0, __pBitRate, 0)

#define RTMP_DRIVER_MAIN_INF_CREATE(__pAd, __ppNetDev)						\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_INF_MAIN_CREATE, 0, __ppNetDev, 0)

#define RTMP_DRIVER_MAIN_INF_CHECK(__pAd, __InfId)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_INF_MAIN_CHECK, 0, NULL, __InfId)

#define RTMP_DRIVER_P2P_INF_CHECK(__pAd, __InfId)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_INF_P2P_CHECK, 0, NULL, __InfId)

#ifdef EXT_BUILD_CHANNEL_LIST
#define RTMP_DRIVER_SET_PRECONFIG_VALUE(__pAd)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_SET_PRECONFIG_VALUE, 0, NULL, 0)
#endif /* EXT_BUILD_CHANNEL_LIST */

/* cfg80211 */
#define RTMP_DRIVER_CFG80211_START(__pAd)									\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_CFG80211_CFG_START, 0, NULL, 0)


#ifdef RT_CFG80211_SUPPORT
#define RTMP_DRIVER_80211_CB_GET(__pAd, __ppCB)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_CB_GET, 0, __ppCB, 0)
#define RTMP_DRIVER_80211_CB_SET(__pAd, __pCB)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_CB_SET, 0, __pCB, 0)
#define RTMP_DRIVER_80211_CHAN_SET(__pAd, __pChan)						\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_CHAN_SET, 0, __pChan, 0)
#define RTMP_DRIVER_80211_VIF_SET(__pAd, __Filter, __IfType)			\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_VIF_CHG, 0, &__Filter, __IfType)
#define RTMP_DRIVER_80211_SCAN(__pAd)									\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_SCAN, 0, NULL, 0)
#define RTMP_DRIVER_80211_IBSS_JOIN(__pAd, __pInfo)						\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_IBSS_JOIN, 0, __pInfo, 0)
#define RTMP_DRIVER_80211_STA_LEAVE(__pAd)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_STA_LEAVE, 0, NULL, 0)
#define RTMP_DRIVER_80211_STA_GET(__pAd, __pStaInfo)					\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_STA_GET, 0, __pStaInfo, 0)
#define RTMP_DRIVER_80211_KEY_ADD(__pAd, __pKeyInfo)					\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_KEY_ADD, 0, __pKeyInfo, 0)
#define RTMP_DRIVER_80211_KEY_DEFAULT_SET(__pAd, __KeyId)				\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_KEY_DEFAULT_SET, 0, NULL, __KeyId)
#define RTMP_DRIVER_80211_CONNECT(__pAd, __pConnInfo)					\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_CONNECT_TO, 0, __pConnInfo, 0)
#define RTMP_DRIVER_80211_RFKILL(__pAd, __pActive)						\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_RFKILL, 0, __pActive, 0)
#define RTMP_DRIVER_80211_REG_NOTIFY(__pAd, __pNotify)					\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_REG_NOTIFY_TO, 0, __pNotify, 0)
#define RTMP_DRIVER_80211_UNREGISTER(__pAd, __pNetDev)					\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_UNREGISTER, 0, __pNetDev, 0)
#define RTMP_DRIVER_80211_BANDINFO_GET(__pAd, __pBandInfo)				\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_BANDINFO_GET, 0, __pBandInfo, 0)
#define RTMP_DRIVER_80211_SURVEY_GET(__pAd, __pSurveyInfo)				\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_SURVEY_GET, 0, __pSurveyInfo, 0)
#define RTMP_DRIVER_80211_PMKID_CTRL(__pAd, __pPmkidInfo)				\
	RTMP_STA_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_STA_SIOCSIWPMKSA, 0, __pPmkidInfo, 0, 0);

#define RTMP_DRIVER_80211_BEACON_DEL(__pAd) \
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_BEACON_DEL, 0, NULL, 0)

#define RTMP_DRIVER_80211_BEACON_ADD(__pAd, __pBeacon) \
   	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_BEACON_ADD, 0, __pBeacon, 0)

#define RTMP_DRIVER_80211_BEACON_SET(__pAd, __pBeacon) \
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_80211_BEACON_SET, 0, __pBeacon, 0)

#define RTMP_DRIVER_80211_GEN_IE_SET(__pAd, __pData, __Len)    \
    RTMP_STA_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_STA_SIOCSIWGENIE, 0, __pData, __Len, 0)

#endif /* RT_CFG80211_SUPPORT */

/* mesh */
#define RTMP_DRIVER_MESH_REMOVE(__pAd)										\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_MESH_REMOVE, 0, NULL, 0)

/* inf ppa */
#define RTMP_DRIVER_INF_PPA_INIT(__pAd)										\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_INF_PPA_INIT, 0, NULL, 0)

#define RTMP_DRIVER_INF_PPA_EXIT(__pAd)										\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_INF_PPA_EXIT, 0, NULL, 0)

/* pci */
#define RTMP_DRIVER_IRQ_INIT(__pAd)											\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_IRQ_INIT, 0, NULL, 0)

#define RTMP_DRIVER_IRQ_RELEASE(__pAd)										\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_IRQ_RELEASE, 0, NULL, 0)

#define RTMP_DRIVER_PCI_MSI_ENABLE(__pAd, __pPciDev)						\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_MSI_ENABLE, 0, __pPciDev, 0)

#define RTMP_DRIVER_PCI_SUSPEND(__pAd)										\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_PCI_SUSPEND, 0, NULL, 0)

#define RTMP_DRIVER_PCI_RESUME(__pAd)										\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_PCI_RESUME, 0, NULL, 0)

#define RTMP_DRIVER_PCI_CSR_SET(__pAd, __Address)							\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_PCI_CSR_SET, 0, NULL, __Address)

#define RTMP_DRIVER_PCIE_INIT(__pAd, __pPciDev)								\
{																			\
	RT_CMD_PCIE_INIT __Config, *__pConfig = &__Config;						\
	__pConfig->pPciDev = __pPciDev;											\
	__pConfig->ConfigDeviceID = PCI_DEVICE_ID;								\
	__pConfig->ConfigSubsystemVendorID = PCI_SUBSYSTEM_VENDOR_ID;			\
	__pConfig->ConfigSubsystemID = PCI_SUBSYSTEM_ID;						\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_PCIE_INIT, 0, __pConfig, 0);\
}

/* usb */
#define RTMP_DRIVER_USB_CONFIG_INIT(__pAd, __pConfig)						\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_USB_CONFIG_INIT, 0, __pConfig, 0)

#define RTMP_DRIVER_USB_SUSPEND(__pAd, __bIsRunning)						\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_USB_SUSPEND, 0, NULL, __bIsRunning)

#define RTMP_DRIVER_USB_RESUME(__pAd)										\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_USB_RESUME, 0, NULL, 0)

/* ap */
#define RTMP_DRIVER_AP_BITRATE_GET(__pAd, __pConfig)							\
	RTMP_AP_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_AP_SIOCGIWRATEQ, 0, __pConfig, 0)

#define RTMP_DRIVER_AP_MAIN_OPEN(__pAd)										\
	RTMP_AP_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_MAIN_OPEN, 0, NULL, 0)

/* sta */
#define RTMP_DRIVER_STA_DEV_TYPE_SET(__pAd, __Type)							\
	RTMP_STA_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_ORI_DEV_TYPE_SET, 0, NULL, __Type, __Type)

#define RTMP_DRIVER_ADAPTER_CSO_SUPPORT_TEST(__pAd, __flag)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_ADAPTER_CSO_SUPPORT_TEST, 0,  __flag, 0)

#define RTMP_DRIVER_ADAPTER_TSO_SUPPORT_TEST(__pAd, __flag)								\
	RTMP_COM_IoctlHandle(__pAd, NULL, CMD_RTPRIV_IOCTL_ADAPTER_TSO_SUPPORT_TEST, 0,  __flag, 0)

#endif /* __RT_OS_NET_H__ */

