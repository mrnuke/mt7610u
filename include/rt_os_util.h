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


#ifndef __RT_OS_UTIL_H__
#define __RT_OS_UTIL_H__

/* ============================ rt_linux.c ================================== */
/* General */
void RtmpUtilInit(void);

/* OS Time */
void RTMPusecDelay(
	ULONG					usec);

ULONG RTMPMsecsToJiffies(UINT msec);

void RTMP_GetCurrentSystemTick(
	ULONG					*pNow);

void RtmpOsWait(
	u32					Time);

u32 RtmpOsTimerAfter(
	ULONG					a,
	ULONG					b);

u32 RtmpOsTimerBefore(
	ULONG					a,
	ULONG					b);

void RtmpOsGetSystemUpTime(
	ULONG					*pTime);

u32 RtmpOsTickUnitGet(void);

/* OS Memory */

int os_alloc_mem_suspend(
	void 				*pReserved,
	u8 				**mem,
	ULONG					size);

int AdapterBlockAllocateMemory(struct rtmp_adapter **ppAd, u32 SizeOfpAd);

void *RtmpOsVmalloc(
	ULONG					Size);

void RtmpOsVfree(
	void 				*pMem);

ULONG RtmpOsCopyFromUser(
	void 				*to,
	const void				*from,
	ULONG					n);

ULONG RtmpOsCopyToUser(
	void 				*to,
	const void				*from,
	ULONG					n);

bool RtmpOsStatsAlloc(
	void 				**ppStats,
	void 				**ppIwStats);

/* OS Packet */

int RTMPAllocateNdisPacket(
	void 				*pReserved,
	struct sk_buff *			*ppPacket,
	u8 *				pHeader,
	UINT					HeaderLen,
	u8 *				pData,
	UINT					DataLen);

void RTMPFreeNdisPacket(
	void 				*pReserved,
	struct sk_buff *			pPacket);

int Sniff2BytesFromNdisBuffer(
	PNDIS_BUFFER			pFirstBuffer,
	u8           		DesiredOffset,
	u8 *         		pByte0,
	u8 *         		pByte1);

void RTMP_QueryPacketInfo(
	struct sk_buff *			pPacket,
	PACKET_INFO  			*pPacketInfo,
	u8 *	 			*pSrcBufVA,
	UINT		 			*pSrcBufLen);

struct sk_buff * DuplicatePacket(
	struct net_device *			pNetDev,
	struct sk_buff *			pPacket,
	u8 				FromWhichBSSID);

struct sk_buff * duplicate_pkt(
	struct net_device *			pNetDev,
	u8 *				pHeader802_3,
    UINT            		HdrLen,
	u8 *				pData,
	ULONG					DataSize,
	u8 				FromWhichBSSID);

struct sk_buff * duplicate_pkt_with_TKIP_MIC(
	void 				*pReserved,
	struct sk_buff *			pOldPkt);

struct sk_buff * duplicate_pkt_with_VLAN(
	struct net_device *			pNetDev,
	USHORT					VLAN_VID,
	USHORT					VLAN_Priority,
	u8 *				pHeader802_3,
    UINT            		HdrLen,
	u8 *				pData,
	ULONG					DataSize,
	u8 				FromWhichBSSID,
	u8 				*TPID);

typedef void (*RTMP_CB_8023_PACKET_ANNOUNCE)(
			void 		*pCtrlBkPtr,
			struct sk_buff *	pPacket,
			u8 		OpMode);

bool RTMPL2FrameTxAction(
	void 				*pCtrlBkPtr,
	struct net_device *			pNetDev,
	RTMP_CB_8023_PACKET_ANNOUNCE _announce_802_3_packet,
	u8 				apidx,
	u8 *				pData,
	u32					data_len,
	u8 		OpMode);

struct sk_buff * ExpandPacket(
	void 				*pReserved,
	struct sk_buff *			pPacket,
	u32					ext_head_len,
	u32					ext_tail_len);

struct sk_buff * ClonePacket(
	void 				*pReserved,
	struct sk_buff *			pPacket,
	u8 *				pData,
	ULONG					DataSize);

void wlan_802_11_to_802_3_packet(
	struct net_device *			pNetDev,
	u8 				OpMode,
	USHORT					VLAN_VID,
	USHORT					VLAN_Priority,
	struct sk_buff *			pRxPacket,
	u8 				*pData,
	ULONG					DataSize,
	u8 *				pHeader802_3,
	u8 				FromWhichBSSID,
	u8 				*TPID);

void send_monitor_packets(
	struct net_device *			pNetDev,
	struct sk_buff *			pRxPacket,
	PHEADER_802_11			pHeader,
	u8 				*pData,
	USHORT					DataSize,
	u8 				L2PAD,
	u8 				PHYMODE,
	u8 				BW,
	u8 				ShortGI,
	u8 				MCS,
	u8 				AMPDU,
	u8 				STBC,
	u8 				RSSI1,
	u8 				BssMonitorFlag11n,
	u8 				*pDevName,
	u8 				Channel,
	u8 				CentralChannel,
	u32					MaxRssi);

u8 VLAN_8023_Header_Copy(
	USHORT					VLAN_VID,
	USHORT					VLAN_Priority,
	u8 *				pHeader802_3,
	UINT            		HdrLen,
	u8 *				pData,
	u8 				FromWhichBSSID,
	u8 				*TPID);

void RtmpOsPktBodyCopy(
	struct net_device *			pNetDev,
	struct sk_buff *			pNetPkt,
	ULONG					ThisFrameLen,
	u8 *				pData);

INT RtmpOsIsPktCloned(
	struct sk_buff *			pNetPkt);

struct sk_buff * RtmpOsPktCopy(
	struct sk_buff *			pNetPkt);

struct sk_buff * RtmpOsPktClone(
	struct sk_buff *			pNetPkt);

void RtmpOsPktDataPtrAssign(
	struct sk_buff *			pNetPkt,
	u8 				*pData);

void RtmpOsPktLenAssign(
	struct sk_buff *			pNetPkt,
	LONG					Len);

void RtmpOsPktTailAdjust(
	struct sk_buff *			pNetPkt,
	UINT					removedTagLen);

u8 *RtmpOsPktTailBufExtend(
	struct sk_buff *			pNetPkt,
	UINT					Len);

u8 *RtmpOsPktHeadBufExtend(
	struct sk_buff *			pNetPkt,
	UINT					Len);

void RtmpOsPktReserve(
	struct sk_buff *			pNetPkt,
	UINT					Len);

void RtmpOsPktProtocolAssign(
	struct sk_buff *			pNetPkt);

void RtmpOsPktInfPpaSend(
	struct sk_buff *			pNetPkt);

void RtmpOsPktRcvHandle(
	struct sk_buff *			pNetPkt);

void RtmpOsPktInit(
	struct sk_buff *			pNetPkt,
	struct net_device *			pNetDev,
	u8 				*pData,
	USHORT					DataSize);

struct sk_buff * RtmpOsPktIappMakeUp(
	struct net_device *			pNetDev,
	u8					*pMac);

bool RtmpOsPktOffsetInit(void);

/*
========================================================================
Routine Description:
	Initialize the OS atomic_t.
*/

uint16_t RtmpOsNtohs(
	uint16_t					Value);

uint16_t RtmpOsHtons(
	uint16_t					Value);

u32 RtmpOsNtohl(
	u32					Value);

u32 RtmpOsHtonl(
	u32					Value);

/* OS File */
RTMP_OS_FD RtmpOSFileOpen(char *pPath,  int flag, int mode);
int RtmpOSFileClose(RTMP_OS_FD osfd);
void RtmpOSFileSeek(RTMP_OS_FD osfd, int offset);
int RtmpOSFileRead(RTMP_OS_FD osfd, char *pDataPtr, int readLen);
int RtmpOSFileWrite(RTMP_OS_FD osfd, char *pDataPtr, int writeLen);

INT32 RtmpOsFileIsErr(
	void 				*pFile);

void RtmpOSFSInfoChange(
	RTMP_OS_FS_INFO			*pOSFSInfoOrg,
	bool 				bSet);

/* OS Network Interface */
int RtmpOSNetDevAddrSet(
	u8 				OpMode,
	struct net_device *				pNetDev,
	u8 *				pMacAddr,
	u8 *				dev_name);

void RtmpOSNetDevClose(
	struct net_device *				pNetDev);

void RtmpOSNetDevFree(
	struct net_device *			pNetDev);

INT RtmpOSNetDevAlloc(
	struct net_device *			*new_dev_p,
	u32					privDataSize);

INT RtmpOSNetDevOpsAlloc(
	void *				*pNetDevOps);


struct net_device *RtmpOSNetDevGetByName(
	struct net_device *			pNetDev,
	char *				pDevName);

void RtmpOSNetDeviceRefPut(
	struct net_device *			pNetDev);

INT RtmpOSNetDevDestory(
	void 				*pReserved,
	struct net_device *			pNetDev);

void RtmpOSNetDevDetach(
	struct net_device *			pNetDev);

int RtmpOSNetDevAttach(
	u8 				OpMode,
	struct net_device *			pNetDev,
	RTMP_OS_NETDEV_OP_HOOK	*pDevOpHook);

void RtmpOSNetDevProtect(
	bool lock_it);

struct net_device *RtmpOSNetDevCreate(
	INT32					MC_RowID,
	u32					*pIoctlIF,
	INT 					devType,
	INT						devNum,
	INT						privMemSize,
	char *				pNamePrefix);

bool RtmpOSNetDevIsUp(
	void 				*pDev);

unsigned char *RtmpOsNetDevGetPhyAddr(
	void 				*pDev);

void RtmpOsNetQueueStart(
	struct net_device *			pDev);

void RtmpOsNetQueueStop(
	struct net_device *			pDev);

void RtmpOsNetQueueWake(
	struct net_device *			pDev);

void RtmpOsSetPktNetDev(
	void 				*pPkt,
	void 				*pDev);

char *RtmpOsGetNetDevName(struct net_device *pDev);

void RtmpOsSetNetDevPriv(struct net_device *pDev, struct rtmp_adapter *pPriv);
struct rtmp_adapter *RtmpOsGetNetDevPriv(struct net_device *pDev);
u32 RtmpDevPrivFlagsGet(struct net_device *pDev);
void RtmpDevPrivFlagsSet(struct net_device *pDev, u32 PrivFlags);

void RtmpOsSetNetDevType(void *pDev, USHORT Type);

void RtmpOsSetNetDevTypeMonitor(void *pDev);


/* OS Semaphore */
void RtmpOsCmdUp(RTMP_OS_TASK *pCmdQTask);
bool RtmpOsSemaInitLocked(struct semaphore *pSemOrg, LIST_HEADER *pSemList);
bool RtmpOsSemaInit(struct semaphore *pSemOrg, LIST_HEADER *pSemList);
bool RtmpOsSemaDestroy(struct semaphore *pSemOrg);
INT RtmpOsSemaWaitInterruptible(struct semaphore *pSemOrg);
void RtmpOsSemaWakeUp(struct semaphore *pSemOrg);
void RtmpOsMlmeUp(RTMP_OS_TASK *pMlmeQTask);

void RtmpOsInitCompletion(RTMP_OS_COMPLETION *pCompletion);
void RtmpOsExitCompletion(RTMP_OS_COMPLETION *pCompletion);
void RtmpOsComplete(RTMP_OS_COMPLETION *pCompletion);
ULONG RtmpOsWaitForCompletionTimeout(RTMP_OS_COMPLETION *pCompletion, ULONG Timeout);

/* OS Task */
bool RtmpOsTaskletSche(RTMP_NET_TASK_STRUCT *pTasklet);

bool RtmpOsTaskletInit(
	RTMP_NET_TASK_STRUCT *pTasklet,
	void (*pFunc)(unsigned long data),
	ULONG Data,
	LIST_HEADER *pTaskletList);

bool RtmpOsTaskletKill(RTMP_NET_TASK_STRUCT *pTasklet);

void RtmpOsTaskletDataAssign(
	RTMP_NET_TASK_STRUCT *pTasklet,
	ULONG Data);

void RtmpOsTaskWakeUp(RTMP_OS_TASK *pTaskOrg);

INT32 RtmpOsTaskIsKilled(RTMP_OS_TASK *pTaskOrg);

bool RtmpOsCheckTaskLegality(RTMP_OS_TASK *pTaskOrg);

bool RtmpOSTaskAlloc(
	RTMP_OS_TASK			*pTask,
	LIST_HEADER				*pTaskList);

void RtmpOSTaskFree(
	RTMP_OS_TASK			*pTask);

int RtmpOSTaskKill(
	RTMP_OS_TASK			*pTaskOrg);

INT RtmpOSTaskNotifyToExit(
	RTMP_OS_TASK			*pTaskOrg);

void RtmpOSTaskCustomize(
	RTMP_OS_TASK			*pTaskOrg);

int RtmpOSTaskAttach(
	RTMP_OS_TASK			*pTaskOrg,
	RTMP_OS_TASK_CALLBACK	fn,
	ULONG					arg);

int RtmpOSTaskInit(
	RTMP_OS_TASK			*pTaskOrg,
	char *				pTaskName,
	void 				*pPriv,
	LIST_HEADER				*pTaskList,
	LIST_HEADER				*pSemList);

bool RtmpOSTaskWait(
	void 				*pReserved,
	RTMP_OS_TASK			*pTaskOrg,
	INT32					*pStatus);

void *RtmpOsTaskDataGet(RTMP_OS_TASK *pTaskOrg);

INT32 RtmpThreadPidKill(RTMP_OS_PID	 PID);

/* OS Cache */
void RtmpOsDCacheFlush(ULONG AddrStart, ULONG Size);

/* OS Timer */
void RTMP_SetPeriodicTimer(
	NDIS_MINIPORT_TIMER *pTimerOrg,
	unsigned long timeout);

void RTMP_OS_Init_Timer(
	void 					*pReserved,
	NDIS_MINIPORT_TIMER		*pTimerOrg,
	TIMER_FUNCTION			function,
	void *				data,
	LIST_HEADER				*pTimerList);

void RTMP_OS_Add_Timer(
	NDIS_MINIPORT_TIMER *pTimerOrg,
	unsigned long timeout);

void RTMP_OS_Mod_Timer(
	NDIS_MINIPORT_TIMER *pTimerOrg,
	unsigned long timeout);

void RTMP_OS_Del_Timer(
	NDIS_MINIPORT_TIMER		*pTimerOrg,
	bool 				*pCancelled);

void RTMP_OS_Release_Timer(
	NDIS_MINIPORT_TIMER		*pTimerOrg);

bool RTMP_OS_Alloc_Rsc(
	LIST_HEADER				*pRscList,
	void 					*pRsc,
	u32					RscLen);

void RTMP_OS_Free_Rscs(
	LIST_HEADER				*pRscList);

/* OS Lock */
bool RtmpOsAllocateLock(
	spinlock_t			*pLock,
	LIST_HEADER				*pLockList);

void RtmpOsFreeSpinLock(
	spinlock_t			*pLockOrg);

void RtmpOsSpinLockBh(
	spinlock_t			*pLockOrg);

void RtmpOsSpinUnLockBh(spinlock_t *pLockOrg);
void RtmpOsIntLock(spinlock_t *pLockOrg, ULONG *pIrqFlags);
void RtmpOsIntUnLock(spinlock_t *pLockOrg, ULONG IrqFlags);

/* OS PID */
void RtmpOsGetPid(ULONG *pDst, ULONG PID);
void RtmpOsTaskPidInit(RTMP_OS_PID *pPid);

/* OS I/O */
void RTMP_PCI_Writel(ULONG Value, void *pAddr);
void RTMP_PCI_Writew(ULONG Value, void *pAddr);
void RTMP_PCI_Writeb(ULONG Value, void *pAddr);
ULONG RTMP_PCI_Readl(void *pAddr);
ULONG RTMP_PCI_Readw(void *pAddr);
ULONG RTMP_PCI_Readb(void *pAddr);

int RtmpOsPciConfigReadWord(
	void 				*pDev,
	u32					Offset,
	uint16_t					*pValue);

int RtmpOsPciConfigWriteWord(
	void 				*pDev,
	u32					Offset,
	uint16_t					Value);

int RtmpOsPciConfigReadDWord(
	void 				*pDev,
	u32					Offset,
	u32					*pValue);

int RtmpOsPciConfigWriteDWord(
	void 				*pDev,
	u32					Offset,
	u32					Value);

int RtmpOsPciFindCapability(
	void 				*pDev,
	int						Cap);

void *RTMPFindHostPCIDev(void *pPciDevSrc);

int RtmpOsPciMsiEnable(void *pDev);
void RtmpOsPciMsiDisable(void *pDev);

/* OS Wireless */
ULONG RtmpOsMaxScanDataGet(void);

/* OS Interrutp */
INT32 RtmpOsIsInInterrupt(void);

/* OS USB */
void *RtmpOsUsbUrbDataGet(void *pUrb);
int RtmpOsUsbUrbStatusGet(void *pUrb);
ULONG RtmpOsUsbUrbLenGet(void *pUrb);

/* OS Atomic */
bool RtmpOsAtomicInit(RTMP_OS_ATOMIC *pAtomic, LIST_HEADER *pAtomicList);
void RtmpOsAtomicDestroy(RTMP_OS_ATOMIC *pAtomic);
LONG RtmpOsAtomicRead(RTMP_OS_ATOMIC *pAtomic);
void RtmpOsAtomicDec(RTMP_OS_ATOMIC *pAtomic);
void RtmpOsAtomicInterlockedExchange(RTMP_OS_ATOMIC *pAtomicSrc, LONG Value);

int RtmpOSWrielessEventSend(
	struct net_device *			pNetDev,
	u32					eventType,
	INT						flags,
	u8 *				pSrcMac,
	u8 *				pData,
	u32					dataLen);

int RtmpOSWrielessEventSendExt(
	struct net_device *			pNetDev,
	u32					eventType,
	INT						flags,
	u8 *				pSrcMac,
	u8 *				pData,
	u32					dataLen,
	u32					family);

UINT RtmpOsWirelessExtVerGet(void);

void RtmpDrvAllMacPrint(
	void 					*pReserved,
	u32					*pBufMac,
	u32					AddrStart,
	u32					AddrEnd,
	u32					AddrStep);

void RtmpDrvAllE2PPrint(
	void 				*pReserved,
	USHORT					*pMacContent,
	u32					AddrEnd,
	u32					AddrStep);

int RtmpOSIRQRelease(
	struct net_device *			pNetDev,
	u32					infType,
	PPCI_DEV				pci_dev,
	bool 				*pHaveMsi);

void RtmpOsWlanEventSet(
	void 				*pReserved,
	bool 				*pCfgWEnt,
	bool 				FlgIsWEntSup);

uint16_t RtmpOsGetUnaligned(uint16_t *pWord);

u32 RtmpOsGetUnaligned32(u32 *pWord);

ULONG RtmpOsGetUnalignedlong(ULONG *pWord);

long RtmpOsSimpleStrtol(
	const char				*cp,
	char 					**endp,
	unsigned int			base);

void RtmpOsOpsInit(RTMP_OS_ABL_OPS *pOps);

/* ============================ rt_os_util.c ================================ */
void RtmpDrvMaxRateGet(
	void *pReserved,
	u8 MODE,
	u8 ShortGI,
	u8 BW,
	u8 MCS,
	u32 *pRate);

char * rtstrchr(const char * s, int c);

char *  WscGetAuthTypeStr(USHORT authFlag);

char *  WscGetEncryTypeStr(USHORT encryFlag);

USHORT WscGetAuthTypeFromStr(char *arg);

USHORT WscGetEncrypTypeFromStr(char *arg);

void RtmpMeshDown(
	void *pDrvCtrlBK,
	bool WaitFlag,
	bool (*RtmpMeshLinkCheck)(void *pAd));

USHORT RtmpOsNetPrivGet(struct net_device *pDev);

bool RtmpOsCmdDisplayLenCheck(
	u32					LenSrc,
	u32					Offset);

void    WpaSendMicFailureToWpaSupplicant(
	struct net_device *			pNetDev,
    bool 				bUnicast);

int wext_notify_event_assoc(
	struct net_device *			pNetDev,
	u8 				*ReqVarIEs,
	u32					ReqVarIELen);

void    SendAssocIEsToWpaSupplicant(
	struct net_device *			pNetDev,
	u8 				*ReqVarIEs,
	u32					ReqVarIELen);

/* ============================ rt_rbus_pci_util.c ========================== */
void RtmpAllocDescBuf(
	PPCI_DEV pPciDev,
	UINT Index,
	ULONG Length,
	bool Cached,
	void **VirtualAddress,
	PNDIS_PHYSICAL_ADDRESS	PhysicalAddress);

void RtmpFreeDescBuf(
	PPCI_DEV pPciDev,
	ULONG Length,
	void *VirtualAddress,
	NDIS_PHYSICAL_ADDRESS	PhysicalAddress);

void RTMP_AllocateFirstTxBuffer(
	PPCI_DEV pPciDev,
	UINT Index,
	ULONG Length,
	bool Cached,
	void **VirtualAddress,
	PNDIS_PHYSICAL_ADDRESS	PhysicalAddress);

void RTMP_FreeFirstTxBuffer(
	PPCI_DEV				pPciDev,
	ULONG					Length,
	bool 				Cached,
	void *				VirtualAddress,
	NDIS_PHYSICAL_ADDRESS	PhysicalAddress);

struct sk_buff * RTMP_AllocateRxPacketBuffer(
	void 				*pReserved,
	void 				*pPciDev,
	ULONG					Length,
	bool 				Cached,
	void *				*VirtualAddress,
	PNDIS_PHYSICAL_ADDRESS	PhysicalAddress);

dma_addr_t linux_pci_map_single(void *pPciDev, void *ptr, size_t size, int sd_idx, int direction);

void linux_pci_unmap_single(void *pPciDev, dma_addr_t dma_addr, size_t size, int direction);

/* ============================ rt_usb_util.c =============================== */
#ifdef RTMP_MAC_USB
typedef void (*USB_COMPLETE_HANDLER)(void *);

void dump_urb(void *purb);

int rausb_register(void * new_driver);

void rausb_deregister(void * driver);

/*struct urb *rausb_alloc_urb(int iso_packets); */

void rausb_free_urb(void *urb);

void rausb_put_dev(void *dev);

struct usb_device *rausb_get_dev(void *dev);

int rausb_submit_urb(void *urb);

void *rausb_buffer_alloc(void *dev,
							size_t size,
							dma_addr_t *dma);

void rausb_buffer_free(void *dev,
							size_t size,
							void *addr,
							dma_addr_t dma);

int rausb_control_msg(void *dev,
						unsigned int pipe,
						__u8 request,
						__u8 requesttype,
						__u16 value,
						__u16 index,
						void *data,
						__u16 size,
						int timeout);

void rausb_fill_bulk_urb(void *urb,
						 void *dev,
						 unsigned int pipe,
						 void *transfer_buffer,
						 int buffer_length,
						 USB_COMPLETE_HANDLER complete_fn,
						 void *context);

unsigned int rausb_sndctrlpipe(void *dev, ULONG address);

unsigned int rausb_rcvctrlpipe(void *dev, ULONG address);


unsigned int rausb_sndbulkpipe(void *dev, ULONG address);
unsigned int rausb_rcvbulkpipe(void *dev, ULONG address);

void rausb_kill_urb(void *urb);

void RtmpOsUsbEmptyUrbCheck(
	void 			**ppWait,
	spinlock_t		*pBulkInLock,
	u8 			*pPendingRx);


void RtmpOsUsbInitHTTxDesc(
	struct urb *pUrb,
	struct usb_device *pUsb_Dev,
	UINT BulkOutEpAddr,
	u8 *pSrc,
	ULONG BulkOutSize,
	USB_COMPLETE_HANDLER Func,
	void *pTxContext,
	dma_addr_t TransferDma);

void RtmpOsUsbInitRxDesc(
	struct urb *pUrb,
	struct usb_device *pUsb_Dev,
	UINT BulkInEpAddr,
	u8 *pTransferBuffer,
	u32 BufSize,
	USB_COMPLETE_HANDLER Func,
	void *pRxContext,
	dma_addr_t TransferDma);

#endif /* RTMP_MAC_USB */

u32 RtmpOsGetUsbDevVendorID(
	void *pUsbDev);

u32 RtmpOsGetUsbDevProductID(
	void *pUsbDev);

/* CFG80211 */
#ifdef RT_CFG80211_SUPPORT
typedef struct __CFG80211_BAND {

	u8 RFICType;
	u8 MpduDensity;
	u8 TxStream;
	u8 RxStream;
	u32 MaxTxPwr;
	u32 MaxBssTable;

	uint16_t RtsThreshold;
	uint16_t FragmentThreshold;
	u32 RetryMaxCnt; /* bit0~7: short; bit8 ~ 15: long */
	bool FlgIsBMode;
} CFG80211_BAND;

void CFG80211OS_UnRegister(
	void 					*pCB,
	void 					*pNetDev);

bool CFG80211_SupBandInit(
	void 					*pCB,
	CFG80211_BAND 			*pBandInfo,
	void 					*pWiphyOrg,
	void 					*pChannelsOrg,
	void 					*pRatesOrg);

bool CFG80211OS_SupBandReInit(
	void 					*pCB,
	CFG80211_BAND 			*pBandInfo);

void CFG80211OS_RegHint(
	void 					*pCB,
	u8 				*pCountryIe,
	ULONG					CountryIeLen);

void CFG80211OS_RegHint11D(
	void 					*pCB,
	u8 				*pCountryIe,
	ULONG					CountryIeLen);

bool CFG80211OS_BandInfoGet(
	void 					*pCB,
	void 					*pWiphyOrg,
	void 				**ppBand24,
	void 				**ppBand5);

u32 CFG80211OS_ChanNumGet(
	void 					*pCB,
	void 					*pWiphyOrg,
	u32					IdBand);

bool CFG80211OS_ChanInfoGet(
	void 					*pCB,
	void 					*pWiphyOrg,
	u32					IdBand,
	u32					IdChan,
	u32					*pChanId,
	u32					*pPower,
	bool 				*pFlgIsRadar);

bool CFG80211OS_ChanInfoInit(
	void 					*pCB,
	u32					InfoIndex,
	u8 				ChanId,
	u8 				MaxTxPwr,
	bool 				FlgIsNMode,
	bool 				FlgIsBW20M);

void CFG80211OS_Scaning(
	void 					*pCB,
	u32					ChanId,
	u8 				*pFrame,
	u32					FrameLen,
	INT32					RSSI,
	bool 				FlgIsNMode,
	u8					BW);

void CFG80211OS_ScanEnd(
	void 					*pCB,
	bool 				FlgIsAborted);

void CFG80211OS_ConnectResultInform(
	void 					*pCB,
	u8 				*pBSSID,
	u8 				*pReqIe,
	u32					ReqIeLen,
	u8 				*pRspIe,
	u32					RspIeLen,
	u8 				FlgIsSuccess);
#endif /* RT_CFG80211_SUPPORT */




/* ================================ MACRO =================================== */
#define RTMP_UTIL_DCACHE_FLUSH(__AddrStart, __Size)

/* ================================ EXTERN ================================== */
extern u8 SNAP_802_1H[6];
extern u8 SNAP_BRIDGE_TUNNEL[6];
extern u8 EAPOL[2];
extern u8 TPID[];
extern u8 IPX[2];
extern u8 APPLE_TALK[2];
extern u8 NUM_BIT8[8];
extern ULONG RTPktOffsetData, RTPktOffsetLen, RTPktOffsetCB;

extern ULONG OS_NumOfMemAlloc, OS_NumOfMemFree;

extern INT32 ralinkrate[];
extern u32 RT_RateSize;

#ifdef PLATFORM_UBM_IPX8
#include "vrut_ubm.h"
#endif /* PLATFORM_UBM_IPX8 */

int OS_TEST_BIT(int bit, unsigned long *flags);
void OS_SET_BIT(int bit, unsigned long *flags);
void OS_CLEAR_BIT(int bit, unsigned long *flags);

#endif /* __RT_OS_UTIL_H__ */
