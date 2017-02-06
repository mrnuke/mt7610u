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
#include <stdarg.h>


u8 CISCO_OUI[] = {0x00, 0x40, 0x96};
u8 RALINK_OUI[]  = {0x00, 0x0c, 0x43};
u8 WPA_OUI[] = {0x00, 0x50, 0xf2, 0x01};
u8 RSN_OUI[] = {0x00, 0x0f, 0xac};
u8 WAPI_OUI[] = {0x00, 0x14, 0x72};
u8 WME_INFO_ELEM[]  = {0x00, 0x50, 0xf2, 0x02, 0x00, 0x01};
u8 WME_PARM_ELEM[] = {0x00, 0x50, 0xf2, 0x02, 0x01, 0x01};
u8 BROADCOM_OUI[]  = {0x00, 0x90, 0x4c};
u8 WPS_OUI[] = {0x00, 0x50, 0xf2, 0x04};
#ifdef CONFIG_STA_SUPPORT
#ifdef DOT11_N_SUPPORT
u8 PRE_N_HT_OUI[]	= {0x00, 0x90, 0x4c};
#endif /* DOT11_N_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */

u8 OfdmRateToRxwiMCS[12] = {
	0,  0,	0,  0,
	0,  1,	2,  3,	/* OFDM rate 6,9,12,18 = rxwi mcs 0,1,2,3 */
	4,  5,	6,  7,	/* OFDM rate 24,36,48,54 = rxwi mcs 4,5,6,7 */
};

u8 RxwiMCSToOfdmRate[12] = {
	RATE_6,  RATE_9,	RATE_12,  RATE_18,
	RATE_24,  RATE_36,	RATE_48,  RATE_54,	/* OFDM rate 6,9,12,18 = rxwi mcs 0,1,2,3 */
	4,  5,	6,  7,	/* OFDM rate 24,36,48,54 = rxwi mcs 4,5,6,7 */
};

extern u8  OfdmRateToRxwiMCS[];
/* since RT61 has better RX sensibility, we have to limit TX ACK rate not to exceed our normal data TX rate.*/
/* otherwise the WLAN peer may not be able to receive the ACK thus downgrade its data TX rate*/
unsigned long BasicRateMask[12]				= {0xfffff001 /* 1-Mbps */, 0xfffff003 /* 2 Mbps */, 0xfffff007 /* 5.5 */, 0xfffff00f /* 11 */,
									  0xfffff01f /* 6 */	 , 0xfffff03f /* 9 */	  , 0xfffff07f /* 12 */ , 0xfffff0ff /* 18 */,
									  0xfffff1ff /* 24 */	 , 0xfffff3ff /* 36 */	  , 0xfffff7ff /* 48 */ , 0xffffffff /* 54 */};

u8 BROADCAST_ADDR[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
u8 ZERO_MAC_ADDR[ETH_ALEN]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* e.g. RssiSafeLevelForTxRate[RATE_36]" means if the current RSSI is greater than*/
/*		this value, then it's quaranteed capable of operating in 36 mbps TX rate in*/
/*		clean environment.*/
/*								  TxRate: 1   2   5.5	11	 6	  9    12	18	 24   36   48	54	 72  100*/
char RssiSafeLevelForTxRate[] ={  -92, -91, -90, -87, -88, -86, -85, -83, -81, -78, -72, -71, -40, -40 };

u8  RateIdToMbps[]	 = { 1, 2, 5, 11, 6, 9, 12, 18, 24, 36, 48, 54, 72, 100};
unsigned short RateIdTo500Kbps[] = { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108, 144, 200};

u8 SsidIe = IE_SSID;
u8 SupRateIe = IE_SUPP_RATES;
u8 ExtRateIe = IE_EXT_SUPP_RATES;
#ifdef DOT11_N_SUPPORT
u8 HtCapIe = IE_HT_CAP;
u8 AddHtInfoIe = IE_ADD_HT;
u8 NewExtChanIe = IE_SECONDARY_CH_OFFSET;
u8 BssCoexistIe = IE_2040_BSS_COEXIST;
u8 ExtHtCapIe = IE_EXT_CAPABILITY;
#endif /* DOT11_N_SUPPORT */
u8 ExtCapIe = IE_EXT_CAPABILITY;
u8 ErpIe = IE_ERP;
u8 DsIe = IE_DS_PARM;
u8 TimIe = IE_TIM;
u8 WpaIe = IE_WPA;
u8 Wpa2Ie = IE_WPA2;
u8 IbssIe = IE_IBSS_PARM;
u8 WapiIe = IE_WAPI;

extern u8 WPA_OUI[];

u8 SES_OUI[] = {0x00, 0x90, 0x4c};

u8 ZeroSsid[32] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};


u8 dot11_max_sup_rate(int SupRateLen, u8 *SupRate, int ExtRateLen, u8 *ExtRate)
{
	int idx;
	u8 MaxSupportedRateIn500Kbps = 0;

	/* supported rates array may not be sorted. sort it and find the maximum rate */
	for (idx = 0; idx < SupRateLen; idx++) {
		if (MaxSupportedRateIn500Kbps < (SupRate[idx] & 0x7f))
			MaxSupportedRateIn500Kbps = SupRate[idx] & 0x7f;
	}

	if (ExtRateLen > 0 && ExtRate != NULL)
	{
		for (idx = 0; idx < ExtRateLen; idx++) {
			if (MaxSupportedRateIn500Kbps < (ExtRate[idx] & 0x7f))
				MaxSupportedRateIn500Kbps = ExtRate[idx] & 0x7f;
		}
	}

	return MaxSupportedRateIn500Kbps;
}


u8 dot11_2_ra_rate(u8 MaxSupportedRateIn500Kbps)
{
	u8 MaxSupportedRate;

	switch (MaxSupportedRateIn500Kbps)
	{
		case 108: MaxSupportedRate = RATE_54;   break;
		case 96:  MaxSupportedRate = RATE_48;   break;
		case 72:  MaxSupportedRate = RATE_36;   break;
		case 48:  MaxSupportedRate = RATE_24;   break;
		case 36:  MaxSupportedRate = RATE_18;   break;
		case 24:  MaxSupportedRate = RATE_12;   break;
		case 18:  MaxSupportedRate = RATE_9;    break;
		case 12:  MaxSupportedRate = RATE_6;    break;
		case 22:  MaxSupportedRate = RATE_11;   break;
		case 11:  MaxSupportedRate = RATE_5_5;  break;
		case 4:   MaxSupportedRate = RATE_2;    break;
		case 2:   MaxSupportedRate = RATE_1;    break;
		default:  MaxSupportedRate = RATE_11;   break;
	}

	return MaxSupportedRate;
}


/*
	==========================================================================
	Description:
		initialize the MLME task and its data structure (queue, spinlock,
		timer, state machines).

	IRQL = PASSIVE_LEVEL

	Return:
		always return NDIS_STATUS_SUCCESS

	==========================================================================
*/
int MlmeInit(
	struct rtmp_adapter *pAd)
{
	int Status = NDIS_STATUS_SUCCESS;

	DBGPRINT(RT_DEBUG_TRACE, ("--> MLME Initialize\n"));

	do
	{
		Status = MlmeQueueInit(pAd, &pAd->Mlme.Queue);
		if(Status != NDIS_STATUS_SUCCESS)
			break;

		pAd->Mlme.bRunning = false;
		spin_lock_init(&pAd->Mlme.TaskLock);

#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
			BssTableInit(&pAd->ScanTab);

			/* init STA state machines*/
			AssocStateMachineInit(pAd, &pAd->Mlme.AssocMachine, pAd->Mlme.AssocFunc);
			AuthStateMachineInit(pAd, &pAd->Mlme.AuthMachine, pAd->Mlme.AuthFunc);
			AuthRspStateMachineInit(pAd, &pAd->Mlme.AuthRspMachine, pAd->Mlme.AuthRspFunc);
			SyncStateMachineInit(pAd, &pAd->Mlme.SyncMachine, pAd->Mlme.SyncFunc);

#ifdef QOS_DLS_SUPPORT
			DlsStateMachineInit(pAd, &pAd->Mlme.DlsMachine, pAd->Mlme.DlsFunc);
#endif /* QOS_DLS_SUPPORT */





			/* Since we are using switch/case to implement it, the init is different from the above */
			/* state machine init*/
			MlmeCntlInit(pAd, &pAd->Mlme.CntlMachine, NULL);

			RTMPInitTimer(pAd, &pAd->Mlme.LinkDownTimer, GET_TIMER_FUNCTION(LinkDownExec), pAd, false);
			RTMPInitTimer(pAd, &pAd->StaCfg.StaQuickResponeForRateUpTimer, GET_TIMER_FUNCTION(StaQuickResponeForRateUpExec), pAd, false);
			pAd->StaCfg.StaQuickResponeForRateUpTimerRunning = false;
			RTMPInitTimer(pAd, &pAd->StaCfg.WpaDisassocAndBlockAssocTimer, GET_TIMER_FUNCTION(WpaDisassocApAndBlockAssoc), pAd, false);

#ifdef RTMP_MAC_USB
			RTMPInitTimer(pAd, &pAd->Mlme.AutoWakeupTimer, GET_TIMER_FUNCTION(RtmpUsbStaAsicForceWakeupTimeout), pAd, false);
			pAd->Mlme.AutoWakeupTimerRunning = false;
#endif /* RTMP_MAC_USB */


		}
#endif /* CONFIG_STA_SUPPORT */



		WpaStateMachineInit(pAd, &pAd->Mlme.WpaMachine, pAd->Mlme.WpaFunc);


		ActionStateMachineInit(pAd, &pAd->Mlme.ActMachine, pAd->Mlme.ActFunc);

		/* Init mlme periodic timer*/
		RTMPInitTimer(pAd, &pAd->Mlme.PeriodicTimer, GET_TIMER_FUNCTION(MlmePeriodicExec), pAd, true);

		/* Set mlme periodic timer*/
		RTMPSetTimer(&pAd->Mlme.PeriodicTimer, MLME_TASK_EXEC_INTV);

		/* software-based RX Antenna diversity*/
		RTMPInitTimer(pAd, &pAd->Mlme.RxAntEvalTimer, GET_TIMER_FUNCTION(AsicRxAntEvalTimeout), pAd, false);



	} while (false);

	DBGPRINT(RT_DEBUG_TRACE, ("<-- MLME Initialize\n"));

	return Status;
}


/*
	==========================================================================
	Description:
		main loop of the MLME
	Pre:
		Mlme has to be initialized, and there are something inside the queue
	Note:
		This function is invoked from MPSetInformation and MPReceive;
		This task guarantee only one MlmeHandler will run.

	IRQL = DISPATCH_LEVEL

	==========================================================================
 */
void MlmeHandler(struct rtmp_adapter*pAd)
{
	MLME_QUEUE_ELEM *Elem = NULL;
#ifdef APCLI_SUPPORT
	short apcliIfIndex;
#endif /* APCLI_SUPPORT */

	/* Only accept MLME and Frame from peer side, no other (control/data) frame should*/
	/* get into this state machine*/

	NdisAcquireSpinLock(&pAd->Mlme.TaskLock);
	if(pAd->Mlme.bRunning)
	{
		NdisReleaseSpinLock(&pAd->Mlme.TaskLock);
		return;
	}
	else
	{
		pAd->Mlme.bRunning = true;
	}
	NdisReleaseSpinLock(&pAd->Mlme.TaskLock);

	while (!MlmeQueueEmpty(&pAd->Mlme.Queue))
	{
		if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_MLME_RESET_IN_PROGRESS) ||
			RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS) ||
			RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_NIC_NOT_EXIST) ||
			RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_SUSPEND))
		{
			DBGPRINT(RT_DEBUG_TRACE, ("Device Halted or Removed or MlmeRest, exit MlmeHandler! (queue num = %ld)\n", pAd->Mlme.Queue.Num));
			break;
		}

		/*From message type, determine which state machine I should drive*/
		if (MlmeDequeue(&pAd->Mlme.Queue, &Elem))
		{
#ifdef RTMP_MAC_USB
			if (Elem->MsgType == MT2_RESET_CONF)
			{
				DBGPRINT_RAW(RT_DEBUG_TRACE, ("!!! reset MLME state machine !!!\n"));
				MlmeRestartStateMachine(pAd);
				Elem->Occupied = false;
				Elem->MsgLen = 0;
				continue;
			}
#endif /* RTMP_MAC_USB */

			/* if dequeue success*/
			switch (Elem->Machine)
			{
				/* STA state machines*/
#ifdef CONFIG_STA_SUPPORT
				case ASSOC_STATE_MACHINE:
					StateMachinePerformAction(pAd, &pAd->Mlme.AssocMachine,
										Elem, pAd->Mlme.AssocMachine.CurrState);
					break;

				case AUTH_STATE_MACHINE:
					StateMachinePerformAction(pAd, &pAd->Mlme.AuthMachine,
										Elem, pAd->Mlme.AuthMachine.CurrState);
					break;

				case AUTH_RSP_STATE_MACHINE:
					StateMachinePerformAction(pAd, &pAd->Mlme.AuthRspMachine,
										Elem, pAd->Mlme.AuthRspMachine.CurrState);
					break;

				case SYNC_STATE_MACHINE:
					StateMachinePerformAction(pAd, &pAd->Mlme.SyncMachine,
										Elem, pAd->Mlme.SyncMachine.CurrState);
					break;

				case MLME_CNTL_STATE_MACHINE:
					MlmeCntlMachinePerformAction(pAd, &pAd->Mlme.CntlMachine, Elem);
					break;

				case WPA_PSK_STATE_MACHINE:
					StateMachinePerformAction(pAd, &pAd->Mlme.WpaPskMachine,
										Elem, pAd->Mlme.WpaPskMachine.CurrState);
					break;

#ifdef QOS_DLS_SUPPORT
				case DLS_STATE_MACHINE:
					StateMachinePerformAction(pAd, &pAd->Mlme.DlsMachine,
										Elem, pAd->Mlme.DlsMachine.CurrState);
					break;
#endif /* QOS_DLS_SUPPORT */




#endif /* CONFIG_STA_SUPPORT */

				case ACTION_STATE_MACHINE:
					StateMachinePerformAction(pAd, &pAd->Mlme.ActMachine,
										Elem, pAd->Mlme.ActMachine.CurrState);
					break;

				case WPA_STATE_MACHINE:
					StateMachinePerformAction(pAd, &pAd->Mlme.WpaMachine, Elem, pAd->Mlme.WpaMachine.CurrState);
					break;


				default:
					DBGPRINT(RT_DEBUG_TRACE, ("ERROR: Illegal machine %ld in MlmeHandler()\n", Elem->Machine));
					break;
			} /* end of switch*/

			/* free MLME element*/
			Elem->Occupied = false;
			Elem->MsgLen = 0;

		}
		else {
			DBGPRINT_ERR(("MlmeHandler: MlmeQueue empty\n"));
		}
	}

	NdisAcquireSpinLock(&pAd->Mlme.TaskLock);
	pAd->Mlme.bRunning = false;
	NdisReleaseSpinLock(&pAd->Mlme.TaskLock);
}

/*
	==========================================================================
	Description:
		Destructor of MLME (Destroy queue, state machine, spin lock and timer)
	Parameters:
		Adapter - NIC Adapter pointer
	Post:
		The MLME task will no longer work properly

	IRQL = PASSIVE_LEVEL

	==========================================================================
 */
void MlmeHalt(
	struct rtmp_adapter *pAd)
{
	bool 	  Cancelled;

	DBGPRINT(RT_DEBUG_TRACE, ("==> MlmeHalt\n"));

	if (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_NIC_NOT_EXIST))
	{
		/* disable BEACON generation and other BEACON related hardware timers*/
		AsicDisableSync(pAd);
	}

	RTMPCancelTimer(&pAd->Mlme.PeriodicTimer, &Cancelled);

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
#ifdef QOS_DLS_SUPPORT
		u8 	i;
#endif /* QOS_DLS_SUPPORT */
		/* Cancel pending timers*/
		RTMPCancelTimer(&pAd->MlmeAux.AssocTimer, &Cancelled);
		RTMPCancelTimer(&pAd->MlmeAux.ReassocTimer, &Cancelled);
		RTMPCancelTimer(&pAd->MlmeAux.DisassocTimer, &Cancelled);
		RTMPCancelTimer(&pAd->MlmeAux.AuthTimer, &Cancelled);
		RTMPCancelTimer(&pAd->MlmeAux.BeaconTimer, &Cancelled);
		RTMPCancelTimer(&pAd->MlmeAux.ScanTimer, &Cancelled);



#ifdef QOS_DLS_SUPPORT
		for (i=0; i<MAX_NUM_OF_DLS_ENTRY; i++)
		{
			RTMPCancelTimer(&pAd->StaCfg.DLSEntry[i].Timer, &Cancelled);
		}
#endif /* QOS_DLS_SUPPORT */
		RTMPCancelTimer(&pAd->Mlme.LinkDownTimer, &Cancelled);

#ifdef RTMP_MAC_USB
		if (pAd->Mlme.AutoWakeupTimerRunning)
		{
			RTMPCancelTimer(&pAd->Mlme.AutoWakeupTimer, &Cancelled);
			pAd->Mlme.AutoWakeupTimerRunning = false;
		}
#endif /* RTMP_MAC_USB */



		if (pAd->StaCfg.StaQuickResponeForRateUpTimerRunning)
		{
			RTMPCancelTimer(&pAd->StaCfg.StaQuickResponeForRateUpTimer, &Cancelled);
			pAd->StaCfg.StaQuickResponeForRateUpTimerRunning = false;
		}
		RTMPCancelTimer(&pAd->StaCfg.WpaDisassocAndBlockAssocTimer, &Cancelled);
	}
#endif /* CONFIG_STA_SUPPORT */

	RTMPCancelTimer(&pAd->Mlme.RxAntEvalTimer, &Cancelled);





	if (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_NIC_NOT_EXIST))
	{
		struct rtmp_chip_ops  *pChipOps = &pAd->chipOps;

#ifdef LED_CONTROL_SUPPORT
		/* Set LED*/
		RTMPSetLED(pAd, LED_HALT);
#ifdef RTMP_MAC_USB
		{
			LED_CFG_STRUC LedCfg;

			LedCfg.word =  mt7610u_read32(pAd, LED_CFG);
			LedCfg.field.LedPolar = 0;
			LedCfg.field.RLedMode = 0;
			LedCfg.field.GLedMode = 0;
			LedCfg.field.YLedMode = 0;
			mt7610u_write32(pAd, LED_CFG, LedCfg.word);
		}
#endif /* RTMP_MAC_USB */
#endif /* LED_CONTROL_SUPPORT */

	}

	RTMPusecDelay(5000);    /*  5 msec to gurantee Ant Diversity timer canceled*/

	MlmeQueueDestroy(&pAd->Mlme.Queue);

	DBGPRINT(RT_DEBUG_TRACE, ("<== MlmeHalt\n"));
}

void MlmeResetRalinkCounters(
	struct rtmp_adapter *  pAd)
{
	pAd->RalinkCounters.LastOneSecRxOkDataCnt = pAd->RalinkCounters.OneSecRxOkDataCnt;

	/* for performace enchanement */
	memset(&pAd->RalinkCounters, 0,
			(unsigned long)&pAd->RalinkCounters.OneSecEnd -
			(unsigned long)&pAd->RalinkCounters.OneSecStart);

	return;
}


/*
	==========================================================================
	Description:
		This routine is executed periodically to -
		1. Decide if it's a right time to turn on PwrMgmt bit of all
		   outgoiing frames
		2. Calculate ChannelQuality based on statistics of the last
		   period, so that TX rate won't toggling very frequently between a
		   successful TX and a failed TX.
		3. If the calculated ChannelQuality indicated current connection not
		   healthy, then a ROAMing attempt is tried here.

	IRQL = DISPATCH_LEVEL

	==========================================================================
 */
#define ADHOC_BEACON_LOST_TIME		(8*OS_HZ)  /* 8 sec*/
void MlmePeriodicExec(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3)
{
	unsigned long			TxTotalCnt;
	struct rtmp_adapter *pAd = (struct rtmp_adapter*)FunctionContext;

	/* No More 0x84 MCU CMD from v.30 FW*/

#ifdef CONFIG_STA_SUPPORT

	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		RTMP_MLME_PRE_SANITY_CHECK(pAd);
	}

#ifdef RTMP_MAC_USB
	/* Only when count down to zero, can we go to sleep mode.*/
	/* Count down counter is set after link up. So within 10 seconds after link up, we never go to sleep.*/
	/* 10 seconds period, we can get IP, finish 802.1x authenticaion. and some critical , timing protocol.*/
	if (pAd->CountDowntoPsm > 0)
	{
		pAd->CountDowntoPsm--;
	}
#endif /* RTMP_MAC_USB */

#endif /* CONFIG_STA_SUPPORT */

	/* Do nothing if the driver is starting halt state.*/
	/* This might happen when timer already been fired before cancel timer with mlmehalt*/
	if ((RTMP_TEST_FLAG(pAd, (fRTMP_ADAPTER_HALT_IN_PROGRESS |
								fRTMP_ADAPTER_RADIO_OFF |
								fRTMP_ADAPTER_RADIO_MEASUREMENT |
								fRTMP_ADAPTER_RESET_IN_PROGRESS |
								fRTMP_ADAPTER_NIC_NOT_EXIST))))
		return;

	if (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_START_UP))
	{
		//DBGPRINT(RT_DEBUG_TRACE, ("%s(): StartUp not finish yet!\n", __FUNCTION__));
		return;
	}

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		/* Do nothing if monitor mode is on*/
		if (MONITOR_ON(pAd))
			return;

		if ((pAd->Mlme.PeriodicRound & 0x1) &&
			(STA_TGN_WIFI_ON(pAd)) &&
			((pAd->MACVersion & 0xffff) == 0x0101))
		{
			u32 txop_cfg;

			/* This is the fix for wifi 11n extension channel overlapping test case.  for 2860D*/
			if (pAd->CommonCfg.IOTestParm.bToggle == false)
			{
				txop_cfg = 0x24BF;
				pAd->CommonCfg.IOTestParm.bToggle = true;
			}
			else
			{
				txop_cfg = 0x243f;
				pAd->CommonCfg.IOTestParm.bToggle = false;
			}
			mt7610u_write32(pAd, TXOP_CTRL_CFG, txop_cfg);
		}
	}
#endif /* CONFIG_STA_SUPPORT */

	pAd->bUpdateBcnCntDone = false;

/*	RECBATimerTimeout(SystemSpecific1,FunctionContext,SystemSpecific2,SystemSpecific3);*/
	pAd->Mlme.PeriodicRound ++;
	pAd->Mlme.GPIORound++;

#ifdef RTMP_MAC_USB
	/* execute every 100ms, update the Tx FIFO Cnt for update Tx Rate.*/
	NICUpdateFifoStaCounters(pAd);
#endif /* RTMP_MAC_USB */

	/* by default, execute every 500ms */
	if ((pAd->ra_interval) &&
		((pAd->Mlme.PeriodicRound % (pAd->ra_interval / 100)) == 0) &&
		RTMPAutoRateSwitchCheck(pAd)/*(OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_TX_RATE_SWITCH_ENABLED))*/
	)
	{
#ifdef CONFIG_STA_SUPPORT
		/* perform dynamic tx rate switching based on past TX history*/
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
			if ((OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED)
					)
				&& (!OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_DOZE)))
				MlmeDynamicTxRateSwitching(pAd);
		}
#endif /* CONFIG_STA_SUPPORT */
	}

#ifdef DFS_SUPPORT
#endif /* DFS_SUPPORT */



	/* Normal 1 second Mlme PeriodicExec.*/
	if (pAd->Mlme.PeriodicRound %MLME_TASK_EXEC_MULTIPLE == 0)
	{
		pAd->Mlme.OneSecPeriodicRound ++;



		/*ORIBATimerTimeout(pAd);*/
		NdisGetSystemUpTime(&pAd->Mlme.Now32);

		/* add the most up-to-date h/w raw counters into software variable, so that*/
		/* the dynamic tuning mechanism below are based on most up-to-date information*/
		/* Hint: throughput impact is very serious in the function */
		NICUpdateRawCounters(pAd);

		RTMP_SECOND_CCA_DETECTION(pAd);

#ifdef RTMP_MAC_USB
#endif /* RTMP_MAC_USB */

#ifdef DOT11_N_SUPPORT
   		/* Need statistics after read counter. So put after NICUpdateRawCounters*/
		ORIBATimerTimeout(pAd);
#endif /* DOT11_N_SUPPORT */

	/*
		if (pAd->RalinkCounters.MgmtRingFullCount >= 2)
			RTMP_SET_FLAG(pAd, fRTMP_HW_ERR);
		else
			pAd->RalinkCounters.MgmtRingFullCount = 0;
	*/

		/* The time period for checking antenna is according to traffic*/
		{
			if (pAd->Mlme.bEnableAutoAntennaCheck)
			{
				TxTotalCnt = pAd->RalinkCounters.OneSecTxNoRetryOkCount +
								 pAd->RalinkCounters.OneSecTxRetryOkCount +
								 pAd->RalinkCounters.OneSecTxFailCount;

				/* dynamic adjust antenna evaluation period according to the traffic*/
				if (TxTotalCnt > 50)
				{
					if (pAd->Mlme.OneSecPeriodicRound % 10 == 0)
						AsicEvaluateRxAnt(pAd);
				}
				else
				{
					if (pAd->Mlme.OneSecPeriodicRound % 3 == 0)
						AsicEvaluateRxAnt(pAd);
				}
			}
		}

#ifdef VIDEO_TURBINE_SUPPORT
	/*
		VideoTurbineUpdate(pAd);
		VideoTurbineDynamicTune(pAd);
	*/
#endif /* VIDEO_TURBINE_SUPPORT */

		if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_RADIO_OFF | fRTMP_ADAPTER_DISABLE_DEQUEUEPACKET) == false)
		{
			if ((pAd->Mlme.OneSecPeriodicRound % 5) == 0)
			{
#ifdef MT76x0
#ifdef CONFIG_STA_SUPPORT
				if (IS_MT76x0U(pAd))
					MT76x0_dynamic_vga_tuning(pAd);
#endif /* CONFIG_STA_SUPPORT */
#endif /* MT76x0 */
			}

			if ((pAd->Mlme.OneSecPeriodicRound % 10) == 0)
			{
#ifdef MT76x0
				if (IS_MT76x0(pAd) &&
					pAd->chipCap.bDoTemperatureSensor)
				{
					int32_t temperature_diff = 0;
					/*
						For temperature sensor
					*/

					MT76x0_TempSensor(pAd);

					temperature_diff = (pAd->chipCap.NowTemperature - pAd->chipCap.LastTemperatureforVCO);
					if ((temperature_diff > 20) ||
						(temperature_diff < (-20)))
					{
						DBGPRINT(RT_DEBUG_OFF, ("%s - Do VCORecalibration again!(LastTemperatureforVCO=%d, NowTemperature = %d)\n",
							__FUNCTION__, pAd->chipCap.LastTemperatureforVCO, pAd->chipCap.NowTemperature));
						pAd->chipCap.LastTemperatureforVCO = pAd->chipCap.NowTemperature;
						MT76x0_VCO_CalibrationMode3(pAd, pAd->hw_cfg.cent_ch);
					}

				}
				else
#endif /* MT76x0 */
				{
				}
			}
		}

#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
			STAMlmePeriodicExec(pAd);
		}
#endif /* CONFIG_STA_SUPPORT */

		RTMP_SECOND_CCA_DETECTION(pAd);

		MlmeResetRalinkCounters(pAd);

#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
#ifdef RTMP_MAC_USB
			if (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_IDLE_RADIO_OFF))
#endif /* RTMP_MAC_USB */
			{


			u32	MacReg = 0;

			MacReg = mt7610u_read32(pAd, 0x10F4);
			if (((MacReg & 0x20000000) && (MacReg & 0x80)) || ((MacReg & 0x20000000) && (MacReg & 0x20)))
			{
				mt7610u_write32(pAd, MAC_SYS_CTRL, 0x1);
				RTMPusecDelay(1);
				MacReg = 0;
				{
					MacReg = 0xc;
				}

				if (MacReg)
					mt7610u_write32(pAd, MAC_SYS_CTRL, MacReg);

				DBGPRINT(RT_DEBUG_WARN,("Warning, MAC specific condition occurs \n"));
			}
		}
		}
#endif /* CONFIG_STA_SUPPORT */

		RTMP_MLME_HANDLER(pAd);
	}




	pAd->bUpdateBcnCntDone = false;
}


/*
	==========================================================================
	Validate SSID for connection try and rescan purpose
	Valid SSID will have visible chars only.
	The valid length is from 0 to 32.
	IRQL = DISPATCH_LEVEL
	==========================================================================
 */
bool MlmeValidateSSID(
	u8 *pSsid,
	u8 SsidLen)
{
	int	index;

	if (SsidLen > MAX_LEN_OF_SSID)
		return (false);

	/* Check each character value*/
	for (index = 0; index < SsidLen; index++)
	{
		if (pSsid[index] < 0x20)
			return (false);
	}

	/* All checked*/
	return (true);
}


#ifdef CONFIG_STA_SUPPORT
void STAMlmePeriodicExec(
	struct rtmp_adapter *pAd)
{
	unsigned long			    TxTotalCnt;
	int 	i;
	bool bCheckBeaconLost = true;

	RTMP_CHIP_HIGH_POWER_TUNING(pAd, &pAd->StaCfg.RssiSample);

#ifdef WPA_SUPPLICANT_SUPPORT
    if (pAd->StaCfg.WpaSupplicantUP == WPA_SUPPLICANT_DISABLE)
#endif /* WPA_SUPPLICANT_SUPPORT */
    {
    	/* WPA MIC error should block association attempt for 60 seconds*/
		if (pAd->StaCfg.bBlockAssoc &&
			RTMP_TIME_AFTER(pAd->Mlme.Now32, pAd->StaCfg.LastMicErrorTime + (60*OS_HZ)))
    		pAd->StaCfg.bBlockAssoc = false;
    }

#ifdef RTMP_MAC_USB
	/* If station is idle, go to sleep*/
	if ( 1
	/*	&& (pAd->StaCfg.PSControl.field.EnablePSinIdle == true)*/
		&& (pAd->StaCfg.WindowsPowerMode > 0)
		&& (pAd->OpMode == OPMODE_STA) && (IDLE_ON(pAd))
		&& (pAd->Mlme.SyncMachine.CurrState == SYNC_IDLE)
		&& (pAd->Mlme.CntlMachine.CurrState == CNTL_IDLE)
		&& (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_IDLE_RADIO_OFF))
		)
	{
			MT76x0UsbAsicRadioOff(pAd, MLME_RADIO_OFF);

		DBGPRINT(RT_DEBUG_TRACE, ("PSM - Issue Sleep command)\n"));
	}

#endif /* RTMP_MAC_USB */




	if (ADHOC_ON(pAd))
	{
	}
	else
	{
    	AsicStaBbpTuning(pAd);
	}

	TxTotalCnt = pAd->RalinkCounters.OneSecTxNoRetryOkCount +
					 pAd->RalinkCounters.OneSecTxRetryOkCount +
					 pAd->RalinkCounters.OneSecTxFailCount;

	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS)
	)
	{
		unsigned long Now;
		bCheckBeaconLost = false;
		NdisGetSystemUpTime(&Now);
		pAd->StaCfg.LastBeaconRxTime = Now;
	}

	if (OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED) &&
		(!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS)))
	{
		/* update channel quality for Roaming/Fast-Roaming and UI LinkQuality display*/
		/* bImprovedScan True means scan is not completed */
		if (pAd->StaCfg.bImprovedScan)
			bCheckBeaconLost = false;


		if (bCheckBeaconLost)
		{
			/* The NIC may lost beacons during scaning operation.*/
			MAC_TABLE_ENTRY *pEntry = &pAd->MacTab.Content[BSSID_WCID];
			MlmeCalculateChannelQuality(pAd, pEntry, pAd->Mlme.Now32);
		}
	}


	/* must be AFTER MlmeDynamicTxRateSwitching() because it needs to know if*/
	/* Radio is currently in noisy environment*/
	if (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS))
		AsicAdjustTxPower(pAd);

	mt76x0_temp_tx_alc(pAd);

	/*
		Driver needs to up date value of LastOneSecTotalTxCount here;
		otherwise UI couldn't do scanning sometimes when STA doesn't connect to AP or peer Ad-Hoc.
	*/
	pAd->RalinkCounters.LastOneSecTotalTxCount = TxTotalCnt;

		/* resume Improved Scanning*/
		if ((pAd->StaCfg.bImprovedScan) &&
			(!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS)) &&
			(pAd->Mlme.SyncMachine.CurrState == SCAN_PENDING))
		{
			MLME_SCAN_REQ_STRUCT       ScanReq;

			pAd->StaCfg.LastScanTime = pAd->Mlme.Now32;

			ScanParmFill(pAd, &ScanReq, pAd->MlmeAux.Ssid, pAd->MlmeAux.SsidLen, BSS_ANY, SCAN_ACTIVE);
			MlmeEnqueue(pAd, SYNC_STATE_MACHINE, MT2_MLME_SCAN_REQ, sizeof(MLME_SCAN_REQ_STRUCT), &ScanReq, 0);
			DBGPRINT(RT_DEBUG_WARN, ("bImprovedScan ............. Resume for bImprovedScan, SCAN_PENDING .............. \n"));
		}

	if (INFRA_ON(pAd))
	{



#ifdef QOS_DLS_SUPPORT
		/* Check DLS time out, then tear down those session*/
		RTMPCheckDLSTimeOut(pAd);
#endif /* QOS_DLS_SUPPORT */


		/* Is PSM bit consistent with user power management policy?*/
		/* This is the only place that will set PSM bit ON.*/
		if (!OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_DOZE))
		MlmeCheckPsmChange(pAd, pAd->Mlme.Now32);

		/*
			When we are connected and do the scan progress, it's very possible we cannot receive
			the beacon of the AP. So, here we simulate that we received the beacon.
		*/
		if ((bCheckBeaconLost == false) &&
			RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS) &&
			(RTMP_TIME_AFTER(pAd->Mlme.Now32, pAd->StaCfg.LastBeaconRxTime + (1*OS_HZ))))
		{
			unsigned long BPtoJiffies;
			long timeDiff;

			BPtoJiffies = (((pAd->CommonCfg.BeaconPeriod * 1024 / 1000) * OS_HZ) / 1000);
			timeDiff = (pAd->Mlme.Now32 - pAd->StaCfg.LastBeaconRxTime) / BPtoJiffies;
			if (timeDiff > 0)
				pAd->StaCfg.LastBeaconRxTime += (timeDiff * BPtoJiffies);

			if (RTMP_TIME_AFTER(pAd->StaCfg.LastBeaconRxTime, pAd->Mlme.Now32))
			{
				DBGPRINT(RT_DEBUG_TRACE, ("MMCHK - BeaconRxTime adjust wrong(BeaconRx=0x%lx, Now=0x%lx)\n",
								pAd->StaCfg.LastBeaconRxTime, pAd->Mlme.Now32));
			}
		}


#ifdef RTMP_MAC_USB
#ifdef DOT11_N_SUPPORT
/*for 1X1 STA pass 11n wifi wmm, need to change txop per case;*/
/* 1x1 device for 802.11n WMM Test*/
	if(!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_IDLE_RADIO_OFF))
	{

		if ((pAd->Antenna.field.TxPath == 1)&&
		(pAd->StaActive.SupportedPhyInfo.bHtEnable == true) &&
			(pAd->CommonCfg.BACapability.field.Policy == BA_NOTUSE)
		)
		{
			EDCA_AC_CFG_STRUC	Ac0Cfg;
			EDCA_AC_CFG_STRUC	Ac2Cfg;
			Ac2Cfg.word = mt7610u_read32(pAd, EDCA_AC2_CFG);
			Ac0Cfg.word = mt7610u_read32(pAd, EDCA_AC0_CFG);

			if ((pAd->RalinkCounters.OneSecOsTxCount[QID_AC_VO] == 0) &&
			(pAd->RalinkCounters.OneSecOsTxCount[QID_AC_BK] == 0) &&
			(pAd->RalinkCounters.OneSecOsTxCount[QID_AC_BE] < 50) &&
			(pAd->RalinkCounters.OneSecOsTxCount[QID_AC_VI] >= 1000))
			{
			/*5.2.27/28 T7: Total throughput need to ~36Mbps*/
				if (Ac2Cfg.field.Aifsn!=0xc)
				{
					Ac2Cfg.field.Aifsn = 0xc;
					mt7610u_write32(pAd, EDCA_AC2_CFG, Ac2Cfg.word);
				}
			}
			else if ((pAd->RalinkCounters.OneSecOsTxCount[QID_AC_VO] == 0) &&
			(pAd->RalinkCounters.OneSecOsTxCount[QID_AC_BK] == 0) &&
			(pAd->RalinkCounters.OneSecOsTxCount[QID_AC_VI] == 0) &&
			(pAd->RalinkCounters.OneSecOsTxCount[QID_AC_BE] < 10))
			{
			/* restore default parameter of BE*/
				if ((Ac0Cfg.field.Aifsn!=3) ||(Ac0Cfg.field.AcTxop!=0))
				{
					if(Ac0Cfg.field.Aifsn!=3)
						Ac0Cfg.field.Aifsn = 3;
					if(Ac0Cfg.field.AcTxop!=0)
						Ac0Cfg.field.AcTxop = 0;
					mt7610u_write32(pAd, EDCA_AC0_CFG, Ac0Cfg.word);
				}

			/* restore default parameter of VI*/
				if (Ac2Cfg.field.Aifsn!=0x3)
				{
					Ac2Cfg.field.Aifsn = 0x3;
					mt7610u_write32(pAd, EDCA_AC2_CFG, Ac2Cfg.word);
				}

			}
		}
	}
#endif /* DOT11_N_SUPPORT */

		/* TODO: for debug only. to be removed*/
		pAd->RalinkCounters.OneSecOsTxCount[QID_AC_BE] = 0;
		pAd->RalinkCounters.OneSecOsTxCount[QID_AC_BK] = 0;
		pAd->RalinkCounters.OneSecOsTxCount[QID_AC_VI] = 0;
		pAd->RalinkCounters.OneSecOsTxCount[QID_AC_VO] = 0;
		pAd->RalinkCounters.OneSecDmaDoneCount[QID_AC_BE] = 0;
		pAd->RalinkCounters.OneSecDmaDoneCount[QID_AC_BK] = 0;
		pAd->RalinkCounters.OneSecDmaDoneCount[QID_AC_VI] = 0;
		pAd->RalinkCounters.OneSecDmaDoneCount[QID_AC_VO] = 0;
		pAd->RalinkCounters.OneSecTxDoneCount = 0;
		pAd->RalinkCounters.OneSecTxAggregationCount = 0;


#endif /* RTMP_MAC_USB */


        /*if ((pAd->RalinkCounters.OneSecTxNoRetryOkCount == 0) &&*/
        /*    (pAd->RalinkCounters.OneSecTxRetryOkCount == 0))*/
       if ((!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS)))
        {
    		if (pAd->StaCfg.UapsdInfo.bAPSDCapable && pAd->CommonCfg.APEdcaParm.bAPSDCapable)
    		{
    		    /* When APSD is enabled, the period changes as 20 sec*/
    			if ((pAd->Mlme.OneSecPeriodicRound % 20) == 8)
    			{
    				RTMPSendNullFrame(pAd, pAd->CommonCfg.TxRate, true, pAd->CommonCfg.bAPSDForcePowerSave ? PWR_SAVE : pAd->StaCfg.Psm);
    			}
    		}
    		else
    		{
    		    /* Send out a NULL frame every 10 sec to inform AP that STA is still alive (Avoid being age out)*/
    			if ((pAd->Mlme.OneSecPeriodicRound % 10) == 8)
			{
				RTMPSendNullFrame(pAd,
								  pAd->CommonCfg.TxRate,
								  (pAd->CommonCfg.bWmmCapable & pAd->CommonCfg.APEdcaParm.bValid),
								  pAd->CommonCfg.bAPSDForcePowerSave ? PWR_SAVE : pAd->StaCfg.Psm);
			}
    		}
        }

		if (CQI_IS_DEAD(pAd->Mlme.ChannelQuality))
			{
			DBGPRINT(RT_DEBUG_TRACE, ("MMCHK - No BEACON. Dead CQI. Auto Recovery attempt #%ld\n", pAd->RalinkCounters.BadCQIAutoRecoveryCount));

			if (pAd->StaCfg.bAutoConnectByBssid)
				pAd->StaCfg.bAutoConnectByBssid = false;

#ifdef WPA_SUPPLICANT_SUPPORT
			if ((pAd->StaCfg.WpaSupplicantUP != WPA_SUPPLICANT_DISABLE) &&
				(pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA2))
				pAd->StaCfg.bLostAp = true;
#endif /* WPA_SUPPLICANT_SUPPORT */

			pAd->MlmeAux.CurrReqIsFromNdis = false;
			/* Lost AP, send disconnect & link down event*/
			LinkDown(pAd, false);
		}
		else if (CQI_IS_BAD(pAd->Mlme.ChannelQuality))
		{
			pAd->RalinkCounters.BadCQIAutoRecoveryCount ++;
			DBGPRINT(RT_DEBUG_TRACE, ("MMCHK - Bad CQI. Auto Recovery attempt #%ld\n", pAd->RalinkCounters.BadCQIAutoRecoveryCount));
		}

		if (pAd->StaCfg.bAutoRoaming)
		{
			bool rv = false;
			char	dBmToRoam = pAd->StaCfg.dBmToRoam;
			char 	MaxRssi = RTMPMaxRssi(pAd,
										  pAd->StaCfg.RssiSample.LastRssi0,
										  pAd->StaCfg.RssiSample.LastRssi1,
										  pAd->StaCfg.RssiSample.LastRssi2);

			if (pAd->StaCfg.bAutoConnectByBssid)
				pAd->StaCfg.bAutoConnectByBssid = false;

			/* Scanning, ignore Roaming*/
			if (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS) &&
				(pAd->Mlme.SyncMachine.CurrState == SYNC_IDLE) &&
				(MaxRssi <= dBmToRoam))
			{
				DBGPRINT(RT_DEBUG_TRACE, ("Rssi=%d, dBmToRoam=%d\n", MaxRssi, (char)dBmToRoam));


				/* Add auto seamless roaming*/
				if (rv == false)
					rv = MlmeCheckForFastRoaming(pAd);

				if (rv == false)
				{
					if ((pAd->StaCfg.LastScanTime + 10 * OS_HZ) < pAd->Mlme.Now32)
					{
						DBGPRINT(RT_DEBUG_TRACE, ("MMCHK - Roaming, No eligable entry, try new scan!\n"));
						pAd->StaCfg.LastScanTime = pAd->Mlme.Now32;
						MlmeAutoScan(pAd);
					}
				}
			}
		}
	}
	else if (ADHOC_ON(pAd))
	{

		/* If all peers leave, and this STA becomes the last one in this IBSS, then change MediaState*/
		/* to DISCONNECTED. But still holding this IBSS (i.e. sending BEACON) so that other STAs can*/
		/* join later.*/
		if (/*(RTMP_TIME_AFTER(pAd->Mlme.Now32, pAd->StaCfg.LastBeaconRxTime + ADHOC_BEACON_LOST_TIME)
			|| (pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA2PSK))
			&& */OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED))
		{

			for (i = 1; i < MAX_LEN_OF_MAC_TABLE; i++)
			{
				MAC_TABLE_ENTRY *pEntry = &pAd->MacTab.Content[i];

				if (!IS_ENTRY_CLIENT(pEntry))
					continue;

				if (RTMP_TIME_AFTER(pAd->Mlme.Now32, pEntry->LastBeaconRxTime + ADHOC_BEACON_LOST_TIME)
				)
					MlmeDeAuthAction(pAd, pEntry, REASON_DISASSOC_STA_LEAVING, false);
			}

            if (pAd->MacTab.Size == 0)
            {
    			OPSTATUS_CLEAR_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED);
    			RTMP_IndicateMediaState(pAd, NdisMediaStateDisconnected);
            }
		}

	}
	else /* no INFRA nor ADHOC connection*/
	{


#ifdef WPA_SUPPLICANT_SUPPORT
		if (pAd->StaCfg.WpaSupplicantUP & WPA_SUPPLICANT_ENABLE_WPS)
			goto SKIP_AUTO_SCAN_CONN;
#endif /* WPA_SUPPLICANT_SUPPORT */

		if (pAd->StaCfg.bSkipAutoScanConn &&
			RTMP_TIME_BEFORE(pAd->Mlme.Now32, pAd->StaCfg.LastScanTime + (30 * OS_HZ)))
			goto SKIP_AUTO_SCAN_CONN;
		else
			pAd->StaCfg.bSkipAutoScanConn = false;

	}

SKIP_AUTO_SCAN_CONN:

#ifdef DOT11_N_SUPPORT
    if ((pAd->MacTab.Content[BSSID_WCID].TXBAbitmap !=0) && (pAd->MacTab.fAnyBASession == false)
		&& (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_IDLE_RADIO_OFF)))
	{
		pAd->MacTab.fAnyBASession = true;
		AsicUpdateProtect(pAd, HT_FORCERTSCTS,  ALLN_SETPROTECT, false, false);
	}
	else if ((pAd->MacTab.Content[BSSID_WCID].TXBAbitmap ==0) && (pAd->MacTab.fAnyBASession == true)
		&& (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_IDLE_RADIO_OFF)))
	{
		pAd->MacTab.fAnyBASession = false;
		AsicUpdateProtect(pAd, pAd->MlmeAux.AddHtInfo.AddHtInfo2.OperaionMode,  ALLN_SETPROTECT, false, false);
	}
#endif /* DOT11_N_SUPPORT */



#ifdef DOT11_N_SUPPORT
#ifdef DOT11N_DRAFT3
	/* Perform 20/40 BSS COEX scan every Dot11BssWidthTriggerScanInt	*/
	if ((OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_SCAN_2040)) &&
		(pAd->CommonCfg.Dot11BssWidthTriggerScanInt != 0) &&
		((pAd->Mlme.OneSecPeriodicRound % pAd->CommonCfg.Dot11BssWidthTriggerScanInt) == (pAd->CommonCfg.Dot11BssWidthTriggerScanInt-1)))
	{
		DBGPRINT(RT_DEBUG_TRACE, ("MMCHK - LastOneSecTotalTxCount/LastOneSecRxOkDataCnt  = %d/%d \n",
								pAd->RalinkCounters.LastOneSecTotalTxCount,
								pAd->RalinkCounters.LastOneSecRxOkDataCnt));

		/* Check last scan time at least 30 seconds from now. 		*/
		/* Check traffic is less than about 1.5~2Mbps.*/
		/* it might cause data lost if we enqueue scanning.*/
		/* This criteria needs to be considered*/
		if ((pAd->RalinkCounters.LastOneSecTotalTxCount < 70) && (pAd->RalinkCounters.LastOneSecRxOkDataCnt < 70))
		{
			MLME_SCAN_REQ_STRUCT            ScanReq;
			/* Fill out stuff for scan request and kick to scan*/
			ScanParmFill(pAd, &ScanReq, ZeroSsid, 0, BSS_ANY, SCAN_2040_BSS_COEXIST);
			MlmeEnqueue(pAd, SYNC_STATE_MACHINE, MT2_MLME_SCAN_REQ, sizeof(MLME_SCAN_REQ_STRUCT), &ScanReq, 0);
			pAd->Mlme.CntlMachine.CurrState = CNTL_WAIT_OID_LIST_SCAN;
			/* Set InfoReq = 1, So after scan , alwats sebd 20/40 Coexistence frame to AP*/
			pAd->CommonCfg.BSSCoexist2040.field.InfoReq = 1;
			RTMP_MLME_HANDLER(pAd);
		}

		DBGPRINT(RT_DEBUG_TRACE, (" LastOneSecTotalTxCount/LastOneSecRxOkDataCnt  = %d/%d \n",
							pAd->RalinkCounters.LastOneSecTotalTxCount,
							pAd->RalinkCounters.LastOneSecRxOkDataCnt));
	}
#endif /* DOT11N_DRAFT3 */
#endif /* DOT11_N_SUPPORT */

	return;
}

/* Link down report*/
void LinkDownExec(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3)
{
	struct rtmp_adapter*pAd = (struct rtmp_adapter*)FunctionContext;

	if (pAd != NULL)
	{
		MLME_DISASSOC_REQ_STRUCT   DisassocReq;

		if ((pAd->StaCfg.PortSecured == WPA_802_1X_PORT_NOT_SECURED) &&
			(INFRA_ON(pAd)))
		{
			DBGPRINT(RT_DEBUG_TRACE, ("LinkDownExec(): disassociate with current AP...\n"));
			DisassocParmFill(pAd, &DisassocReq, pAd->CommonCfg.Bssid, REASON_DISASSOC_STA_LEAVING);
			MlmeEnqueue(pAd, ASSOC_STATE_MACHINE, MT2_MLME_DISASSOC_REQ,
						sizeof(MLME_DISASSOC_REQ_STRUCT), &DisassocReq, 0);
			pAd->Mlme.CntlMachine.CurrState = CNTL_WAIT_DISASSOC;

			RTMP_IndicateMediaState(pAd, NdisMediaStateDisconnected);
		    pAd->ExtraInfo = GENERAL_LINK_DOWN;
		}
	}
}

/* IRQL = DISPATCH_LEVEL*/
void MlmeAutoScan(
	struct rtmp_adapter *pAd)
{
	/* check CntlMachine.CurrState to avoid collision with NDIS SetOID request*/
	if (pAd->Mlme.CntlMachine.CurrState == CNTL_IDLE)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("MMCHK - Driver auto scan\n"));
		MlmeEnqueue(pAd,
					MLME_CNTL_STATE_MACHINE,
					OID_802_11_BSSID_LIST_SCAN,
					pAd->MlmeAux.AutoReconnectSsidLen,
					pAd->MlmeAux.AutoReconnectSsid, 0);
		RTMP_MLME_HANDLER(pAd);
	}
}

/*
	==========================================================================
	Description:
		This routine checks if there're other APs out there capable for
		roaming. Caller should call this routine only when Link up in INFRA mode
		and channel quality is below CQI_GOOD_THRESHOLD.

	IRQL = DISPATCH_LEVEL

	Output:
	==========================================================================
 */
void MlmeCheckForRoaming(
	struct rtmp_adapter *pAd,
	unsigned long	Now32)
{
	unsigned short	   i;
	BSS_TABLE  *pRoamTab = &pAd->MlmeAux.RoamTab;
	BSS_ENTRY  *pBss;

	DBGPRINT(RT_DEBUG_TRACE, ("==> MlmeCheckForRoaming\n"));
	/* put all roaming candidates into RoamTab, and sort in RSSI order*/
	BssTableInit(pRoamTab);
	for (i = 0; i < pAd->ScanTab.BssNr; i++)
	{
		pBss = &pAd->ScanTab.BssEntry[i];

		if (RTMP_TIME_AFTER(Now32, pBss->LastBeaconRxTime + pAd->StaCfg.BeaconLostTime))
			continue;	 /* AP disappear*/
		if (pBss->Rssi <= RSSI_THRESHOLD_FOR_ROAMING)
			continue;	 /* RSSI too weak. forget it.*/
		if (MAC_ADDR_EQUAL(pBss->Bssid, pAd->CommonCfg.Bssid))
			continue;	 /* skip current AP*/
		if (pBss->Rssi < (pAd->StaCfg.RssiSample.LastRssi0 + RSSI_DELTA))
			continue;	 /* only AP with stronger RSSI is eligible for roaming*/

		/* AP passing all above rules is put into roaming candidate table		 */
		memmove(&pRoamTab->BssEntry[pRoamTab->BssNr], pBss, sizeof(BSS_ENTRY));
		pRoamTab->BssNr += 1;
	}

	if (pRoamTab->BssNr > 0)
	{
		/* check CntlMachine.CurrState to avoid collision with NDIS SetOID request*/
		if (pAd->Mlme.CntlMachine.CurrState == CNTL_IDLE)
		{
			pAd->RalinkCounters.PoorCQIRoamingCount ++;
			DBGPRINT(RT_DEBUG_TRACE, ("MMCHK - Roaming attempt #%ld\n", pAd->RalinkCounters.PoorCQIRoamingCount));
			MlmeEnqueue(pAd, MLME_CNTL_STATE_MACHINE, MT2_MLME_ROAMING_REQ, 0, NULL, 0);
			RTMP_MLME_HANDLER(pAd);
		}
	}
	DBGPRINT(RT_DEBUG_TRACE, ("<== MlmeCheckForRoaming(# of candidate= %d)\n",pRoamTab->BssNr));
}

/*
	==========================================================================
	Description:
		This routine checks if there're other APs out there capable for
		roaming. Caller should call this routine only when link up in INFRA mode
		and channel quality is below CQI_GOOD_THRESHOLD.

	IRQL = DISPATCH_LEVEL

	Output:
	==========================================================================
 */
bool MlmeCheckForFastRoaming(
	struct rtmp_adapter *pAd)
{
	unsigned short		i;
	BSS_TABLE	*pRoamTab = &pAd->MlmeAux.RoamTab;
	BSS_ENTRY	*pBss;

	DBGPRINT(RT_DEBUG_TRACE, ("==> MlmeCheckForFastRoaming\n"));
	/* put all roaming candidates into RoamTab, and sort in RSSI order*/
	BssTableInit(pRoamTab);
	for (i = 0; i < pAd->ScanTab.BssNr; i++)
	{
		pBss = &pAd->ScanTab.BssEntry[i];

        if ((pBss->Rssi <= -50) && (pBss->Channel == pAd->CommonCfg.Channel))
			continue;	 /* RSSI too weak. forget it.*/
		if (MAC_ADDR_EQUAL(pBss->Bssid, pAd->CommonCfg.Bssid))
			continue;	 /* skip current AP*/
		if (!SSID_EQUAL(pBss->Ssid, pBss->SsidLen, pAd->CommonCfg.Ssid, pAd->CommonCfg.SsidLen))
			continue;	 /* skip different SSID*/
        if (pBss->Rssi < (RTMPMaxRssi(pAd, pAd->StaCfg.RssiSample.LastRssi0, pAd->StaCfg.RssiSample.LastRssi1, pAd->StaCfg.RssiSample.LastRssi2) + RSSI_DELTA))
			continue;	 /* skip AP without better RSSI*/

        DBGPRINT(RT_DEBUG_TRACE, ("LastRssi0 = %d, pBss->Rssi = %d\n", RTMPMaxRssi(pAd, pAd->StaCfg.RssiSample.LastRssi0, pAd->StaCfg.RssiSample.LastRssi1, pAd->StaCfg.RssiSample.LastRssi2), pBss->Rssi));
		/* AP passing all above rules is put into roaming candidate table		 */
		memmove(&pRoamTab->BssEntry[pRoamTab->BssNr], pBss, sizeof(BSS_ENTRY));
		pRoamTab->BssNr += 1;
	}

	DBGPRINT(RT_DEBUG_TRACE, ("<== MlmeCheckForFastRoaming (BssNr=%d)\n", pRoamTab->BssNr));
	if (pRoamTab->BssNr > 0)
	{
		/* check CntlMachine.CurrState to avoid collision with NDIS SetOID request*/
		if (pAd->Mlme.CntlMachine.CurrState == CNTL_IDLE)
		{
			pAd->RalinkCounters.PoorCQIRoamingCount ++;
			DBGPRINT(RT_DEBUG_TRACE, ("MMCHK - Roaming attempt #%ld\n", pAd->RalinkCounters.PoorCQIRoamingCount));
			MlmeEnqueue(pAd, MLME_CNTL_STATE_MACHINE, MT2_MLME_ROAMING_REQ, 0, NULL, 0);
			RTMP_MLME_HANDLER(pAd);
			return true;
		}
	}

	return false;
}


/*
	==========================================================================
	Description:
		This routine is executed periodically inside MlmePeriodicExec() after
		association with an AP.
		It checks if StaCfg.Psm is consistent with user policy (recorded in
		StaCfg.WindowsPowerMode). If not, enforce user policy. However,
		there're some conditions to consider:
		1. we don't support power-saving in ADHOC mode, so Psm=PWR_ACTIVE all
		   the time when Mibss==true
		2. When link up in INFRA mode, Psm should not be switch to PWR_SAVE
		   if outgoing traffic available in TxRing or MgmtRing.
	Output:
		1. change pAd->StaCfg.Psm to PWR_SAVE or leave it untouched

	IRQL = DISPATCH_LEVEL

	==========================================================================
 */
void MlmeCheckPsmChange(
	struct rtmp_adapter *pAd,
	unsigned long	Now32)
{
	unsigned long	PowerMode;

	/*
		condition -
		1. Psm maybe ON only happen in INFRASTRUCTURE mode
		2. user wants either MAX_PSP or FAST_PSP
		3. but current psm is not in PWR_SAVE
		4. CNTL state machine is not doing SCANning
		5. no TX SUCCESS event for the past 1-sec period
	*/
	PowerMode = pAd->StaCfg.WindowsPowerMode;

	if (INFRA_ON(pAd) &&
		(PowerMode != Ndis802_11PowerModeCAM) &&
		(pAd->StaCfg.Psm == PWR_ACTIVE) &&
/*		(! RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS))*/
		(pAd->Mlme.CntlMachine.CurrState == CNTL_IDLE)
#ifdef RTMP_MAC_USB
		&&		(pAd->CountDowntoPsm == 0)
#endif /* RTMP_MAC_USB */
		 /*&&
		(pAd->RalinkCounters.OneSecTxNoRetryOkCount == 0) &&
		(pAd->RalinkCounters.OneSecTxRetryOkCount == 0)*/)
	{
		NdisGetSystemUpTime(&pAd->Mlme.LastSendNULLpsmTime);
		pAd->RalinkCounters.RxCountSinceLastNULL = 0;
		RTMP_SET_PSM_BIT(pAd, PWR_SAVE);

		if (!(pAd->StaCfg.UapsdInfo.bAPSDCapable && pAd->CommonCfg.APEdcaParm.bAPSDCapable))
		{
			RTMPSendNullFrame(pAd, pAd->CommonCfg.TxRate, (OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_WMM_INUSED) ? true:false), pAd->CommonCfg.bAPSDForcePowerSave ? PWR_SAVE : pAd->StaCfg.Psm);
		}
		else
		{
			RTMPSendNullFrame(pAd, pAd->CommonCfg.TxRate, true, pAd->CommonCfg.bAPSDForcePowerSave ? PWR_SAVE : pAd->StaCfg.Psm);
		}

	}
}

/* IRQL = PASSIVE_LEVEL*/
/* IRQL = DISPATCH_LEVEL*/
void MlmeSetPsmBit(
	struct rtmp_adapter *pAd,
	unsigned short psm)
{

	pAd->StaCfg.Psm = psm;


	DBGPRINT(RT_DEBUG_TRACE, ("MlmeSetPsmBit = %d\n", psm));
}
#endif /* CONFIG_STA_SUPPORT */

/*
	==========================================================================
	Description:
		This routine calculates TxPER, RxPER of the past N-sec period. And
		according to the calculation result, ChannelQuality is calculated here
		to decide if current AP is still doing the job.

		If ChannelQuality is not good, a ROAMing attempt may be tried later.
	Output:
		StaCfg.ChannelQuality - 0..100

	IRQL = DISPATCH_LEVEL

	NOTE: This routine decide channle quality based on RX CRC error ratio.
		Caller should make sure a function call to NICUpdateRawCounters(pAd)
		is performed right before this routine, so that this routine can decide
		channel quality based on the most up-to-date information
	==========================================================================
 */
void MlmeCalculateChannelQuality(
	struct rtmp_adapter *pAd,
	PMAC_TABLE_ENTRY pMacEntry,
	unsigned long Now32)
{
	unsigned long TxOkCnt, TxCnt, TxPER, TxPRR;
	unsigned long RxCnt, RxPER;
	u8 NorRssi;
	char  MaxRssi;
	RSSI_SAMPLE *pRssiSample = NULL;
	u32 OneSecTxNoRetryOkCount = 0;
	u32 OneSecTxRetryOkCount = 0;
	u32 OneSecTxFailCount = 0;
	u32 OneSecRxOkCnt = 0;
	u32 OneSecRxFcsErrCnt = 0;
	unsigned long ChannelQuality = 0;  /* 0..100, Channel Quality Indication for Roaming*/
#ifdef CONFIG_STA_SUPPORT
	unsigned long LastBeaconRxTime = 0;
	unsigned long BeaconLostTime = pAd->StaCfg.BeaconLostTime;
#endif /* CONFIG_STA_SUPPORT */

#ifdef CONFIG_STA_SUPPORT

#ifdef APCLI_SUPPORT
		if (pMacEntry && IS_ENTRY_APCLI(pMacEntry) && (pMacEntry->MatchAPCLITabIdx < MAX_APCLI_NUM))
			LastBeaconRxTime = pAd->ApCfg.ApCliTab[pMacEntry->MatchAPCLITabIdx].ApCliRcvBeaconTime;
		else
#endif /*APCLI_SUPPORT*/
			LastBeaconRxTime = pAd->StaCfg.LastBeaconRxTime;
#endif /* CONFIG_STA_SUPPORT */


		if (pMacEntry != NULL)
		{
			pRssiSample = &pMacEntry->RssiSample;
			OneSecTxNoRetryOkCount = pMacEntry->OneSecTxNoRetryOkCount;
			OneSecTxRetryOkCount = pMacEntry->OneSecTxRetryOkCount;
			OneSecTxFailCount = pMacEntry->OneSecTxFailCount;
			OneSecRxOkCnt = pAd->RalinkCounters.OneSecRxOkCnt;
			OneSecRxFcsErrCnt = pAd->RalinkCounters.OneSecRxFcsErrCnt;
		}
		else
		{
			pRssiSample = &pAd->MacTab.Content[0].RssiSample;
			OneSecTxNoRetryOkCount = pAd->RalinkCounters.OneSecTxNoRetryOkCount;
			OneSecTxRetryOkCount = pAd->RalinkCounters.OneSecTxRetryOkCount;
			OneSecTxFailCount = pAd->RalinkCounters.OneSecTxFailCount;
			OneSecRxOkCnt = pAd->RalinkCounters.OneSecRxOkCnt;
			OneSecRxFcsErrCnt = pAd->RalinkCounters.OneSecRxFcsErrCnt;
		}

	if (pRssiSample == NULL)
		return;
	MaxRssi = RTMPMaxRssi(pAd, pRssiSample->LastRssi0,
								pRssiSample->LastRssi1,
								pRssiSample->LastRssi2);


	/*
		calculate TX packet error ratio and TX retry ratio - if too few TX samples,
		skip TX related statistics
	*/
	TxOkCnt = OneSecTxNoRetryOkCount + OneSecTxRetryOkCount;
	TxCnt = TxOkCnt + OneSecTxFailCount;
	if (TxCnt < 5)
	{
		TxPER = 0;
		TxPRR = 0;
	}
	else
	{
		TxPER = (OneSecTxFailCount * 100) / TxCnt;
		TxPRR = ((TxCnt - OneSecTxNoRetryOkCount) * 100) / TxCnt;
	}


	/* calculate RX PER - don't take RxPER into consideration if too few sample*/
	RxCnt = OneSecRxOkCnt + OneSecRxFcsErrCnt;
	if (RxCnt < 5)
		RxPER = 0;
	else
		RxPER = (OneSecRxFcsErrCnt * 100) / RxCnt;


	/* decide ChannelQuality based on: 1)last BEACON received time, 2)last RSSI, 3)TxPER, and 4)RxPER*/
#ifdef CONFIG_STA_SUPPORT
	if ((pAd->OpMode == OPMODE_STA) &&
		INFRA_ON(pAd) &&
		(OneSecTxNoRetryOkCount < 2) && /* no heavy traffic*/
		RTMP_TIME_AFTER(Now32, LastBeaconRxTime + BeaconLostTime))
	{
		DBGPRINT(RT_DEBUG_TRACE, ("BEACON lost > %ld msec with TxOkCnt=%ld -> CQI=0\n", BeaconLostTime * (1000 / OS_HZ) , TxOkCnt));
		ChannelQuality = 0;
	}
	else
#endif /* CONFIG_STA_SUPPORT */
	{
		/* Normalize Rssi*/
		if (MaxRssi > -40)
			NorRssi = 100;
		else if (MaxRssi < -90)
			NorRssi = 0;
		else
			NorRssi = (MaxRssi + 90) * 2;

		/* ChannelQuality = W1*RSSI + W2*TxPRR + W3*RxPER	 (RSSI 0..100), (TxPER 100..0), (RxPER 100..0)*/
		ChannelQuality = (RSSI_WEIGHTING * NorRssi +
								   TX_WEIGHTING * (100 - TxPRR) +
								   RX_WEIGHTING* (100 - RxPER)) / 100;
	}


#ifdef CONFIG_STA_SUPPORT
	if (pAd->OpMode == OPMODE_STA)
		pAd->Mlme.ChannelQuality = (ChannelQuality > 100) ? 100 : ChannelQuality;
#endif /* CONFIG_STA_SUPPORT */


}


/* IRQL = DISPATCH_LEVEL*/
void MlmeSetTxPreamble(
	struct rtmp_adapter *pAd,
	unsigned short TxPreamble)
{
	AUTO_RSP_CFG_STRUC csr4;


	/* Always use Long preamble before verifiation short preamble functionality works well.*/
	/* Todo: remove the following line if short preamble functionality works*/

	/*TxPreamble = Rt802_11PreambleLong;*/

	csr4.word = mt7610u_read32(pAd, AUTO_RSP_CFG);
	if (TxPreamble == Rt802_11PreambleLong)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("MlmeSetTxPreamble (= long PREAMBLE)\n"));
		OPSTATUS_CLEAR_FLAG(pAd, fOP_STATUS_SHORT_PREAMBLE_INUSED);
		csr4.field.AutoResponderPreamble = 0;
	}
	else
	{
		/* NOTE: 1Mbps should always use long preamble*/
		DBGPRINT(RT_DEBUG_TRACE, ("MlmeSetTxPreamble (= SHORT PREAMBLE)\n"));
		OPSTATUS_SET_FLAG(pAd, fOP_STATUS_SHORT_PREAMBLE_INUSED);
		csr4.field.AutoResponderPreamble = 1;
	}

	mt7610u_write32(pAd, AUTO_RSP_CFG, csr4.word);
}

/*
    ==========================================================================
    Description:
        Update basic rate bitmap
    ==========================================================================
 */

void UpdateBasicRateBitmap(
    struct rtmp_adapter *  pAdapter)
{
    int  i, j;
                  /* 1  2  5.5, 11,  6,  9, 12, 18, 24, 36, 48,  54 */
    u8 rate[] = { 2, 4,  11, 22, 12, 18, 24, 36, 48, 72, 96, 108 };
    u8 *sup_p = pAdapter->CommonCfg.SupRate;
    u8 *ext_p = pAdapter->CommonCfg.ExtRate;
    unsigned long bitmap = pAdapter->CommonCfg.BasicRateBitmap;

    /* if A mode, always use fix BasicRateBitMap */
    /*if (pAdapter->CommonCfg.Channel == WMODE_A)*/
	if (pAdapter->CommonCfg.Channel > 14)
	{
		if (pAdapter->CommonCfg.BasicRateBitmap & 0xF)
		{
			/* no 11b rate in 5G band */
			pAdapter->CommonCfg.BasicRateBitmapOld = \
										pAdapter->CommonCfg.BasicRateBitmap;
			pAdapter->CommonCfg.BasicRateBitmap &= (~0xF); /* no 11b */
		}

		/* force to 6,12,24M in a-band */
		pAdapter->CommonCfg.BasicRateBitmap |= 0x150; /* 6, 12, 24M */
    }
	else
	{
		/* no need to modify in 2.4G (bg mixed) */
		pAdapter->CommonCfg.BasicRateBitmap = \
										pAdapter->CommonCfg.BasicRateBitmapOld;
	}

    if (pAdapter->CommonCfg.BasicRateBitmap > 4095)
    {
        /* (2 ^ MAX_LEN_OF_SUPPORTED_RATES) -1 */
        return;
    }

    for(i=0; i<MAX_LEN_OF_SUPPORTED_RATES; i++)
    {
        sup_p[i] &= 0x7f;
        ext_p[i] &= 0x7f;
    }

    for(i=0; i<MAX_LEN_OF_SUPPORTED_RATES; i++)
    {
        if (bitmap & (1 << i))
        {
            for(j=0; j<MAX_LEN_OF_SUPPORTED_RATES; j++)
            {
                if (sup_p[j] == rate[i])
                    sup_p[j] |= 0x80;
            }

            for(j=0; j<MAX_LEN_OF_SUPPORTED_RATES; j++)
            {
                if (ext_p[j] == rate[i])
                    ext_p[j] |= 0x80;
            }
        }
    }
}

/*
	bLinkUp is to identify the inital link speed.
	true indicates the rate update at linkup, we should not try to set the rate at 54Mbps.
*/
void MlmeUpdateTxRates(
	struct rtmp_adapter*pAd,
	bool bLinkUp,
	u8 apidx)
{
	int i, num;
	u8 Rate = RATE_6, MaxDesire = RATE_1, MaxSupport = RATE_1;
	u8 MinSupport = RATE_54;
	unsigned long BasicRateBitmap = 0;
	u8 CurrBasicRate = RATE_1;
	u8 *pSupRate, SupRateLen, *pExtRate, ExtRateLen;
	HTTRANSMIT_SETTING *pHtPhy = NULL, *pMaxHtPhy = NULL, *pMinHtPhy = NULL;
	bool *auto_rate_cur_p;
	u8 HtMcs = MCS_AUTO;

	/* find max desired rate*/
	UpdateBasicRateBitmap(pAd);

	num = 0;
	auto_rate_cur_p = NULL;
	for (i=0; i<MAX_LEN_OF_SUPPORTED_RATES; i++)
	{
		switch (pAd->CommonCfg.DesireRate[i] & 0x7f)
		{
			case 2:  Rate = RATE_1;   num++;   break;
			case 4:  Rate = RATE_2;   num++;   break;
			case 11: Rate = RATE_5_5; num++;   break;
			case 22: Rate = RATE_11;  num++;   break;
			case 12: Rate = RATE_6;   num++;   break;
			case 18: Rate = RATE_9;   num++;   break;
			case 24: Rate = RATE_12;  num++;   break;
			case 36: Rate = RATE_18;  num++;   break;
			case 48: Rate = RATE_24;  num++;   break;
			case 72: Rate = RATE_36;  num++;   break;
			case 96: Rate = RATE_48;  num++;   break;
			case 108: Rate = RATE_54; num++;   break;
			/*default: Rate = RATE_1;   break;*/
		}
		if (MaxDesire < Rate)  MaxDesire = Rate;
	}

/*===========================================================================*/
/*===========================================================================*/
	do
	{

#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
			pHtPhy = &pAd->StaCfg.HTPhyMode;
			pMaxHtPhy = &pAd->StaCfg.MaxHTPhyMode;
			pMinHtPhy = &pAd->StaCfg.MinHTPhyMode;

			auto_rate_cur_p = &pAd->StaCfg.bAutoTxRateSwitch;
			HtMcs = pAd->StaCfg.DesiredTransmitSetting.field.MCS;

			if ((pAd->StaCfg.BssType == BSS_ADHOC) &&
				WMODE_EQUAL(pAd->CommonCfg.PhyMode, WMODE_B) &&
				(MaxDesire > RATE_11))
			{
				MaxDesire = RATE_11;
			}
			break;
		}
#endif /* CONFIG_STA_SUPPORT */
	} while(false);

	pAd->CommonCfg.MaxDesiredRate = MaxDesire;

	if (pMinHtPhy == NULL)
		return;
	pMinHtPhy->word = 0;
	pMaxHtPhy->word = 0;
	pHtPhy->word = 0;

	/*
		Auto rate switching is enabled only if more than one DESIRED RATES are
		specified; otherwise disabled
	*/
	if (num <= 1)
		*auto_rate_cur_p = false;
	else
		*auto_rate_cur_p = true;

	if (HtMcs != MCS_AUTO)
		*auto_rate_cur_p = false;
	else
		*auto_rate_cur_p = true;

#ifdef CONFIG_STA_SUPPORT
	if ((ADHOC_ON(pAd) || INFRA_ON(pAd)) && (pAd->OpMode == OPMODE_STA)
		)
	{
		pSupRate = &pAd->StaActive.SupRate[0];
		pExtRate = &pAd->StaActive.ExtRate[0];
		SupRateLen = pAd->StaActive.SupRateLen;
		ExtRateLen = pAd->StaActive.ExtRateLen;
	}
	else
#endif /* CONFIG_STA_SUPPORT */
	{
		pSupRate = &pAd->CommonCfg.SupRate[0];
		pExtRate = &pAd->CommonCfg.ExtRate[0];
		SupRateLen = pAd->CommonCfg.SupRateLen;
		ExtRateLen = pAd->CommonCfg.ExtRateLen;
	}

	/* find max supported rate*/
	for (i=0; i<SupRateLen; i++)
	{
		switch (pSupRate[i] & 0x7f)
		{
			case 2:   Rate = RATE_1;	if (pSupRate[i] & 0x80) BasicRateBitmap |= 1 << 0;	 break;
			case 4:   Rate = RATE_2;	if (pSupRate[i] & 0x80) BasicRateBitmap |= 1 << 1;	 break;
			case 11:  Rate = RATE_5_5;	if (pSupRate[i] & 0x80) BasicRateBitmap |= 1 << 2;	 break;
			case 22:  Rate = RATE_11;	if (pSupRate[i] & 0x80) BasicRateBitmap |= 1 << 3;	 break;
			case 12:  Rate = RATE_6;	/*if (pSupRate[i] & 0x80)*/  BasicRateBitmap |= 1 << 4;  break;
			case 18:  Rate = RATE_9;	if (pSupRate[i] & 0x80) BasicRateBitmap |= 1 << 5;	 break;
			case 24:  Rate = RATE_12;	/*if (pSupRate[i] & 0x80)*/  BasicRateBitmap |= 1 << 6;  break;
			case 36:  Rate = RATE_18;	if (pSupRate[i] & 0x80) BasicRateBitmap |= 1 << 7;	 break;
			case 48:  Rate = RATE_24;	/*if (pSupRate[i] & 0x80)*/  BasicRateBitmap |= 1 << 8;  break;
			case 72:  Rate = RATE_36;	if (pSupRate[i] & 0x80) BasicRateBitmap |= 1 << 9;	 break;
			case 96:  Rate = RATE_48;	if (pSupRate[i] & 0x80) BasicRateBitmap |= 1 << 10;	 break;
			case 108: Rate = RATE_54;	if (pSupRate[i] & 0x80) BasicRateBitmap |= 1 << 11;	 break;
			default:  Rate = RATE_1;	break;
		}

		if (MaxSupport < Rate)
			MaxSupport = Rate;

		if (MinSupport > Rate)
			MinSupport = Rate;
	}

	for (i=0; i<ExtRateLen; i++)
	{
		switch (pExtRate[i] & 0x7f)
		{
			case 2:   Rate = RATE_1;	if (pExtRate[i] & 0x80) BasicRateBitmap |= 1 << 0;	 break;
			case 4:   Rate = RATE_2;	if (pExtRate[i] & 0x80) BasicRateBitmap |= 1 << 1;	 break;
			case 11:  Rate = RATE_5_5;	if (pExtRate[i] & 0x80) BasicRateBitmap |= 1 << 2;	 break;
			case 22:  Rate = RATE_11;	if (pExtRate[i] & 0x80) BasicRateBitmap |= 1 << 3;	 break;
			case 12:  Rate = RATE_6;	/*if (pExtRate[i] & 0x80)*/  BasicRateBitmap |= 1 << 4;  break;
			case 18:  Rate = RATE_9;	if (pExtRate[i] & 0x80) BasicRateBitmap |= 1 << 5;	 break;
			case 24:  Rate = RATE_12;	/*if (pExtRate[i] & 0x80)*/  BasicRateBitmap |= 1 << 6;  break;
			case 36:  Rate = RATE_18;	if (pExtRate[i] & 0x80) BasicRateBitmap |= 1 << 7;	 break;
			case 48:  Rate = RATE_24;	/*if (pExtRate[i] & 0x80)*/  BasicRateBitmap |= 1 << 8;  break;
			case 72:  Rate = RATE_36;	if (pExtRate[i] & 0x80) BasicRateBitmap |= 1 << 9;	 break;
			case 96:  Rate = RATE_48;	if (pExtRate[i] & 0x80) BasicRateBitmap |= 1 << 10;	 break;
			case 108: Rate = RATE_54;	if (pExtRate[i] & 0x80) BasicRateBitmap |= 1 << 11;	 break;
			default:  Rate = RATE_1;
				break;
		}
		if (MaxSupport < Rate)
			MaxSupport = Rate;

		if (MinSupport > Rate)
			MinSupport = Rate;
	}

	mt7610u_write32(pAd, LEGACY_BASIC_RATE, BasicRateBitmap);

	for (i=0; i<MAX_LEN_OF_SUPPORTED_RATES; i++)
	{
		if (BasicRateBitmap & (0x01 << i))
			CurrBasicRate = (u8)i;
		pAd->CommonCfg.ExpectedACKRate[i] = CurrBasicRate;
	}

	DBGPRINT(RT_DEBUG_TRACE,("%s():[MaxSupport = %d] = MaxDesire %d Mbps\n",
				__FUNCTION__, RateIdToMbps[MaxSupport], RateIdToMbps[MaxDesire]));
	/* max tx rate = min {max desire rate, max supported rate}*/
	if (MaxSupport < MaxDesire)
		pAd->CommonCfg.MaxTxRate = MaxSupport;
	else
		pAd->CommonCfg.MaxTxRate = MaxDesire;

	pAd->CommonCfg.MinTxRate = MinSupport;
	/*
		2003-07-31 john - 2500 doesn't have good sensitivity at high OFDM rates. to increase the success
		ratio of initial DHCP packet exchange, TX rate starts from a lower rate depending
		on average RSSI
			1. RSSI >= -70db, start at 54 Mbps (short distance)
			2. -70 > RSSI >= -75, start at 24 Mbps (mid distance)
			3. -75 > RSSI, start at 11 Mbps (long distance)
	*/
	if (*auto_rate_cur_p)
	{
		short dbm = 0;
#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
			dbm = pAd->StaCfg.RssiSample.AvgRssi0 - pAd->BbpRssiToDbmDelta;
#endif /* CONFIG_STA_SUPPORT */
		if (bLinkUp == true)
			pAd->CommonCfg.TxRate = RATE_24;
		else
			pAd->CommonCfg.TxRate = pAd->CommonCfg.MaxTxRate;

		if (dbm < -75)
			pAd->CommonCfg.TxRate = RATE_11;
		else if (dbm < -70)
			pAd->CommonCfg.TxRate = RATE_24;

		/* should never exceed MaxTxRate (consider 11B-only mode)*/
		if (pAd->CommonCfg.TxRate > pAd->CommonCfg.MaxTxRate)
			pAd->CommonCfg.TxRate = pAd->CommonCfg.MaxTxRate;

		pAd->CommonCfg.TxRateIndex = 0;

	}
	else
	{
		pAd->CommonCfg.TxRate = pAd->CommonCfg.MaxTxRate;

		/* Choose the Desire Tx MCS in CCK/OFDM mode */
		if (num > RATE_6)
		{
			if (HtMcs <= MCS_7)
				MaxDesire = RxwiMCSToOfdmRate[HtMcs];
			else
				MaxDesire = MinSupport;
		}
		else
		{
			if (HtMcs <= MCS_3)
				MaxDesire = HtMcs;
			else
				MaxDesire = MinSupport;
		}

		pAd->MacTab.Content[BSSID_WCID].HTPhyMode.field.STBC = pHtPhy->field.STBC;
		pAd->MacTab.Content[BSSID_WCID].HTPhyMode.field.ShortGI = pHtPhy->field.ShortGI;
		pAd->MacTab.Content[BSSID_WCID].HTPhyMode.field.MCS = pHtPhy->field.MCS;
		pAd->MacTab.Content[BSSID_WCID].HTPhyMode.field.MODE	= pHtPhy->field.MODE;

	}

	if (pAd->CommonCfg.TxRate <= RATE_11)
	{
		pMaxHtPhy->field.MODE = MODE_CCK;

#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
			pMaxHtPhy->field.MCS = pAd->CommonCfg.TxRate;
			pMinHtPhy->field.MCS = pAd->CommonCfg.MinTxRate;
		}
#endif /* CONFIG_STA_SUPPORT */

	}
	else
	{
		pMaxHtPhy->field.MODE = MODE_OFDM;

#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
			pMaxHtPhy->field.MCS = OfdmRateToRxwiMCS[pAd->CommonCfg.TxRate];
			if (pAd->CommonCfg.MinTxRate >= RATE_6 && (pAd->CommonCfg.MinTxRate <= RATE_54))
				pMinHtPhy->field.MCS = OfdmRateToRxwiMCS[pAd->CommonCfg.MinTxRate];
			else
				pMinHtPhy->field.MCS = pAd->CommonCfg.MinTxRate;
		}
#endif /* CONFIG_STA_SUPPORT */

	}

	pHtPhy->word = (pMaxHtPhy->word);
	if (bLinkUp && (pAd->OpMode == OPMODE_STA))
	{
		pAd->MacTab.Content[BSSID_WCID].HTPhyMode.word = pHtPhy->word;
		pAd->MacTab.Content[BSSID_WCID].MaxHTPhyMode.word = pMaxHtPhy->word;
		pAd->MacTab.Content[BSSID_WCID].MinHTPhyMode.word = pMinHtPhy->word;
	}
	else
	{
		if (WMODE_CAP(pAd->CommonCfg.PhyMode, WMODE_B) &&
			pAd->CommonCfg.Channel <= 14)
		{
			pAd->CommonCfg.MlmeRate = RATE_1;
			pAd->CommonCfg.MlmeTransmit.field.MODE = MODE_CCK;
			pAd->CommonCfg.MlmeTransmit.field.MCS = RATE_1;
			pAd->CommonCfg.RtsRate = RATE_11;
		}
		else
		{
			pAd->CommonCfg.MlmeRate = RATE_6;
			pAd->CommonCfg.RtsRate = RATE_6;
			pAd->CommonCfg.MlmeTransmit.field.MODE = MODE_OFDM;
			pAd->CommonCfg.MlmeTransmit.field.MCS = OfdmRateToRxwiMCS[pAd->CommonCfg.MlmeRate];
		}

		/* Keep Basic Mlme Rate.*/
		pAd->MacTab.Content[MCAST_WCID].HTPhyMode.word = pAd->CommonCfg.MlmeTransmit.word;
		if (pAd->CommonCfg.MlmeTransmit.field.MODE == MODE_OFDM)
			pAd->MacTab.Content[MCAST_WCID].HTPhyMode.field.MCS = OfdmRateToRxwiMCS[RATE_24];
		else
			pAd->MacTab.Content[MCAST_WCID].HTPhyMode.field.MCS = RATE_1;
		pAd->CommonCfg.BasicMlmeRate = pAd->CommonCfg.MlmeRate;

	}

	DBGPRINT(RT_DEBUG_TRACE, (" %s(): (MaxDesire=%d, MaxSupport=%d, MaxTxRate=%d, MinRate=%d, Rate Switching =%d)\n",
				__FUNCTION__, RateIdToMbps[MaxDesire], RateIdToMbps[MaxSupport],
				RateIdToMbps[pAd->CommonCfg.MaxTxRate],
				RateIdToMbps[pAd->CommonCfg.MinTxRate],
			 /*OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_TX_RATE_SWITCH_ENABLED)*/*auto_rate_cur_p));
	DBGPRINT(RT_DEBUG_TRACE, (" %s(): (TxRate=%d, RtsRate=%d, BasicRateBitmap=0x%04lx)\n",
				__FUNCTION__, RateIdToMbps[pAd->CommonCfg.TxRate],
				RateIdToMbps[pAd->CommonCfg.RtsRate], BasicRateBitmap));
	DBGPRINT(RT_DEBUG_TRACE, ("%s(): (MlmeTransmit=0x%x, MinHTPhyMode=%x, MaxHTPhyMode=0x%x, HTPhyMode=0x%x)\n",
				__FUNCTION__, pAd->CommonCfg.MlmeTransmit.word,
				pAd->MacTab.Content[BSSID_WCID].MinHTPhyMode.word,
				pAd->MacTab.Content[BSSID_WCID].MaxHTPhyMode.word,
				pAd->MacTab.Content[BSSID_WCID].HTPhyMode.word ));
}

#ifdef DOT11_N_SUPPORT
/*
	==========================================================================
	Description:
		This function update HT Rate setting.
		Input Wcid value is valid for 2 case :
		1. it's used for Station in infra mode that copy AP rate to Mactable.
		2. OR Station 	in adhoc mode to copy peer's HT rate to Mactable.

	IRQL = DISPATCH_LEVEL

	==========================================================================
 */
void MlmeUpdateHtTxRates(
	struct rtmp_adapter*pAd,
	u8 apidx)
{
	u8 StbcMcs;
	RT_HT_CAPABILITY *pRtHtCap = NULL;
	RT_PHY_INFO *pActiveHtPhy = NULL;
	unsigned long BasicMCS;
	RT_PHY_INFO *pDesireHtPhy = NULL;
	PHTTRANSMIT_SETTING pHtPhy = NULL;
	PHTTRANSMIT_SETTING pMaxHtPhy = NULL;
	PHTTRANSMIT_SETTING pMinHtPhy = NULL;
	bool *auto_rate_cur_p;

	DBGPRINT(RT_DEBUG_TRACE,("%s()===> \n", __FUNCTION__));

	auto_rate_cur_p = NULL;

	do
	{

#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
			pDesireHtPhy	= &pAd->StaCfg.DesiredHtPhyInfo;
			pActiveHtPhy	= &pAd->StaCfg.DesiredHtPhyInfo;
			pHtPhy 		= &pAd->StaCfg.HTPhyMode;
			pMaxHtPhy	= &pAd->StaCfg.MaxHTPhyMode;
			pMinHtPhy	= &pAd->StaCfg.MinHTPhyMode;

			auto_rate_cur_p = &pAd->StaCfg.bAutoTxRateSwitch;
			break;
		}
#endif /* CONFIG_STA_SUPPORT */
	} while (false);

#ifdef CONFIG_STA_SUPPORT
	if ((ADHOC_ON(pAd) || INFRA_ON(pAd)) && (pAd->OpMode == OPMODE_STA)
		)
	{
		if (pAd->StaActive.SupportedPhyInfo.bHtEnable == false)
			return;

		pRtHtCap = &pAd->StaActive.SupportedHtPhy;
		pActiveHtPhy = &pAd->StaActive.SupportedPhyInfo;
		StbcMcs = (u8)pAd->MlmeAux.AddHtInfo.AddHtInfo3.StbcMcs;
		BasicMCS =pAd->MlmeAux.AddHtInfo.MCSSet[0]+(pAd->MlmeAux.AddHtInfo.MCSSet[1]<<8)+(StbcMcs<<16);
		if ((pAd->CommonCfg.DesiredHtPhy.TxSTBC) && (pRtHtCap->RxSTBC) && (pAd->Antenna.field.TxPath == 2))
			pMaxHtPhy->field.STBC = STBC_USE;
		else
			pMaxHtPhy->field.STBC = STBC_NONE;
	}
	else
#endif /* CONFIG_STA_SUPPORT */
	{
		if ((!pDesireHtPhy) || pDesireHtPhy->bHtEnable == false)
			return;

		pRtHtCap = &pAd->CommonCfg.DesiredHtPhy;
		StbcMcs = (u8)pAd->CommonCfg.AddHTInfo.AddHtInfo3.StbcMcs;
		BasicMCS = pAd->CommonCfg.AddHTInfo.MCSSet[0]+(pAd->CommonCfg.AddHTInfo.MCSSet[1]<<8)+(StbcMcs<<16);
		if ((pAd->CommonCfg.DesiredHtPhy.TxSTBC) && (pAd->Antenna.field.TxPath >= 2))
			pMaxHtPhy->field.STBC = STBC_USE;
		else
			pMaxHtPhy->field.STBC = STBC_NONE;
	}

	/* Decide MAX ht rate.*/
	if ((pRtHtCap->GF) && (pAd->CommonCfg.DesiredHtPhy.GF))
		pMaxHtPhy->field.MODE = MODE_HTGREENFIELD;
	else
		pMaxHtPhy->field.MODE = MODE_HTMIX;

    if ((pAd->CommonCfg.DesiredHtPhy.ChannelWidth) && (pRtHtCap->ChannelWidth))
		pMaxHtPhy->field.BW = BW_40;
	else
		pMaxHtPhy->field.BW = BW_20;

    if (pMaxHtPhy->field.BW == BW_20)
		pMaxHtPhy->field.ShortGI = (pAd->CommonCfg.DesiredHtPhy.ShortGIfor20 & pRtHtCap->ShortGIfor20);
	else
		pMaxHtPhy->field.ShortGI = (pAd->CommonCfg.DesiredHtPhy.ShortGIfor40 & pRtHtCap->ShortGIfor40);

	if (pDesireHtPhy->MCSSet[4] != 0)
	{
		pMaxHtPhy->field.MCS = 32;
	}

	pMaxHtPhy->field.MCS = get_ht_max_mcs(pAd, &pDesireHtPhy->MCSSet[0],
											&pActiveHtPhy->MCSSet[0]);

	/* Copy MIN ht rate.  rt2860???*/
	pMinHtPhy->field.BW = BW_20;
	pMinHtPhy->field.MCS = 0;
	pMinHtPhy->field.STBC = 0;
	pMinHtPhy->field.ShortGI = 0;
	/*If STA assigns fixed rate. update to fixed here.*/
#ifdef CONFIG_STA_SUPPORT
	if ( (pAd->OpMode == OPMODE_STA) && (pDesireHtPhy->MCSSet[0] != 0xff)
		)
	{
		char i;
		u8 j, bitmask;

		if (pDesireHtPhy->MCSSet[4] != 0)
		{
			pMaxHtPhy->field.MCS = 32;
			pMinHtPhy->field.MCS = 32;
			DBGPRINT(RT_DEBUG_TRACE,("%s():<=== Use Fixed MCS = %d\n",__FUNCTION__, pMinHtPhy->field.MCS));
		}

		for (i=23; (char)i >= 0; i--)
		{
			j = i/8;
			bitmask = (1<<(i-(j*8)));
			if ( (pDesireHtPhy->MCSSet[j] & bitmask) && (pActiveHtPhy->MCSSet[j] & bitmask))
			{
				pMaxHtPhy->field.MCS = i;
				pMinHtPhy->field.MCS = i;
				break;
			}
			if (i==0)
				break;
		}
	}
#endif /* CONFIG_STA_SUPPORT */


	/* Decide ht rate*/
	pHtPhy->field.STBC = pMaxHtPhy->field.STBC;
	pHtPhy->field.BW = pMaxHtPhy->field.BW;
	pHtPhy->field.MODE = pMaxHtPhy->field.MODE;
	pHtPhy->field.MCS = pMaxHtPhy->field.MCS;
	pHtPhy->field.ShortGI = pMaxHtPhy->field.ShortGI;

	/* use default now. rt2860*/
	if (pDesireHtPhy->MCSSet[0] != 0xff)
		*auto_rate_cur_p = false;
	else
		*auto_rate_cur_p = true;

	DBGPRINT(RT_DEBUG_TRACE, (" %s():<---.AMsduSize = %d  \n", __FUNCTION__, pAd->CommonCfg.DesiredHtPhy.AmsduSize ));
	DBGPRINT(RT_DEBUG_TRACE,("TX: MCS[0] = %x (choose %d), BW = %d, ShortGI = %d, MODE = %d,  \n", pActiveHtPhy->MCSSet[0],pHtPhy->field.MCS,
		pHtPhy->field.BW, pHtPhy->field.ShortGI, pHtPhy->field.MODE));
	DBGPRINT(RT_DEBUG_TRACE,("%s():<=== \n", __FUNCTION__));
}


void BATableInit(
	struct rtmp_adapter *pAd,
    BA_TABLE *Tab)
{
	int i;

	Tab->numAsOriginator = 0;
	Tab->numAsRecipient = 0;
	Tab->numDoneOriginator = 0;
	spin_lock_init(&pAd->BATabLock);
	for (i = 0; i < MAX_LEN_OF_BA_REC_TABLE; i++)
	{
		Tab->BARecEntry[i].REC_BA_Status = Recipient_NONE;
		spin_lock_init(&(Tab->BARecEntry[i].RxReRingLock));
	}
	for (i = 0; i < MAX_LEN_OF_BA_ORI_TABLE; i++)
	{
		Tab->BAOriEntry[i].ORI_BA_Status = Originator_NONE;
	}
}

void BATableExit(
	struct rtmp_adapter*pAd)
{
	int i;

	for(i=0; i<MAX_LEN_OF_BA_REC_TABLE; i++)
	{
		;
	}
}
#endif /* DOT11_N_SUPPORT */

/* IRQL = DISPATCH_LEVEL*/
void MlmeRadioOff(
	struct rtmp_adapter *pAd)
{
	RTMP_MLME_RADIO_OFF(pAd);
}

/* IRQL = DISPATCH_LEVEL*/
void MlmeRadioOn(
	struct rtmp_adapter *pAd)
{
	RTMP_MLME_RADIO_ON(pAd);
}

/*
===========================================================================================
	bss_table.c
===========================================================================================
*/


/*! \brief initialize BSS table
 *	\param p_tab pointer to the table
 *	\return none
 *	\pre
 *	\post

 IRQL = PASSIVE_LEVEL
 IRQL = DISPATCH_LEVEL

 */
void BssTableInit(BSS_TABLE *Tab)
{
	int i;

	Tab->BssNr = 0;
	Tab->BssOverlapNr = 0;

	for (i = 0; i < MAX_LEN_OF_BSS_TABLE; i++)
	{
		u8 *pOldAddr = Tab->BssEntry[i].pVarIeFromProbRsp;

		memset(&Tab->BssEntry[i], 0, sizeof(BSS_ENTRY));

		Tab->BssEntry[i].Rssi = -127;	/* initial the rssi as a minimum value */
		if (pOldAddr)
		{
			memset(pOldAddr, 0, MAX_VIE_LEN);
			Tab->BssEntry[i].pVarIeFromProbRsp = pOldAddr;
		}
	}
}


/*! \brief search the BSS table by SSID
 *	\param p_tab pointer to the bss table
 *	\param ssid SSID string
 *	\return index of the table, BSS_NOT_FOUND if not in the table
 *	\pre
 *	\post
 *	\note search by sequential search

 IRQL = DISPATCH_LEVEL

 */
unsigned long BssTableSearch(
	BSS_TABLE *Tab,
	u8 * pBssid,
	u8  Channel)
{
	u8 i;

	for (i = 0; i < Tab->BssNr; i++)
	{

		/*
			Some AP that support A/B/G mode that may used the same BSSID on 11A and 11B/G.
			We should distinguish this case.
		*/
		if ((((Tab->BssEntry[i].Channel <= 14) && (Channel <= 14)) ||
			 ((Tab->BssEntry[i].Channel > 14) && (Channel > 14))) &&
			MAC_ADDR_EQUAL(Tab->BssEntry[i].Bssid, pBssid))
		{
			return i;
		}
	}
	return (unsigned long)BSS_NOT_FOUND;
}

unsigned long BssSsidTableSearch(
	BSS_TABLE *Tab,
	u8 * pBssid,
	u8 * pSsid,
	u8  SsidLen,
	u8  Channel)
{
	u8 i;

	for (i = 0; i < Tab->BssNr; i++)
	{

		/* Some AP that support A/B/G mode that may used the same BSSID on 11A and 11B/G.*/
		/* We should distinguish this case.*/
		/*		*/
		if ((((Tab->BssEntry[i].Channel <= 14) && (Channel <= 14)) ||
			 ((Tab->BssEntry[i].Channel > 14) && (Channel > 14))) &&
			MAC_ADDR_EQUAL(Tab->BssEntry[i].Bssid, pBssid) &&
			SSID_EQUAL(pSsid, SsidLen, Tab->BssEntry[i].Ssid, Tab->BssEntry[i].SsidLen))
		{
			return i;
		}
	}
	return (unsigned long)BSS_NOT_FOUND;
}

unsigned long BssTableSearchWithSSID(
	BSS_TABLE *Tab,
	u8 * Bssid,
	u8 * pSsid,
	u8  SsidLen,
	u8  Channel)
{
	u8 i;

	for (i = 0; i < Tab->BssNr; i++)
	{
		if ((((Tab->BssEntry[i].Channel <= 14) && (Channel <= 14)) ||
			((Tab->BssEntry[i].Channel > 14) && (Channel > 14))) &&
			MAC_ADDR_EQUAL(&(Tab->BssEntry[i].Bssid), Bssid) &&
			(SSID_EQUAL(pSsid, SsidLen, Tab->BssEntry[i].Ssid, Tab->BssEntry[i].SsidLen) ||
			(memcmp(pSsid, ZeroSsid, SsidLen) == 0) ||
			(memcmp(Tab->BssEntry[i].Ssid, ZeroSsid, Tab->BssEntry[i].SsidLen) == 0)))
		{
			return i;
		}
	}
	return (unsigned long)BSS_NOT_FOUND;
}


unsigned long BssSsidTableSearchBySSID(
	BSS_TABLE *Tab,
	u8 * pSsid,
	u8  SsidLen)
{
	u8 i;

	for (i = 0; i < Tab->BssNr; i++)
	{
		if (SSID_EQUAL(pSsid, SsidLen, Tab->BssEntry[i].Ssid, Tab->BssEntry[i].SsidLen))
		{
			return i;
		}
	}
	return (unsigned long)BSS_NOT_FOUND;
}


/* IRQL = DISPATCH_LEVEL*/
void BssTableDeleteEntry(
	BSS_TABLE *Tab,
	u8 *  pBssid,
	u8   Channel)
{
	u8 i, j;

	for (i = 0; i < Tab->BssNr; i++)
	{
		if ((Tab->BssEntry[i].Channel == Channel) &&
			(MAC_ADDR_EQUAL(Tab->BssEntry[i].Bssid, pBssid)))
		{
			u8 *pOldAddr = NULL;

			for (j = i; j < Tab->BssNr - 1; j++)
			{
				pOldAddr = Tab->BssEntry[j].pVarIeFromProbRsp;
				memmove(&(Tab->BssEntry[j]), &(Tab->BssEntry[j + 1]), sizeof(BSS_ENTRY));
				if (pOldAddr)
				{
					memset(pOldAddr, 0, MAX_VIE_LEN);
					memmove(pOldAddr,
								   Tab->BssEntry[j + 1].pVarIeFromProbRsp,
								   Tab->BssEntry[j + 1].VarIeFromProbeRspLen);
					Tab->BssEntry[j].pVarIeFromProbRsp = pOldAddr;
				}
			}

			pOldAddr = Tab->BssEntry[Tab->BssNr - 1].pVarIeFromProbRsp;
			memset(&(Tab->BssEntry[Tab->BssNr - 1]), 0, sizeof(BSS_ENTRY));
			if (pOldAddr)
			{
				memset(pOldAddr, 0, MAX_VIE_LEN);
				Tab->BssEntry[Tab->BssNr - 1].pVarIeFromProbRsp = pOldAddr;
			}

			Tab->BssNr -= 1;
			return;
		}
	}
}


/*! \brief
 *	\param
 *	\return
 *	\pre
 *	\post

 IRQL = DISPATCH_LEVEL

 */
void BssEntrySet(
	struct rtmp_adapter *pAd,
	BSS_ENTRY *pBss,
	BCN_IE_LIST *ie_list,
	char Rssi,
	unsigned short LengthVIE,
	PNDIS_802_11_VARIABLE_IEs pVIE)
{
	memcpy(pBss->Bssid, ie_list->Bssid, ETH_ALEN);
	/* Default Hidden SSID to be true, it will be turned to false after coping SSID*/
	pBss->Hidden = 1;
	if (ie_list->SsidLen > 0)
	{
		/* For hidden SSID AP, it might send beacon with SSID len equal to 0*/
		/* Or send beacon /probe response with SSID len matching real SSID length,*/
		/* but SSID is all zero. such as "00-00-00-00" with length 4.*/
		/* We have to prevent this case overwrite correct table*/
		if (memcmp(ie_list->Ssid, ZeroSsid, ie_list->SsidLen) != 0)
		{
			memset(pBss->Ssid, 0, MAX_LEN_OF_SSID);
			memmove(pBss->Ssid, ie_list->Ssid, ie_list->SsidLen);
			pBss->SsidLen = ie_list->SsidLen;
			pBss->Hidden = 0;
		}
	}
	else
	{
		/* avoid  Hidden SSID form beacon to overwirite correct SSID from probe response */
		if (memcmp(pBss->Ssid, ZeroSsid, pBss->SsidLen) == 0)
		{
			memset(pBss->Ssid, 0, MAX_LEN_OF_SSID);
			pBss->SsidLen = 0;
		}
	}

	pBss->BssType = ie_list->BssType;
	pBss->BeaconPeriod = ie_list->BeaconPeriod;
	if (ie_list->BssType == BSS_INFRA)
	{
		if (ie_list->CfParm.bValid)
		{
			pBss->CfpCount = ie_list->CfParm.CfpCount;
			pBss->CfpPeriod = ie_list->CfParm.CfpPeriod;
			pBss->CfpMaxDuration = ie_list->CfParm.CfpMaxDuration;
			pBss->CfpDurRemaining = ie_list->CfParm.CfpDurRemaining;
		}
	}
	else
	{
		pBss->AtimWin = ie_list->AtimWin;
	}

	NdisGetSystemUpTime(&pBss->LastBeaconRxTime);
	pBss->CapabilityInfo = ie_list->CapabilityInfo;
	/* The privacy bit indicate security is ON, it maight be WEP, TKIP or AES*/
	/* Combine with AuthMode, they will decide the connection methods.*/
	pBss->Privacy = CAP_IS_PRIVACY_ON(pBss->CapabilityInfo);
	ASSERT(ie_list->SupRateLen <= MAX_LEN_OF_SUPPORTED_RATES);
	if (ie_list->SupRateLen <= MAX_LEN_OF_SUPPORTED_RATES)
		memmove(pBss->SupRate, ie_list->SupRate, ie_list->SupRateLen);
	else
		memmove(pBss->SupRate, ie_list->SupRate, MAX_LEN_OF_SUPPORTED_RATES);
	pBss->SupRateLen = ie_list->SupRateLen;
	ASSERT(ie_list->ExtRateLen <= MAX_LEN_OF_SUPPORTED_RATES);
	if (ie_list->ExtRateLen > MAX_LEN_OF_SUPPORTED_RATES)
		ie_list->ExtRateLen = MAX_LEN_OF_SUPPORTED_RATES;
	memmove(pBss->ExtRate, ie_list->ExtRate, ie_list->ExtRateLen);
	pBss->NewExtChanOffset = ie_list->NewExtChannelOffset;
	pBss->ExtRateLen = ie_list->ExtRateLen;
	pBss->Channel = ie_list->Channel;
	pBss->CentralChannel = ie_list->Channel;
	pBss->Rssi = Rssi;
	/* Update CkipFlag. if not exists, the value is 0x0*/
	pBss->CkipFlag = ie_list->CkipFlag;

	/* New for microsoft Fixed IEs*/
	memmove(pBss->FixIEs.Timestamp, &ie_list->TimeStamp, 8);
	pBss->FixIEs.BeaconInterval = ie_list->BeaconPeriod;
	pBss->FixIEs.Capabilities = ie_list->CapabilityInfo;

	/* New for microsoft Variable IEs*/
	if (LengthVIE != 0)
	{
		pBss->VarIELen = LengthVIE;
		memmove(pBss->VarIEs, pVIE, pBss->VarIELen);
	}
	else
	{
		pBss->VarIELen = 0;
	}

	pBss->AddHtInfoLen = 0;
	pBss->HtCapabilityLen = 0;
#ifdef DOT11_N_SUPPORT
	if (ie_list->HtCapabilityLen> 0)
	{
		pBss->HtCapabilityLen = ie_list->HtCapabilityLen;
		memmove(&pBss->HtCapability, &ie_list->HtCapability, ie_list->HtCapabilityLen);
		if (ie_list->AddHtInfoLen > 0)
		{
			pBss->AddHtInfoLen = ie_list->AddHtInfoLen;
			memmove(&pBss->AddHtInfo, &ie_list->AddHtInfo, ie_list->AddHtInfoLen);

			pBss->CentralChannel = get_cent_ch_by_htinfo(pAd, &ie_list->AddHtInfo,
											&ie_list->HtCapability);
		}

#ifdef DOT11_VHT_AC
		if (ie_list->vht_cap_len) {
			memmove(&pBss->vht_cap_ie, &ie_list->vht_cap_ie, ie_list->vht_cap_len);
			pBss->vht_cap_len = ie_list->vht_cap_len;
		}

		if (ie_list->vht_op_len) {
			VHT_OP_IE *vht_op;

			memmove(&pBss->vht_op_ie, &ie_list->vht_op_ie, ie_list->vht_op_len);
			pBss->vht_op_len = ie_list->vht_op_len;
			vht_op = &ie_list->vht_op_ie;
			if ((vht_op->vht_op_info.ch_width > 0) &&
				(ie_list->AddHtInfo.AddHtInfo.ExtChanOffset != EXTCHA_NONE) &&
				(ie_list->HtCapability.HtCapInfo.ChannelWidth == BW_40) &&
				(pBss->CentralChannel != ie_list->AddHtInfo.ControlChan))
			{
				u8 cent_ch;

				cent_ch = vht_cent_ch_freq(pAd, ie_list->AddHtInfo.ControlChan);
				DBGPRINT(RT_DEBUG_TRACE, ("%s():VHT cent_ch=%d, vht_op_info->center_freq_1=%d, Bss->CentralChannel=%d, change from CentralChannel to cent_ch!\n",
											__FUNCTION__, cent_ch, vht_op->vht_op_info.center_freq_1, pBss->CentralChannel));
				pBss->CentralChannel = vht_op->vht_op_info.center_freq_1;
			}
		}
#endif /* DOT11_VHT_AC */
	}
#endif /* DOT11_N_SUPPORT */

	BssCipherParse(pBss);

	/* new for QOS*/
	if (ie_list->EdcaParm.bValid)
		memmove(&pBss->EdcaParm, &ie_list->EdcaParm, sizeof(EDCA_PARM));
	else
		pBss->EdcaParm.bValid = false;
	if (ie_list->QosCapability.bValid)
		memmove(&pBss->QosCapability, &ie_list->QosCapability, sizeof(QOS_CAPABILITY_PARM));
	else
		pBss->QosCapability.bValid = false;
	if (ie_list->QbssLoad.bValid)
		memmove(&pBss->QbssLoad, &ie_list->QbssLoad, sizeof(QBSS_LOAD_PARM));
	else
		pBss->QbssLoad.bValid = false;

	{
		PEID_STRUCT     pEid;
		unsigned short          Length = 0;


#ifdef CONFIG_STA_SUPPORT
		memset(&pBss->WpaIE.IE[0], 0, MAX_CUSTOM_LEN);
		memset(&pBss->RsnIE.IE[0], 0, MAX_CUSTOM_LEN);
		memset(&pBss->WpsIE.IE[0], 0, MAX_CUSTOM_LEN);
		pBss->WpaIE.IELen = 0;
		pBss->RsnIE.IELen = 0;
		pBss->WpsIE.IELen = 0;
#ifdef EXT_BUILD_CHANNEL_LIST
		memset(&pBss->CountryString[0], 0, 3);
		pBss->bHasCountryIE = false;
#endif /* EXT_BUILD_CHANNEL_LIST */
#endif /* CONFIG_STA_SUPPORT */
		pEid = (PEID_STRUCT) pVIE;
		while ((Length + 2 + (unsigned short)pEid->Len) <= LengthVIE)
		{
#define WPS_AP		0x01
			switch(pEid->Eid)
			{
				case IE_WPA:
					if (memcmp(pEid->Octet, WPS_OUI, 4) == 0)
					{
#ifdef CONFIG_STA_SUPPORT
						if ((pEid->Len + 2) > MAX_CUSTOM_LEN)
						{
							pBss->WpsIE.IELen = 0;
							break;
						}
						pBss->WpsIE.IELen = pEid->Len + 2;
						memmove(pBss->WpsIE.IE, pEid, pBss->WpsIE.IELen);
#endif /* CONFIG_STA_SUPPORT */
						break;
					}
#ifdef CONFIG_STA_SUPPORT
					if (memcmp(pEid->Octet, WPA_OUI, 4) == 0)
					{
						if ((pEid->Len + 2) > MAX_CUSTOM_LEN)
						{
							pBss->WpaIE.IELen = 0;
							break;
						}
						pBss->WpaIE.IELen = pEid->Len + 2;
						memmove(pBss->WpaIE.IE, pEid, pBss->WpaIE.IELen);
					}
#endif /* CONFIG_STA_SUPPORT */
					break;

#ifdef CONFIG_STA_SUPPORT
				case IE_RSN:
					if (memcmp(pEid->Octet + 2, RSN_OUI, 3) == 0)
					{
						if ((pEid->Len + 2) > MAX_CUSTOM_LEN)
						{
							pBss->RsnIE.IELen = 0;
							break;
						}
						pBss->RsnIE.IELen = pEid->Len + 2;
						memmove(pBss->RsnIE.IE, pEid, pBss->RsnIE.IELen);
					}
					break;
#ifdef EXT_BUILD_CHANNEL_LIST
				case IE_COUNTRY:
					memmove(&pBss->CountryString[0], pEid->Octet, 3);
					pBss->bHasCountryIE = true;
					break;
#endif /* EXT_BUILD_CHANNEL_LIST */
#endif /* CONFIG_STA_SUPPORT */
			}
			Length = Length + 2 + (unsigned short)pEid->Len;  /* Eid[1] + Len[1]+ content[Len]*/
			pEid = (PEID_STRUCT)((u8 *)pEid + 2 + pEid->Len);
		}
	}
}



/*!
 *	\brief insert an entry into the bss table
 *	\param p_tab The BSS table
 *	\param Bssid BSSID
 *	\param ssid SSID
 *	\param ssid_len Length of SSID
 *	\param bss_type
 *	\param beacon_period
 *	\param timestamp
 *	\param p_cf
 *	\param atim_win
 *	\param cap
 *	\param rates
 *	\param rates_len
 *	\param channel_idx
 *	\return none
 *	\pre
 *	\post
 *	\note If SSID is identical, the old entry will be replaced by the new one

 IRQL = DISPATCH_LEVEL

 */
unsigned long BssTableSetEntry(
	struct rtmp_adapter *pAd,
	BSS_TABLE *Tab,
	BCN_IE_LIST *ie_list,
	char Rssi,
	unsigned short LengthVIE,
	PNDIS_802_11_VARIABLE_IEs pVIE)
{
	unsigned long	Idx;
#ifdef APCLI_SUPPORT
	bool bInsert = false;
	PAPCLI_STRUCT pApCliEntry = NULL;
	u8 i;
#endif /* APCLI_SUPPORT */


	Idx = BssTableSearch(Tab, ie_list->Bssid, ie_list->Channel);
	if (Idx == BSS_NOT_FOUND)
	{
		if (Tab->BssNr >= MAX_LEN_OF_BSS_TABLE)
	    {
			/*
				It may happen when BSS Table was full.
				The desired AP will not be added into BSS Table
				In this case, if we found the desired AP then overwrite BSS Table.
			*/
#ifdef APCLI_SUPPORT
			for (i = 0; i < pAd->ApCfg.ApCliNum; i++)
			{
				pApCliEntry = &pAd->ApCfg.ApCliTab[i];
				if (MAC_ADDR_EQUAL(pApCliEntry->ApCliMlmeAux.Bssid, ie_list->Bssid)
					|| SSID_EQUAL(pApCliEntry->ApCliMlmeAux.Ssid, pApCliEntry->ApCliMlmeAux.SsidLen, ie_list->Ssid, ie_list->SsidLen))
				{
					bInsert = true;
					break;
				}
			}
#endif /* APCLI_SUPPORT */
			if(!OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED) ||
				!OPSTATUS_TEST_FLAG(pAd, fOP_AP_STATUS_MEDIA_STATE_CONNECTED))
			{
				if (MAC_ADDR_EQUAL(pAd->MlmeAux.Bssid, ie_list->Bssid) ||
					SSID_EQUAL(pAd->MlmeAux.Ssid, pAd->MlmeAux.SsidLen, ie_list->Ssid, ie_list->SsidLen)
#ifdef APCLI_SUPPORT
					|| bInsert
#endif /* APCLI_SUPPORT */
					)
				{
					Idx = Tab->BssOverlapNr;
					BssEntrySet(pAd, &Tab->BssEntry[Idx], ie_list, Rssi, LengthVIE, pVIE);
					Tab->BssOverlapNr += 1;
					Tab->BssOverlapNr = Tab->BssOverlapNr % MAX_LEN_OF_BSS_TABLE;
				}
				return Idx;
			}
			else
			{
				return BSS_NOT_FOUND;
			}
		}
		Idx = Tab->BssNr;
		BssEntrySet(pAd, &Tab->BssEntry[Idx], ie_list, Rssi, LengthVIE, pVIE);
		Tab->BssNr++;
	}
	else
	{
		BssEntrySet(pAd, &Tab->BssEntry[Idx], ie_list, Rssi, LengthVIE, pVIE);
	}

	return Idx;
}


#ifdef CONFIG_STA_SUPPORT
#ifdef DOT11_N_SUPPORT
#ifdef DOT11N_DRAFT3
void  TriEventInit(
	struct rtmp_adapter *pAd)
{
	u8 	i;

	for (i = 0;i < MAX_TRIGGER_EVENT;i++)
		pAd->CommonCfg.TriggerEventTab.EventA[i].bValid = false;

	pAd->CommonCfg.TriggerEventTab.EventANo = 0;
	pAd->CommonCfg.TriggerEventTab.EventBCountDown = 0;
}

int TriEventTableSetEntry(
	struct rtmp_adapter *pAd,
	TRIGGER_EVENT_TAB *Tab,
	u8 *pBssid,
	HT_CAPABILITY_IE *pHtCapability,
	u8 		HtCapabilityLen,
	u8 		RegClass,
	u8 ChannelNo)
{
	/* Event A, legacy AP exist.*/
	if (HtCapabilityLen == 0)
	{
		u8 index;

		/*
			Check if we already set this entry in the Event Table.
		*/
		for (index = 0; index<MAX_TRIGGER_EVENT; index++)
		{
			if ((Tab->EventA[index].bValid == true) &&
				(Tab->EventA[index].Channel == ChannelNo) &&
				(Tab->EventA[index].RegClass == RegClass)
			)
			{
				return 0;
			}
		}

		/*
			If not set, add it to the Event table
		*/
		if (Tab->EventANo < MAX_TRIGGER_EVENT)
		{
			memmove(Tab->EventA[Tab->EventANo].BSSID, pBssid, 6);
			Tab->EventA[Tab->EventANo].bValid = true;
			Tab->EventA[Tab->EventANo].Channel = ChannelNo;
			if (RegClass != 0)
			{
				/* Beacon has Regulatory class IE. So use beacon's*/
				Tab->EventA[Tab->EventANo].RegClass = RegClass;
			}
			else
			{
				/* Use Station's Regulatory class instead.*/
				/* If no Reg Class in Beacon, set to "unknown"*/
				/* TODO:  Need to check if this's valid*/
				Tab->EventA[Tab->EventANo].RegClass = 0; /* ????????????????? need to check*/
			}
			Tab->EventANo ++;
		}
	}
	else if (pHtCapability->HtCapInfo.Forty_Mhz_Intolerant)
	{
		/* Event B.   My BSS beacon has Intolerant40 bit set*/
		Tab->EventBCountDown = pAd->CommonCfg.Dot11BssWidthChanTranDelay;
	}

	return 0;
}
#endif /* DOT11N_DRAFT3 */
#endif /* DOT11_N_SUPPORT */

/* IRQL = DISPATCH_LEVEL*/
void BssTableSsidSort(
	struct rtmp_adapter *pAd,
	BSS_TABLE *OutTab,
	char Ssid[],
	u8 SsidLen)
{
	int i;
	BssTableInit(OutTab);

	if ((SsidLen == 0) &&
		(pAd->StaCfg.bAutoConnectIfNoSSID == false))
		return;

	for (i = 0; i < pAd->ScanTab.BssNr; i++)
	{
		BSS_ENTRY *pInBss = &pAd->ScanTab.BssEntry[i];
		bool bIsHiddenApIncluded = false;

		if ( ((pAd->CommonCfg.bIEEE80211H == 1) &&
				(pAd->MlmeAux.Channel > 14) &&
				 RadarChannelCheck(pAd, pInBss->Channel))
            )
		{
			if (pInBss->Hidden)
				bIsHiddenApIncluded = true;
		}


		if ((pInBss->BssType == pAd->StaCfg.BssType) &&
			(SSID_EQUAL(Ssid, SsidLen, pInBss->Ssid, pInBss->SsidLen) || bIsHiddenApIncluded))
		{
			BSS_ENTRY *pOutBss = &OutTab->BssEntry[OutTab->BssNr];

#ifdef WPA_SUPPLICANT_SUPPORT
			if (pAd->StaCfg.WpaSupplicantUP & 0x80)
			{
				/* copy matching BSS from InTab to OutTab*/
				memmove(pOutBss, pInBss, sizeof(BSS_ENTRY));
				OutTab->BssNr++;
				continue;
			}
#endif /* WPA_SUPPLICANT_SUPPORT */


#ifdef EXT_BUILD_CHANNEL_LIST
			/* If no Country IE exists no Connection will be established when IEEE80211dClientMode is strict.*/
			if ((pAd->StaCfg.IEEE80211dClientMode == Rt802_11_D_Strict) &&
				(pInBss->bHasCountryIE == false))
			{
				DBGPRINT(RT_DEBUG_TRACE,("StaCfg.IEEE80211dClientMode == Rt802_11_D_Strict, but this AP doesn't have country IE.\n"));
				continue;
			}
#endif /* EXT_BUILD_CHANNEL_LIST */

#ifdef DOT11_N_SUPPORT
			/* 2.4G/5G N only mode*/
			if ((pInBss->HtCapabilityLen == 0) &&
				(WMODE_HT_ONLY(pAd->CommonCfg.PhyMode)))
			{
				DBGPRINT(RT_DEBUG_TRACE,("STA is in N-only Mode, this AP don't have Ht capability in Beacon.\n"));
				continue;
			}

			if ((pAd->CommonCfg.PhyMode == (WMODE_G | WMODE_GN)) &&
				((pInBss->SupRateLen + pInBss->ExtRateLen) < 12))
			{
				DBGPRINT(RT_DEBUG_TRACE,("STA is in GN-only Mode, this AP is in B mode.\n"));
				continue;
			}
#endif /* DOT11_N_SUPPORT */



			/* New for WPA2*/
			/* Check the Authmode first*/
			if (pAd->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
			{
				/* Check AuthMode and AuthModeAux for matching, in case AP support dual-mode*/
				if ((pAd->StaCfg.AuthMode != pInBss->AuthMode) && (pAd->StaCfg.AuthMode != pInBss->AuthModeAux))
					/* None matched*/
					continue;

				/* Check cipher suite, AP must have more secured cipher than station setting*/
				if ((pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA) || (pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPAPSK))
				{
					/* If it's not mixed mode, we should only let BSS pass with the same encryption*/
					if (pInBss->WPA.bMixMode == false)
						if (pAd->StaCfg.WepStatus != pInBss->WPA.GroupCipher)
							continue;

					/* check group cipher*/
					if ((pAd->StaCfg.WepStatus < pInBss->WPA.GroupCipher) &&
						(pInBss->WPA.GroupCipher != Ndis802_11GroupWEP40Enabled) &&
						(pInBss->WPA.GroupCipher != Ndis802_11GroupWEP104Enabled))
						continue;

					/* check pairwise cipher, skip if none matched*/
					/* If profile set to AES, let it pass without question.*/
					/* If profile set to TKIP, we must find one mateched*/
					if ((pAd->StaCfg.WepStatus == Ndis802_11Encryption2Enabled) &&
						(pAd->StaCfg.WepStatus != pInBss->WPA.PairCipher) &&
						(pAd->StaCfg.WepStatus != pInBss->WPA.PairCipherAux))
						continue;
				}
				else if ((pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA2) || (pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA2PSK))
				{
					/* If it's not mixed mode, we should only let BSS pass with the same encryption*/
					if (pInBss->WPA2.bMixMode == false)
						if (pAd->StaCfg.WepStatus != pInBss->WPA2.GroupCipher)
							continue;

					/* check group cipher*/
					if ((pAd->StaCfg.WepStatus < pInBss->WPA.GroupCipher) &&
						(pInBss->WPA2.GroupCipher != Ndis802_11GroupWEP40Enabled) &&
						(pInBss->WPA2.GroupCipher != Ndis802_11GroupWEP104Enabled))
						continue;

					/* check pairwise cipher, skip if none matched*/
					/* If profile set to AES, let it pass without question.*/
					/* If profile set to TKIP, we must find one mateched*/
					if ((pAd->StaCfg.WepStatus == Ndis802_11Encryption2Enabled) &&
						(pAd->StaCfg.WepStatus != pInBss->WPA2.PairCipher) &&
						(pAd->StaCfg.WepStatus != pInBss->WPA2.PairCipherAux))
						continue;
				}
			}
			/* Bss Type matched, SSID matched. */
			/* We will check wepstatus for qualification Bss*/
			else if (pAd->StaCfg.WepStatus != pInBss->WepStatus)
			{
				DBGPRINT(RT_DEBUG_TRACE,("StaCfg.WepStatus=%d, while pInBss->WepStatus=%d\n", pAd->StaCfg.WepStatus, pInBss->WepStatus));

				/* For the SESv2 case, we will not qualify WepStatus.*/

				if (!pInBss->bSES)
					continue;
			}

			/* Since the AP is using hidden SSID, and we are trying to connect to ANY*/
			/* It definitely will fail. So, skip it.*/
			/* CCX also require not even try to connect it!!*/
			if (SsidLen == 0)
				continue;

			/* copy matching BSS from InTab to OutTab*/
			memmove(pOutBss, pInBss, sizeof(BSS_ENTRY));

			OutTab->BssNr++;
		}
		else if ((pInBss->BssType == pAd->StaCfg.BssType) && (SsidLen == 0))
		{
			BSS_ENTRY *pOutBss = &OutTab->BssEntry[OutTab->BssNr];


#ifdef DOT11_N_SUPPORT
			/* 2.4G/5G N only mode*/
			if ((pInBss->HtCapabilityLen == 0) &&
				WMODE_HT_ONLY(pAd->CommonCfg.PhyMode))
			{
				DBGPRINT(RT_DEBUG_TRACE,("STA is in N-only Mode, this AP don't have Ht capability in Beacon.\n"));
				continue;
			}

			if ((pAd->CommonCfg.PhyMode == (WMODE_G | WMODE_GN)) &&
				((pInBss->SupRateLen + pInBss->ExtRateLen) < 12))
			{
				DBGPRINT(RT_DEBUG_TRACE,("STA is in GN-only Mode, this AP is in B mode.\n"));
				continue;
			}
#endif /* DOT11_N_SUPPORT */

			/* New for WPA2*/
			/* Check the Authmode first*/
			if (pAd->StaCfg.AuthMode >= Ndis802_11AuthModeWPA)
			{
				/* Check AuthMode and AuthModeAux for matching, in case AP support dual-mode*/
				if ((pAd->StaCfg.AuthMode != pInBss->AuthMode) && (pAd->StaCfg.AuthMode != pInBss->AuthModeAux))
					/* None matched*/
					continue;

				/* Check cipher suite, AP must have more secured cipher than station setting*/
				if ((pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA) || (pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPAPSK))
				{
					/* If it's not mixed mode, we should only let BSS pass with the same encryption*/
					if (pInBss->WPA.bMixMode == false)
						if (pAd->StaCfg.WepStatus != pInBss->WPA.GroupCipher)
							continue;

					/* check group cipher*/
					if (pAd->StaCfg.WepStatus < pInBss->WPA.GroupCipher)
						continue;

					/* check pairwise cipher, skip if none matched*/
					/* If profile set to AES, let it pass without question.*/
					/* If profile set to TKIP, we must find one mateched*/
					if ((pAd->StaCfg.WepStatus == Ndis802_11Encryption2Enabled) &&
						(pAd->StaCfg.WepStatus != pInBss->WPA.PairCipher) &&
						(pAd->StaCfg.WepStatus != pInBss->WPA.PairCipherAux))
						continue;
				}
				else if ((pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA2) || (pAd->StaCfg.AuthMode == Ndis802_11AuthModeWPA2PSK))
				{
					/* If it's not mixed mode, we should only let BSS pass with the same encryption*/
					if (pInBss->WPA2.bMixMode == false)
						if (pAd->StaCfg.WepStatus != pInBss->WPA2.GroupCipher)
							continue;

					/* check group cipher*/
					if (pAd->StaCfg.WepStatus < pInBss->WPA2.GroupCipher)
						continue;

					/* check pairwise cipher, skip if none matched*/
					/* If profile set to AES, let it pass without question.*/
					/* If profile set to TKIP, we must find one mateched*/
					if ((pAd->StaCfg.WepStatus == Ndis802_11Encryption2Enabled) &&
						(pAd->StaCfg.WepStatus != pInBss->WPA2.PairCipher) &&
						(pAd->StaCfg.WepStatus != pInBss->WPA2.PairCipherAux))
						continue;
				}
			}
			/* Bss Type matched, SSID matched. */
			/* We will check wepstatus for qualification Bss*/
			else if (pAd->StaCfg.WepStatus != pInBss->WepStatus)
					continue;

			/* copy matching BSS from InTab to OutTab*/
			memmove(pOutBss, pInBss, sizeof(BSS_ENTRY));

			OutTab->BssNr++;
		}

		if (OutTab->BssNr >= MAX_LEN_OF_BSS_TABLE)
			break;
	}

	BssTableSortByRssi(OutTab);
}


/* IRQL = DISPATCH_LEVEL*/
void BssTableSortByRssi(
	BSS_TABLE *OutTab)
{
	int 	  i, j;
/*	BSS_ENTRY TmpBss;*/
	BSS_ENTRY *pTmpBss = NULL;


	/* allocate memory */
	pTmpBss = kmalloc(sizeof(BSS_ENTRY), GFP_ATOMIC);
	if (pTmpBss == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: Allocate memory fail!!!\n", __FUNCTION__));
		return;
	}

	for (i = 0; i < OutTab->BssNr - 1; i++)
	{
		for (j = i+1; j < OutTab->BssNr; j++)
		{
			if (OutTab->BssEntry[j].Rssi > OutTab->BssEntry[i].Rssi)
			{
				memmove(pTmpBss, &OutTab->BssEntry[j], sizeof(BSS_ENTRY));
				memmove(&OutTab->BssEntry[j], &OutTab->BssEntry[i], sizeof(BSS_ENTRY));
				memmove(&OutTab->BssEntry[i], pTmpBss, sizeof(BSS_ENTRY));
			}
		}
	}

	if (pTmpBss != NULL)
		kfree(pTmpBss);
}
#endif /* CONFIG_STA_SUPPORT */


void BssCipherParse(
	PBSS_ENTRY	pBss)
{
	PEID_STRUCT 		 pEid;
	u8 *			pTmp;
	PRSN_IE_HEADER_STRUCT			pRsnHeader;
	PCIPHER_SUITE_STRUCT			pCipher;
	PAKM_SUITE_STRUCT				pAKM;
	unsigned short							Count;
	int								Length;
	NDIS_802_11_ENCRYPTION_STATUS	TmpCipher;


	/* WepStatus will be reset later, if AP announce TKIP or AES on the beacon frame.*/

	if (pBss->Privacy)
	{
		pBss->WepStatus 	= Ndis802_11WEPEnabled;
	}
	else
	{
		pBss->WepStatus 	= Ndis802_11WEPDisabled;
	}
	/* Set default to disable & open authentication before parsing variable IE*/
	pBss->AuthMode		= Ndis802_11AuthModeOpen;
	pBss->AuthModeAux	= Ndis802_11AuthModeOpen;

	/* Init WPA setting*/
	pBss->WPA.PairCipher	= Ndis802_11WEPDisabled;
	pBss->WPA.PairCipherAux = Ndis802_11WEPDisabled;
	pBss->WPA.GroupCipher	= Ndis802_11WEPDisabled;
	pBss->WPA.RsnCapability = 0;
	pBss->WPA.bMixMode		= false;

	/* Init WPA2 setting*/
	pBss->WPA2.PairCipher	 = Ndis802_11WEPDisabled;
	pBss->WPA2.PairCipherAux = Ndis802_11WEPDisabled;
	pBss->WPA2.GroupCipher	 = Ndis802_11WEPDisabled;
	pBss->WPA2.RsnCapability = 0;
	pBss->WPA2.bMixMode 	 = false;


	Length = (int) pBss->VarIELen;

	while (Length > 0)
	{
		/* Parse cipher suite base on WPA1 & WPA2, they should be parsed differently*/
		pTmp = ((u8 *) pBss->VarIEs) + pBss->VarIELen - Length;
		pEid = (PEID_STRUCT) pTmp;
		switch (pEid->Eid)
		{
			case IE_WPA:
				if (memcmp(pEid->Octet, SES_OUI, 3) == 0 && (pEid->Len == 7))
				{
					pBss->bSES = true;
					break;
				}
				else if (memcmp(pEid->Octet, WPA_OUI, 4) != 0)
				{
					/* if unsupported vendor specific IE*/
					break;
				}
				/*
					Skip OUI, version, and multicast suite
					This part should be improved in the future when AP supported multiple cipher suite.
					For now, it's OK since almost all APs have fixed cipher suite supported.
				*/
				/* pTmp = (u8 *) pEid->Octet;*/
				pTmp   += 11;

				/*
					Cipher Suite Selectors from Spec P802.11i/D3.2 P26.
					Value	   Meaning
					0			None
					1			WEP-40
					2			Tkip
					3			WRAP
					4			AES
					5			WEP-104
				*/
				/* Parse group cipher*/
				switch (*pTmp)
				{
					case 1:
						pBss->WPA.GroupCipher = Ndis802_11GroupWEP40Enabled;
						break;
					case 5:
						pBss->WPA.GroupCipher = Ndis802_11GroupWEP104Enabled;
						break;
					case 2:
						pBss->WPA.GroupCipher = Ndis802_11Encryption2Enabled;
						break;
					case 4:
						pBss->WPA.GroupCipher = Ndis802_11Encryption3Enabled;
						break;
					default:
						break;
				}
				/* number of unicast suite*/
				pTmp   += 1;

				/* skip all unicast cipher suites*/
				/*Count = *(unsigned short *) pTmp;				*/
				Count = (pTmp[1]<<8) + pTmp[0];
				pTmp   += sizeof(unsigned short);

				/* Parsing all unicast cipher suite*/
				while (Count > 0)
				{
					/* Skip OUI*/
					pTmp += 3;
					TmpCipher = Ndis802_11WEPDisabled;
					switch (*pTmp)
					{
						case 1:
						case 5: /* Although WEP is not allowed in WPA related auth mode, we parse it anyway*/
							TmpCipher = Ndis802_11Encryption1Enabled;
							break;
						case 2:
							TmpCipher = Ndis802_11Encryption2Enabled;
							break;
						case 4:
							TmpCipher = Ndis802_11Encryption3Enabled;
							break;
						default:
							break;
					}
					if (TmpCipher > pBss->WPA.PairCipher)
					{
						/* Move the lower cipher suite to PairCipherAux*/
						pBss->WPA.PairCipherAux = pBss->WPA.PairCipher;
						pBss->WPA.PairCipher	= TmpCipher;
					}
					else
					{
						pBss->WPA.PairCipherAux = TmpCipher;
					}
					pTmp++;
					Count--;
				}

				/* 4. get AKM suite counts*/
				/*Count	= *(unsigned short *) pTmp;*/
				Count = (pTmp[1]<<8) + pTmp[0];
				pTmp   += sizeof(unsigned short);
				pTmp   += 3;

				switch (*pTmp)
				{
					case 1:
						/* Set AP support WPA-enterprise mode*/
						if (pBss->AuthMode == Ndis802_11AuthModeOpen)
							pBss->AuthMode = Ndis802_11AuthModeWPA;
						else
							pBss->AuthModeAux = Ndis802_11AuthModeWPA;
						break;
					case 2:
						/* Set AP support WPA-PSK mode*/
						if (pBss->AuthMode == Ndis802_11AuthModeOpen)
							pBss->AuthMode = Ndis802_11AuthModeWPAPSK;
						else
							pBss->AuthModeAux = Ndis802_11AuthModeWPAPSK;
						break;
					default:
						break;
				}
				pTmp   += 1;

				/* Fixed for WPA-None*/
				if (pBss->BssType == BSS_ADHOC)
				{
					pBss->AuthMode	  = Ndis802_11AuthModeWPANone;
					pBss->AuthModeAux = Ndis802_11AuthModeWPANone;
					pBss->WepStatus   = pBss->WPA.GroupCipher;
					/* Patched bugs for old driver*/
					if (pBss->WPA.PairCipherAux == Ndis802_11WEPDisabled)
						pBss->WPA.PairCipherAux = pBss->WPA.GroupCipher;
				}
				else
					pBss->WepStatus   = pBss->WPA.PairCipher;

				/* Check the Pair & Group, if different, turn on mixed mode flag*/
				if (pBss->WPA.GroupCipher != pBss->WPA.PairCipher)
					pBss->WPA.bMixMode = true;

				break;

			case IE_RSN:
				pRsnHeader = (PRSN_IE_HEADER_STRUCT) pTmp;

				/* 0. Version must be 1*/
				if (le2cpu16(pRsnHeader->Version) != 1)
					break;
				pTmp   += sizeof(RSN_IE_HEADER_STRUCT);

				/* 1. Check group cipher*/
				pCipher = (PCIPHER_SUITE_STRUCT) pTmp;
				if (memcmp(pTmp, RSN_OUI, 3) != 0)
					break;

				/* Parse group cipher*/
				switch (pCipher->Type)
				{
					case 1:
						pBss->WPA2.GroupCipher = Ndis802_11GroupWEP40Enabled;
						break;
					case 5:
						pBss->WPA2.GroupCipher = Ndis802_11GroupWEP104Enabled;
						break;
					case 2:
						pBss->WPA2.GroupCipher = Ndis802_11Encryption2Enabled;
						break;
					case 4:
						pBss->WPA2.GroupCipher = Ndis802_11Encryption3Enabled;
						break;
					default:
						break;
				}
				/* set to correct offset for next parsing*/
				pTmp   += sizeof(CIPHER_SUITE_STRUCT);

				/* 2. Get pairwise cipher counts*/
				/*Count = *(unsigned short *) pTmp;*/
				Count = (pTmp[1]<<8) + pTmp[0];
				pTmp   += sizeof(unsigned short);

				/* 3. Get pairwise cipher*/
				/* Parsing all unicast cipher suite*/
				while (Count > 0)
				{
					/* Skip OUI*/
					pCipher = (PCIPHER_SUITE_STRUCT) pTmp;
					TmpCipher = Ndis802_11WEPDisabled;
					switch (pCipher->Type)
					{
						case 1:
						case 5: /* Although WEP is not allowed in WPA related auth mode, we parse it anyway*/
							TmpCipher = Ndis802_11Encryption1Enabled;
							break;
						case 2:
							TmpCipher = Ndis802_11Encryption2Enabled;
							break;
						case 4:
							TmpCipher = Ndis802_11Encryption3Enabled;
							break;
						default:
							break;
					}
					if (TmpCipher > pBss->WPA2.PairCipher)
					{
						/* Move the lower cipher suite to PairCipherAux*/
						pBss->WPA2.PairCipherAux = pBss->WPA2.PairCipher;
						pBss->WPA2.PairCipher	 = TmpCipher;
					}
					else
					{
						pBss->WPA2.PairCipherAux = TmpCipher;
					}
					pTmp += sizeof(CIPHER_SUITE_STRUCT);
					Count--;
				}

				/* 4. get AKM suite counts*/
				/*Count	= *(unsigned short *) pTmp;*/
				Count = (pTmp[1]<<8) + pTmp[0];
				pTmp   += sizeof(unsigned short);

				/* 5. Get AKM ciphers*/
				/* Parsing all AKM ciphers*/
				while (Count > 0)
				{
					pAKM = (PAKM_SUITE_STRUCT) pTmp;
					if (memcmp(pTmp, RSN_OUI, 3) != 0)
						break;

					switch (pAKM->Type)
					{
						case 0:
							if (pBss->AuthMode == Ndis802_11AuthModeOpen)
								pBss->AuthMode = Ndis802_11AuthModeWPANone;
							else
								pBss->AuthModeAux = Ndis802_11AuthModeWPANone;
							break;
						case 1:
							/* Set AP support WPA-enterprise mode*/
							if (pBss->AuthMode == Ndis802_11AuthModeOpen)
								pBss->AuthMode = Ndis802_11AuthModeWPA2;
							else
								pBss->AuthModeAux = Ndis802_11AuthModeWPA2;
							break;
						case 2:
							/* Set AP support WPA-PSK mode*/
							if (pBss->AuthMode == Ndis802_11AuthModeOpen)
								pBss->AuthMode = Ndis802_11AuthModeWPA2PSK;
							else
								pBss->AuthModeAux = Ndis802_11AuthModeWPA2PSK;


							break;
						default:
							if (pBss->AuthMode == Ndis802_11AuthModeOpen)
								pBss->AuthMode = Ndis802_11AuthModeMax;
							else
								pBss->AuthModeAux = Ndis802_11AuthModeMax;
							break;
					}
					pTmp   += sizeof(AKM_SUITE_STRUCT);
					Count--;
				}

				/* Fixed for WPA-None*/
				if (pBss->BssType == BSS_ADHOC)
				{
					pBss->WPA.PairCipherAux = pBss->WPA2.PairCipherAux;
					pBss->WPA.GroupCipher	= pBss->WPA2.GroupCipher;
					pBss->WepStatus 		= pBss->WPA.GroupCipher;
					/* Patched bugs for old driver*/
					if (pBss->WPA.PairCipherAux == Ndis802_11WEPDisabled)
						pBss->WPA.PairCipherAux = pBss->WPA.GroupCipher;
				}
				pBss->WepStatus   = pBss->WPA2.PairCipher;

				/* 6. Get RSN capability*/
				/*pBss->WPA2.RsnCapability = *(unsigned short *) pTmp;*/
				pBss->WPA2.RsnCapability = (pTmp[1]<<8) + pTmp[0];
				pTmp += sizeof(unsigned short);

				/* Check the Pair & Group, if different, turn on mixed mode flag*/
				if (pBss->WPA2.GroupCipher != pBss->WPA2.PairCipher)
					pBss->WPA2.bMixMode = true;

				break;
			default:
				break;
		}
		Length -= (pEid->Len + 2);
	}
}

/* ===========================================================================================*/
/* mac_table.c*/
/* ===========================================================================================*/

/*! \brief generates a random mac address value for IBSS BSSID
 *	\param Addr the bssid location
 *	\return none
 *	\pre
 *	\post
 */
void MacAddrRandomBssid(
	struct rtmp_adapter *pAd,
	u8 *pAddr)
{
	int i;

	for (i = 0; i < ETH_ALEN; i++)
	{
		pAddr[i] = RandomByte(pAd);
	}

	pAddr[0] = (pAddr[0] & 0xfe) | 0x02;  /* the first 2 bits must be 01xxxxxxxx*/
}

/*! \brief init the management mac frame header
 *	\param p_hdr mac header
 *	\param subtype subtype of the frame
 *	\param p_ds destination address, don't care if it is a broadcast address
 *	\return none
 *	\pre the station has the following information in the pAd->StaCfg
 *	 - bssid
 *	 - station address
 *	\post
 *	\note this function initializes the following field

 IRQL = PASSIVE_LEVEL
 IRQL = DISPATCH_LEVEL

 */
void MgtMacHeaderInit(
	struct rtmp_adapter *pAd,
	PHEADER_802_11 pHdr80211,
	u8 SubType,
	u8 ToDs,
	u8 *pDA,
	u8 *pBssid)
{
	memset(pHdr80211, 0, sizeof(HEADER_802_11));

	pHdr80211->FC.Type = BTYPE_MGMT;
	pHdr80211->FC.SubType = SubType;
/*	if (SubType == SUBTYPE_ACK)	 sample, no use, it will conflict with ACTION frame sub type*/
/*		pHdr80211->FC.Type = BTYPE_CNTL;*/
	pHdr80211->FC.ToDs = ToDs;
	memcpy(pHdr80211->Addr1, pDA, ETH_ALEN);
#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		memcpy(pHdr80211->Addr2, pAd->CurrentAddress, ETH_ALEN);
#endif /* CONFIG_STA_SUPPORT */
	memcpy(pHdr80211->Addr3, pBssid, ETH_ALEN);
}

/* ===========================================================================================*/
/* mem_mgmt.c*/
/* ===========================================================================================*/

/*!***************************************************************************
 * This routine build an outgoing frame, and fill all information specified
 * in argument list to the frame body. The actual frame size is the summation
 * of all arguments.
 * input params:
 *		Buffer - pointer to a pre-allocated memory segment
 *		args - a list of <int arg_size, arg> pairs.
 *		NOTE NOTE NOTE!!!! the last argument must be NULL, otherwise this
 *						   function will FAIL!!!
 * return:
 *		Size of the buffer
 * usage:
 *		MakeOutgoingFrame(Buffer, output_length, 2, &fc, 2, &dur, 6, p_addr1, 6,p_addr2, END_OF_ARGS);

 IRQL = PASSIVE_LEVEL
 IRQL = DISPATCH_LEVEL

 ****************************************************************************/
unsigned long MakeOutgoingFrame(
	u8 *Buffer,
	unsigned long *FrameLen, ...)
{
	u8   *p;
	int 	leng;
	unsigned long	TotLeng;
	va_list Args;

	/* calculates the total length*/
	TotLeng = 0;
	va_start(Args, FrameLen);
	do
	{
		leng = va_arg(Args, int);
		if (leng == END_OF_ARGS)
		{
			break;
		}
		p = va_arg(Args, void *);
		memmove(&Buffer[TotLeng], p, leng);
		TotLeng = TotLeng + leng;
	} while(true);

	va_end(Args); /* clean up */
	*FrameLen = TotLeng;
	return TotLeng;
}

/* ===========================================================================================*/
/* mlme_queue.c*/
/* ===========================================================================================*/

/*! \brief	Initialize The MLME Queue, used by MLME Functions
 *	\param	*Queue	   The MLME Queue
 *	\return Always	   Return NDIS_STATE_SUCCESS in this implementation
 *	\pre
 *	\post
 *	\note	Because this is done only once (at the init stage), no need to be locked

 IRQL = PASSIVE_LEVEL

 */
int MlmeQueueInit(
	struct rtmp_adapter *pAd,
	MLME_QUEUE *Queue)
{
	int i;

	spin_lock_init(&Queue->Lock);

	Queue->Num	= 0;
	Queue->Head = 0;
	Queue->Tail = 0;

	for (i = 0; i < MAX_LEN_OF_MLME_QUEUE; i++)
	{
		Queue->Entry[i].Occupied = false;
		Queue->Entry[i].MsgLen = 0;
		memset(Queue->Entry[i].Msg, 0, MGMT_DMA_BUFFER_SIZE);
	}

	return NDIS_STATUS_SUCCESS;
}

/*! \brief	 Enqueue a message for other threads, if they want to send messages to MLME thread
 *	\param	*Queue	  The MLME Queue
 *	\param	 Machine  The State Machine Id
 *	\param	 MsgType  The Message Type
 *	\param	 MsgLen   The Message length
 *	\param	*Msg	  The message pointer
 *	\return  true if enqueue is successful, false if the queue is full
 *	\pre
 *	\post
 *	\note	 The message has to be initialized

 IRQL = PASSIVE_LEVEL
 IRQL = DISPATCH_LEVEL

 */
bool MlmeEnqueue(
	struct rtmp_adapter *pAd,
	unsigned long Machine,
	unsigned long MsgType,
	unsigned long MsgLen,
	void *Msg,
	unsigned long Priv)
{
	int Tail;
	MLME_QUEUE	*Queue = (MLME_QUEUE *)&pAd->Mlme.Queue;

	/* Do nothing if the driver is starting halt state.*/
	/* This might happen when timer already been fired before cancel timer with mlmehalt*/
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
		return false;

	/* First check the size, it MUST not exceed the mlme queue size*/
	if (MsgLen > MGMT_DMA_BUFFER_SIZE)
	{
		DBGPRINT_ERR(("MlmeEnqueue: msg too large, size = %ld \n", MsgLen));
		return false;
	}

	if (MlmeQueueFull(Queue, 1))
	{
		return false;
	}

	NdisAcquireSpinLock(&(Queue->Lock));
	Tail = Queue->Tail;
	Queue->Tail++;
	Queue->Num++;
	if (Queue->Tail == MAX_LEN_OF_MLME_QUEUE)
	{
		Queue->Tail = 0;
	}

	Queue->Entry[Tail].Wcid = RESERVED_WCID;
	Queue->Entry[Tail].Occupied = true;
	Queue->Entry[Tail].Machine = Machine;
	Queue->Entry[Tail].MsgType = MsgType;
	Queue->Entry[Tail].MsgLen  = MsgLen;
	Queue->Entry[Tail].Priv = Priv;

	if (Msg != NULL)
	{
		memmove(Queue->Entry[Tail].Msg, Msg, MsgLen);
	}

	NdisReleaseSpinLock(&(Queue->Lock));
	return true;
}

/*! \brief	 This function is used when Recv gets a MLME message
 *	\param	*Queue			 The MLME Queue
 *	\param	 TimeStampHigh	 The upper 32 bit of timestamp
 *	\param	 TimeStampLow	 The lower 32 bit of timestamp
 *	\param	 Rssi			 The receiving RSSI strength
 *	\param	 MsgLen 		 The length of the message
 *	\param	*Msg			 The message pointer
 *	\return  true if everything ok, false otherwise (like Queue Full)
 *	\pre
 *	\post

 IRQL = DISPATCH_LEVEL

 */
bool MlmeEnqueueForRecv(
	struct rtmp_adapter *pAd,
	unsigned long Wcid,
	unsigned long TimeStampHigh,
	unsigned long TimeStampLow,
	u8 Rssi0,
	u8 Rssi1,
	u8 Rssi2,
	unsigned long MsgLen,
	void *Msg,
	u8 Signal,
	u8 OpMode)
{
	int 		 Tail, Machine = 0xff;
	PFRAME_802_11 pFrame = (PFRAME_802_11)Msg;
	int		 MsgType = 0x0;
	MLME_QUEUE	*Queue = (MLME_QUEUE *)&pAd->Mlme.Queue;

	/* Do nothing if the driver is starting halt state.*/
	/* This might happen when timer already been fired before cancel timer with mlmehalt*/
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
	{
		DBGPRINT_ERR(("MlmeEnqueueForRecv: fRTMP_ADAPTER_HALT_IN_PROGRESS\n"));
		return false;
	}

	/* First check the size, it MUST not exceed the mlme queue size*/
	if (MsgLen > MGMT_DMA_BUFFER_SIZE)
	{
		DBGPRINT_ERR(("MlmeEnqueueForRecv: frame too large, size = %ld \n", MsgLen));
		return false;
	}

	if (MlmeQueueFull(Queue, 0))
	{
		return false;
	}


#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		if (!MsgTypeSubst(pAd, pFrame, &Machine, &MsgType))
		{
			DBGPRINT_ERR(("MlmeEnqueueForRecv: un-recongnized mgmt->subtype=%d\n",pFrame->Hdr.FC.SubType));
			return false;
		}
	}
#endif /* CONFIG_STA_SUPPORT */

	/* OK, we got all the informations, it is time to put things into queue*/

	NdisAcquireSpinLock(&(Queue->Lock));
	Tail = Queue->Tail;
	Queue->Tail++;
	Queue->Num++;
	if (Queue->Tail == MAX_LEN_OF_MLME_QUEUE)
	{
		Queue->Tail = 0;
	}
	Queue->Entry[Tail].Occupied = true;
	Queue->Entry[Tail].Machine = Machine;
	Queue->Entry[Tail].MsgType = MsgType;
	Queue->Entry[Tail].MsgLen  = MsgLen;
	Queue->Entry[Tail].TimeStamp.u.LowPart = TimeStampLow;
	Queue->Entry[Tail].TimeStamp.u.HighPart = TimeStampHigh;
	Queue->Entry[Tail].Rssi0 = Rssi0;
	Queue->Entry[Tail].Rssi1 = Rssi1;
	Queue->Entry[Tail].Rssi2 = Rssi2;
	Queue->Entry[Tail].Signal = Signal;
	Queue->Entry[Tail].Wcid = (u8)Wcid;
	Queue->Entry[Tail].OpMode = (unsigned long)OpMode;
	Queue->Entry[Tail].Priv = 0;

	Queue->Entry[Tail].Channel = pAd->LatchRfRegs.Channel;

	if (Msg != NULL)
	{
		memmove(Queue->Entry[Tail].Msg, Msg, MsgLen);
	}

	NdisReleaseSpinLock(&(Queue->Lock));
	RTMP_MLME_HANDLER(pAd);

	return true;
}


/*! \brief	 Dequeue a message from the MLME Queue
 *	\param	*Queue	  The MLME Queue
 *	\param	*Elem	  The message dequeued from MLME Queue
 *	\return  true if the Elem contains something, false otherwise
 *	\pre
 *	\post

 IRQL = DISPATCH_LEVEL

 */
bool MlmeDequeue(
	MLME_QUEUE *Queue,
	MLME_QUEUE_ELEM **Elem)
{
	NdisAcquireSpinLock(&(Queue->Lock));
	*Elem = &(Queue->Entry[Queue->Head]);
	Queue->Num--;
	Queue->Head++;
	if (Queue->Head == MAX_LEN_OF_MLME_QUEUE)
	{
		Queue->Head = 0;
	}
	NdisReleaseSpinLock(&(Queue->Lock));
	return true;
}

/* IRQL = DISPATCH_LEVEL*/
void MlmeRestartStateMachine(
	struct rtmp_adapter *pAd)
{
#ifdef CONFIG_STA_SUPPORT
	bool 			Cancelled;
#endif /* CONFIG_STA_SUPPORT */

	DBGPRINT(RT_DEBUG_TRACE, ("MlmeRestartStateMachine \n"));


#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
#ifdef QOS_DLS_SUPPORT
		u8 i;
#endif /* QOS_DLS_SUPPORT */
		/* Cancel all timer events*/
		/* Be careful to cancel new added timer*/
		RTMPCancelTimer(&pAd->MlmeAux.AssocTimer,	  &Cancelled);
		RTMPCancelTimer(&pAd->MlmeAux.ReassocTimer,   &Cancelled);
		RTMPCancelTimer(&pAd->MlmeAux.DisassocTimer,  &Cancelled);
		RTMPCancelTimer(&pAd->MlmeAux.AuthTimer,	   &Cancelled);
		RTMPCancelTimer(&pAd->MlmeAux.BeaconTimer,	   &Cancelled);
		RTMPCancelTimer(&pAd->MlmeAux.ScanTimer,	   &Cancelled);

#ifdef QOS_DLS_SUPPORT
		for (i=0; i<MAX_NUM_OF_DLS_ENTRY; i++)
		{
			RTMPCancelTimer(&pAd->StaCfg.DLSEntry[i].Timer, &Cancelled);
		}
#endif /* QOS_DLS_SUPPORT */
	}
#endif /* CONFIG_STA_SUPPORT */

	/* Change back to original channel in case of doing scan*/
	{
	AsicSwitchChannel(pAd, pAd->CommonCfg.Channel, false);
	AsicLockChannel(pAd, pAd->CommonCfg.Channel);
	}

	/* Resume MSDU which is turned off durning scan*/
	RTMPResumeMsduTransmission(pAd);

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		/* Set all state machines back IDLE*/
		pAd->Mlme.CntlMachine.CurrState    = CNTL_IDLE;
		pAd->Mlme.AssocMachine.CurrState   = ASSOC_IDLE;
		pAd->Mlme.AuthMachine.CurrState    = AUTH_REQ_IDLE;
		pAd->Mlme.AuthRspMachine.CurrState = AUTH_RSP_IDLE;
		pAd->Mlme.SyncMachine.CurrState    = SYNC_IDLE;
		pAd->Mlme.ActMachine.CurrState    = ACT_IDLE;
#ifdef QOS_DLS_SUPPORT
		pAd->Mlme.DlsMachine.CurrState    = DLS_IDLE;
#endif /* QOS_DLS_SUPPORT */

	}
#endif /* CONFIG_STA_SUPPORT */

}

/*! \brief	test if the MLME Queue is empty
 *	\param	*Queue	  The MLME Queue
 *	\return true if the Queue is empty, false otherwise
 *	\pre
 *	\post

 IRQL = DISPATCH_LEVEL

 */
bool MlmeQueueEmpty(
	MLME_QUEUE *Queue)
{
	bool Ans;

	NdisAcquireSpinLock(&(Queue->Lock));
	Ans = (Queue->Num == 0);
	NdisReleaseSpinLock(&(Queue->Lock));

	return Ans;
}

/*! \brief	 test if the MLME Queue is full
 *	\param	 *Queue 	 The MLME Queue
 *	\return  true if the Queue is empty, false otherwise
 *	\pre
 *	\post

 IRQL = PASSIVE_LEVEL
 IRQL = DISPATCH_LEVEL

 */
bool MlmeQueueFull(
	MLME_QUEUE *Queue,
	u8 SendId)
{
	bool Ans;

	NdisAcquireSpinLock(&(Queue->Lock));
	if (SendId == 0)
		Ans = ((Queue->Num >= (MAX_LEN_OF_MLME_QUEUE / 2)) || Queue->Entry[Queue->Tail].Occupied);
	else
		Ans = (Queue->Num == MAX_LEN_OF_MLME_QUEUE);
	NdisReleaseSpinLock(&(Queue->Lock));

	return Ans;
}

/*! \brief	 The destructor of MLME Queue
 *	\param
 *	\return
 *	\pre
 *	\post
 *	\note	Clear Mlme Queue, Set Queue->Num to Zero.

 IRQL = PASSIVE_LEVEL

 */
void MlmeQueueDestroy(
	MLME_QUEUE *pQueue)
{
	NdisAcquireSpinLock(&(pQueue->Lock));
	pQueue->Num  = 0;
	pQueue->Head = 0;
	pQueue->Tail = 0;
	NdisReleaseSpinLock(&(pQueue->Lock));
}


/*! \brief	 To substitute the message type if the message is coming from external
 *	\param	pFrame		   The frame received
 *	\param	*Machine	   The state machine
 *	\param	*MsgType	   the message type for the state machine
 *	\return true if the substitution is successful, false otherwise
 *	\pre
 *	\post

 IRQL = DISPATCH_LEVEL

 */
#ifdef CONFIG_STA_SUPPORT
bool MsgTypeSubst(
	struct rtmp_adapter * pAd,
	PFRAME_802_11 pFrame,
	int *Machine,
	int *MsgType)
{
	unsigned short	Seq, Alg;
	u8 EAPType;
	u8 *pData;
	bool bRV = false;

	/* Pointer to start of data frames including SNAP header*/
	pData = (u8 *) pFrame + LENGTH_802_11;

	/* The only data type will pass to this function is EAPOL frame*/
	if (pFrame->Hdr.FC.Type == BTYPE_DATA)
	{
		if (bRV == false)
		{
	        *Machine = WPA_STATE_MACHINE;
			EAPType = *((u8 *)pFrame + LENGTH_802_11 + LENGTH_802_1_H + 1);
	        return (WpaMsgTypeSubst(EAPType, (int *) MsgType));
		}
	}

	switch (pFrame->Hdr.FC.SubType)
	{
		case SUBTYPE_ASSOC_REQ:
			*Machine = ASSOC_STATE_MACHINE;
			*MsgType = MT2_PEER_ASSOC_REQ;
			break;
		case SUBTYPE_ASSOC_RSP:
			*Machine = ASSOC_STATE_MACHINE;
			*MsgType = MT2_PEER_ASSOC_RSP;
			break;
		case SUBTYPE_REASSOC_REQ:
			*Machine = ASSOC_STATE_MACHINE;
			*MsgType = MT2_PEER_REASSOC_REQ;
			break;
		case SUBTYPE_REASSOC_RSP:
			*Machine = ASSOC_STATE_MACHINE;
			*MsgType = MT2_PEER_REASSOC_RSP;
			break;
		case SUBTYPE_PROBE_REQ:
			*Machine = SYNC_STATE_MACHINE;
			*MsgType = MT2_PEER_PROBE_REQ;
			break;
		case SUBTYPE_PROBE_RSP:
			*Machine = SYNC_STATE_MACHINE;
			*MsgType = MT2_PEER_PROBE_RSP;
			break;
		case SUBTYPE_BEACON:
			*Machine = SYNC_STATE_MACHINE;
			*MsgType = MT2_PEER_BEACON;
			break;
		case SUBTYPE_ATIM:
			*Machine = SYNC_STATE_MACHINE;
			*MsgType = MT2_PEER_ATIM;
			break;
		case SUBTYPE_DISASSOC:
			*Machine = ASSOC_STATE_MACHINE;
			*MsgType = MT2_PEER_DISASSOC_REQ;
			break;
		case SUBTYPE_AUTH:
			/* get the sequence number from payload 24 Mac Header + 2 bytes algorithm*/
			memmove(&Seq, &pFrame->Octet[2], sizeof(unsigned short));
			memmove(&Alg, &pFrame->Octet[0], sizeof(unsigned short));
			if (Seq == 1 || Seq == 3)
			{
				*Machine = AUTH_RSP_STATE_MACHINE;
				*MsgType = MT2_PEER_AUTH_ODD;
			}
			else if (Seq == 2 || Seq == 4)
			{
				if (Alg == AUTH_MODE_OPEN || Alg == AUTH_MODE_KEY)
				{
					*Machine = AUTH_STATE_MACHINE;
					*MsgType = MT2_PEER_AUTH_EVEN;
				}
			}
			else
			{
				return false;
			}
			break;
		case SUBTYPE_DEAUTH:
			*Machine = AUTH_RSP_STATE_MACHINE;
			*MsgType = MT2_PEER_DEAUTH;
			break;
		case SUBTYPE_ACTION:
		case SUBTYPE_ACTION_NO_ACK:
			*Machine = ACTION_STATE_MACHINE;
			/*  Sometimes Sta will return with category bytes with MSB = 1, if they receive catogory out of their support*/
			if ((pFrame->Octet[0]&0x7F) > MAX_PEER_CATE_MSG)
			{
				*MsgType = MT2_ACT_INVALID;
			}
			else
			{
				*MsgType = (pFrame->Octet[0]&0x7F);
			}
			break;
		default:
			return false;
			break;
	}

	return true;
}
#endif /* CONFIG_STA_SUPPORT */

/* ===========================================================================================*/
/* state_machine.c*/
/* ===========================================================================================*/

/*! \brief Initialize the state machine.
 *	\param *S			pointer to the state machine
 *	\param	Trans		State machine transition function
 *	\param	StNr		number of states
 *	\param	MsgNr		number of messages
 *	\param	DefFunc 	default function, when there is invalid state/message combination
 *	\param	InitState	initial state of the state machine
 *	\param	Base		StateMachine base, internal use only
 *	\pre p_sm should be a legal pointer
 *	\post

 IRQL = PASSIVE_LEVEL

 */
void StateMachineInit(
	STATE_MACHINE *S,
	STATE_MACHINE_FUNC Trans[],
	unsigned long StNr,
	unsigned long MsgNr,
	STATE_MACHINE_FUNC DefFunc,
	unsigned long InitState,
	unsigned long Base)
{
	unsigned long i, j;

	/* set number of states and messages*/
	S->NrState = StNr;
	S->NrMsg   = MsgNr;
	S->Base    = Base;

	S->TransFunc  = Trans;

	/* init all state transition to default function*/
	for (i = 0; i < StNr; i++)
	{
		for (j = 0; j < MsgNr; j++)
		{
			S->TransFunc[i * MsgNr + j] = DefFunc;
		}
	}

	/* set the starting state*/
	S->CurrState = InitState;
}

/*! \brief This function fills in the function pointer into the cell in the state machine
 *	\param *S	pointer to the state machine
 *	\param St	state
 *	\param Msg	incoming message
 *	\param f	the function to be executed when (state, message) combination occurs at the state machine
 *	\pre *S should be a legal pointer to the state machine, st, msg, should be all within the range, Base should be set in the initial state
 *	\post

 IRQL = PASSIVE_LEVEL

 */
void StateMachineSetAction(
	STATE_MACHINE *S,
	unsigned long St,
	unsigned long Msg,
	STATE_MACHINE_FUNC Func)
{
	unsigned long MsgIdx;

	MsgIdx = Msg - S->Base;

	if (St < S->NrState && MsgIdx < S->NrMsg)
	{
		/* boundary checking before setting the action*/
		S->TransFunc[St * S->NrMsg + MsgIdx] = Func;
	}
}

/*! \brief	 This function does the state transition
 *	\param	 *Adapter the NIC adapter pointer
 *	\param	 *S 	  the state machine
 *	\param	 *Elem	  the message to be executed
 *	\return   None

 IRQL = DISPATCH_LEVEL

 */
void StateMachinePerformAction(
	struct rtmp_adapter *pAd,
	STATE_MACHINE *S,
	MLME_QUEUE_ELEM *Elem,
	unsigned long CurrState)
{

	if (S->TransFunc[(CurrState) * S->NrMsg + Elem->MsgType - S->Base])
		(*(S->TransFunc[(CurrState) * S->NrMsg + Elem->MsgType - S->Base]))(pAd, Elem);
}

/*
	==========================================================================
	Description:
		The drop function, when machine executes this, the message is simply
		ignored. This function does nothing, the message is freed in
		StateMachinePerformAction()
	==========================================================================
 */
void Drop(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{
}

/*
	==========================================================================
	Description:
	==========================================================================
 */
u8 RandomByte(
	struct rtmp_adapter *pAd)
{
	unsigned long i;
	u8 R, Result;

	R = 0;

	if (pAd->Mlme.ShiftReg == 0)
	NdisGetSystemUpTime((unsigned long *)&pAd->Mlme.ShiftReg);

	for (i = 0; i < 8; i++)
	{
		if (pAd->Mlme.ShiftReg & 0x00000001)
		{
			pAd->Mlme.ShiftReg = ((pAd->Mlme.ShiftReg ^ LFSR_MASK) >> 1) | 0x80000000;
			Result = 1;
		}
		else
		{
			pAd->Mlme.ShiftReg = pAd->Mlme.ShiftReg >> 1;
			Result = 0;
		}
		R = (R << 1) | Result;
	}

	return R;
}


/*
	========================================================================

	Routine Description:
		Verify the support rate for different PHY type

	Arguments:
		pAd 				Pointer to our adapter

	Return Value:
		None

	IRQL = PASSIVE_LEVEL

	========================================================================
*/
void RTMPCheckRates(
	struct rtmp_adapter *pAd,
	u8 SupRate[],
	u8 *SupRateLen)
{
	u8 RateIdx, i, j;
	u8 NewRate[12], NewRateLen;

	NewRateLen = 0;

	if (WMODE_EQUAL(pAd->CommonCfg.PhyMode, WMODE_B))
		RateIdx = 4;
	else
		RateIdx = 12;

	/* Check for support rates exclude basic rate bit */
	for (i = 0; i < *SupRateLen; i++)
		for (j = 0; j < RateIdx; j++)
			if ((SupRate[i] & 0x7f) == RateIdTo500Kbps[j])
				NewRate[NewRateLen++] = SupRate[i];

	*SupRateLen = NewRateLen;
	memmove(SupRate, NewRate, NewRateLen);
}

#ifdef CONFIG_STA_SUPPORT
#ifdef DOT11_N_SUPPORT
bool RTMPCheckChannel(
	struct rtmp_adapter *pAd,
	u8 	CentralChannel,
	u8 	Channel)
{
	u8 	k;
	u8 	UpperChannel = 0, LowerChannel = 0;
	u8 	NoEffectChannelinList = 0;

	/* Find upper and lower channel according to 40MHz current operation. */
	if (CentralChannel < Channel)
	{
		UpperChannel = Channel;
		if (CentralChannel > 2)
			LowerChannel = CentralChannel - 2;
		else
			return false;
	}
	else if (CentralChannel > Channel)
	{
		UpperChannel = CentralChannel + 2;
		LowerChannel = Channel;
	}

	for (k = 0;k < pAd->ChannelListNum;k++)
	{
		if (pAd->ChannelList[k].Channel == UpperChannel)
		{
			NoEffectChannelinList ++;
		}
		if (pAd->ChannelList[k].Channel == LowerChannel)
		{
			NoEffectChannelinList ++;
		}
	}

	DBGPRINT(RT_DEBUG_TRACE,("Total Channel in Channel List = [%d]\n", NoEffectChannelinList));
	if (NoEffectChannelinList == 2)
		return true;
	else
		return false;
}


/*
	========================================================================

	Routine Description:
		Verify the support rate for HT phy type

	Arguments:
		pAd 				Pointer to our adapter

	Return Value:
		false if pAd->CommonCfg.SupportedHtPhy doesn't accept the pHtCapability.  (AP Mode)

	IRQL = PASSIVE_LEVEL

	========================================================================
*/
bool RTMPCheckHt(
	struct rtmp_adapter *pAd,
	u8 Wcid,
	HT_CAPABILITY_IE *pHtCapability,
	ADD_HT_INFO_IE *pAddHtInfo)
{
	if (Wcid >= MAX_LEN_OF_MAC_TABLE)
		return false;

	/* If use AMSDU, set flag.*/
	if (pAd->CommonCfg.DesiredHtPhy.AmsduEnable)
		CLIENT_STATUS_SET_FLAG(&pAd->MacTab.Content[Wcid], fCLIENT_STATUS_AMSDU_INUSED);
	/* Save Peer Capability*/
	if (pHtCapability->HtCapInfo.ShortGIfor20)
		CLIENT_STATUS_SET_FLAG(&pAd->MacTab.Content[Wcid], fCLIENT_STATUS_SGI20_CAPABLE);
	if (pHtCapability->HtCapInfo.ShortGIfor40)
		CLIENT_STATUS_SET_FLAG(&pAd->MacTab.Content[Wcid], fCLIENT_STATUS_SGI40_CAPABLE);
	if (pHtCapability->HtCapInfo.TxSTBC)
		CLIENT_STATUS_SET_FLAG(&pAd->MacTab.Content[Wcid], fCLIENT_STATUS_TxSTBC_CAPABLE);
	if (pHtCapability->HtCapInfo.RxSTBC)
		CLIENT_STATUS_SET_FLAG(&pAd->MacTab.Content[Wcid], fCLIENT_STATUS_RxSTBC_CAPABLE);
	if (pAd->CommonCfg.bRdg && pHtCapability->ExtHtCapInfo.RDGSupport)
	{
		CLIENT_STATUS_SET_FLAG(&pAd->MacTab.Content[Wcid], fCLIENT_STATUS_RDG_CAPABLE);
	}

	if (Wcid < MAX_LEN_OF_MAC_TABLE)
	{
		pAd->MacTab.Content[Wcid].MpduDensity = pHtCapability->HtCapParm.MpduDensity;
	}

	/* Will check ChannelWidth for MCSSet[4] below*/
	memset(&pAd->MlmeAux.HtCapability.MCSSet[0], 0, 16);
	pAd->MlmeAux.HtCapability.MCSSet[4] = 0x1;
	switch (pAd->CommonCfg.RxStream)
	{
		case 3:
			pAd->MlmeAux.HtCapability.MCSSet[2] = 0xff;
		case 2:
			pAd->MlmeAux.HtCapability.MCSSet[1] = 0xff;
		case 1:
		default:
			pAd->MlmeAux.HtCapability.MCSSet[0] = 0xff;
			break;
	}

	pAd->MlmeAux.HtCapability.HtCapInfo.ChannelWidth = pAddHtInfo->AddHtInfo.RecomWidth & pAd->CommonCfg.DesiredHtPhy.ChannelWidth;

	/*
		If both station and AP use 40MHz, still need to check if the 40MHZ band's legality in my country region
		If this 40MHz wideband is not allowed in my country list, use bandwidth 20MHZ instead,
	*/
	if (pAd->MlmeAux.HtCapability.HtCapInfo.ChannelWidth == BW_40)
	{
		if (RTMPCheckChannel(pAd, pAd->MlmeAux.CentralChannel, pAd->MlmeAux.Channel) == false)
		{
			pAd->MlmeAux.HtCapability.HtCapInfo.ChannelWidth = BW_20;
		}
	}

    DBGPRINT(RT_DEBUG_TRACE, ("RTMPCheckHt:: HtCapInfo.ChannelWidth=%d, RecomWidth=%d, DesiredHtPhy.ChannelWidth=%d, BW40MAvailForA/G=%d/%d, PhyMode=%d \n",
		pAd->MlmeAux.HtCapability.HtCapInfo.ChannelWidth, pAddHtInfo->AddHtInfo.RecomWidth, pAd->CommonCfg.DesiredHtPhy.ChannelWidth,
		pAd->NicConfig2.field.BW40MAvailForA, pAd->NicConfig2.field.BW40MAvailForG, pAd->CommonCfg.PhyMode));

	pAd->MlmeAux.HtCapability.HtCapInfo.GF =  pHtCapability->HtCapInfo.GF &pAd->CommonCfg.DesiredHtPhy.GF;

	/* Send Assoc Req with my HT capability.*/
	pAd->MlmeAux.HtCapability.HtCapInfo.AMsduSize =  pAd->CommonCfg.DesiredHtPhy.AmsduSize;
	pAd->MlmeAux.HtCapability.HtCapInfo.MimoPs =  pAd->CommonCfg.DesiredHtPhy.MimoPs;
	pAd->MlmeAux.HtCapability.HtCapInfo.ShortGIfor20 =  (pAd->CommonCfg.DesiredHtPhy.ShortGIfor20) & (pHtCapability->HtCapInfo.ShortGIfor20);
	pAd->MlmeAux.HtCapability.HtCapInfo.ShortGIfor40 =  (pAd->CommonCfg.DesiredHtPhy.ShortGIfor40) & (pHtCapability->HtCapInfo.ShortGIfor40);
	pAd->MlmeAux.HtCapability.HtCapInfo.TxSTBC =  (pAd->CommonCfg.DesiredHtPhy.TxSTBC)&(pHtCapability->HtCapInfo.RxSTBC);
	pAd->MlmeAux.HtCapability.HtCapInfo.RxSTBC =  (pAd->CommonCfg.DesiredHtPhy.RxSTBC)&(pHtCapability->HtCapInfo.TxSTBC);
	pAd->MlmeAux.HtCapability.HtCapParm.MaxRAmpduFactor = pAd->CommonCfg.DesiredHtPhy.MaxRAmpduFactor;
    pAd->MlmeAux.HtCapability.HtCapParm.MpduDensity = pAd->CommonCfg.HtCapability.HtCapParm.MpduDensity;
	pAd->MlmeAux.HtCapability.ExtHtCapInfo.PlusHTC = pHtCapability->ExtHtCapInfo.PlusHTC;
	pAd->MacTab.Content[Wcid].HTCapability.ExtHtCapInfo.PlusHTC = pHtCapability->ExtHtCapInfo.PlusHTC;
	if (pAd->CommonCfg.bRdg)
	{
		pAd->MlmeAux.HtCapability.ExtHtCapInfo.RDGSupport = pHtCapability->ExtHtCapInfo.RDGSupport;
        pAd->MlmeAux.HtCapability.ExtHtCapInfo.PlusHTC = 1;
	}

    if (pAd->MlmeAux.HtCapability.HtCapInfo.ChannelWidth == BW_20)
        pAd->MlmeAux.HtCapability.MCSSet[4] = 0x0;  /* BW20 can't transmit MCS32*/

	COPY_AP_HTSETTINGS_FROM_BEACON(pAd, pHtCapability);
	return true;
}


#ifdef DOT11_VHT_AC
/*
	========================================================================

	Routine Description:
		Verify the support rate for HT phy type

	Arguments:
		pAd 				Pointer to our adapter

	Return Value:
		false if pAd->CommonCfg.SupportedHtPhy doesn't accept the pHtCapability.  (AP Mode)

	IRQL = PASSIVE_LEVEL

	========================================================================
*/
bool RTMPCheckVht(
	struct rtmp_adapter *pAd,
	u8 Wcid,
	VHT_CAP_IE *vht_cap,
	VHT_OP_IE *vht_op)
{
	VHT_CAP_INFO *vht_cap_info = &vht_cap->vht_cap;
	MAC_TABLE_ENTRY *pEntry;

	// TODO: shiang-6590, not finish yet!!!!

	if (Wcid >= MAX_LEN_OF_MAC_TABLE)
		return false;

	pEntry = &pAd->MacTab.Content[Wcid];
	/* Save Peer Capability*/
	if (vht_cap_info->sgi_80M)
		CLIENT_STATUS_SET_FLAG(pEntry, fCLIENT_STATUS_SGI80_CAPABLE);
	if (vht_cap_info->sgi_160M)
		CLIENT_STATUS_SET_FLAG(pEntry, fCLIENT_STATUS_SGI160_CAPABLE);
	if (vht_cap_info->tx_stbc)
		CLIENT_STATUS_SET_FLAG(pEntry, fCLIENT_STATUS_VHT_TXSTBC_CAPABLE);
	if (vht_cap_info->rx_stbc)
		CLIENT_STATUS_SET_FLAG(pEntry, fCLIENT_STATUS_VHT_RXSTBC_CAPABLE);

	/* Will check ChannelWidth for MCSSet[4] below */
	memset(&pAd->MlmeAux.vht_cap.mcs_set, 0, sizeof(VHT_MCS_SET));
	pAd->MlmeAux.vht_cap.mcs_set.rx_high_rate = pAd->CommonCfg.RxStream * 325;
	pAd->MlmeAux.vht_cap.mcs_set.tx_high_rate = pAd->CommonCfg.TxStream * 325;

	//pAd->MlmeAux.vht_cap.vht_cap.ch_width = vht_cap_info->ch_width;


	return true;
}
#endif /* DOT11_VHT_AC */
#endif /* DOT11_N_SUPPORT */
#endif /* CONFIG_STA_SUPPORT */

/*
	========================================================================

	Routine Description:
		Verify the support rate for different PHY type

	Arguments:
		pAd 				Pointer to our adapter

	Return Value:
		None

	IRQL = PASSIVE_LEVEL

	========================================================================
*/
void RTMPUpdateMlmeRate(
	struct rtmp_adapter *pAd)
{
	u8 MinimumRate;
	u8 ProperMlmeRate; /*= RATE_54;*/
	u8 i, j, RateIdx = 12; /*1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54*/
	bool bMatch = false;


	switch (pAd->CommonCfg.PhyMode)
	{
		case (WMODE_B):
			ProperMlmeRate = RATE_11;
			MinimumRate = RATE_1;
			break;
		case (WMODE_B | WMODE_G):
#ifdef DOT11_N_SUPPORT
		case (WMODE_B | WMODE_G | WMODE_GN | WMODE_A |WMODE_AN):
		case (WMODE_B | WMODE_G | WMODE_GN):
#endif /* DOT11_N_SUPPORT */
			if ((pAd->MlmeAux.SupRateLen == 4) &&
				(pAd->MlmeAux.ExtRateLen == 0))
				/* B only AP*/
				ProperMlmeRate = RATE_11;
			else
				ProperMlmeRate = RATE_24;

			if (pAd->MlmeAux.Channel <= 14)
				MinimumRate = RATE_1;
			else
				MinimumRate = RATE_6;
			break;
		case (WMODE_A):
#ifdef DOT11_N_SUPPORT
		case (WMODE_GN):	/* rt2860 need to check mlmerate for 802.11n*/
		case (WMODE_G | WMODE_GN):
		case (WMODE_A | WMODE_G | WMODE_GN | WMODE_AN):
		case (WMODE_A |WMODE_AN):
		case (WMODE_AN):
#endif /* DOT11_N_SUPPORT */
			ProperMlmeRate = RATE_24;
			MinimumRate = RATE_6;
			break;
		case (WMODE_A |WMODE_B | WMODE_G):
			ProperMlmeRate = RATE_24;
			if (pAd->MlmeAux.Channel <= 14)
			   MinimumRate = RATE_1;
			else
				MinimumRate = RATE_6;
			break;
		default:
			ProperMlmeRate = RATE_1;
			MinimumRate = RATE_1;
			break;
	}


#ifdef DOT11_VHT_AC
	if (WMODE_EQUAL(pAd->CommonCfg.PhyMode, WMODE_B))
	{
		ProperMlmeRate = RATE_11;
		MinimumRate = RATE_1;
	}
	else
	{
		if (WMODE_CAP(pAd->CommonCfg.PhyMode, WMODE_B))
		{
			if ((pAd->MlmeAux.SupRateLen == 4) && (pAd->MlmeAux.ExtRateLen == 0))
				ProperMlmeRate = RATE_11; /* B only AP */
			else
				ProperMlmeRate = RATE_24;

			if (pAd->MlmeAux.Channel <= 14)
				MinimumRate = RATE_1;
			else
				MinimumRate = RATE_6;
		}
		else
		{
			ProperMlmeRate = RATE_24;
			MinimumRate = RATE_6;
		}
	}
#endif /* DOT11_VHT_AC */

	for (i = 0; i < pAd->MlmeAux.SupRateLen; i++)
	{
		for (j = 0; j < RateIdx; j++)
		{
			if ((pAd->MlmeAux.SupRate[i] & 0x7f) == RateIdTo500Kbps[j])
			{
				if (j == ProperMlmeRate)
				{
					bMatch = true;
					break;
				}
			}
		}

		if (bMatch)
			break;
	}

	if (bMatch == false)
	{
	for (i = 0; i < pAd->MlmeAux.ExtRateLen; i++)
	{
		for (j = 0; j < RateIdx; j++)
		{
			if ((pAd->MlmeAux.ExtRate[i] & 0x7f) == RateIdTo500Kbps[j])
			{
					if (j == ProperMlmeRate)
					{
						bMatch = true;
						break;
					}
			}
		}

			if (bMatch)
			break;
	}
	}

	if (bMatch == false)
	{
		ProperMlmeRate = MinimumRate;
	}

	pAd->CommonCfg.MlmeRate = MinimumRate;
	pAd->CommonCfg.RtsRate = ProperMlmeRate;
	if (pAd->CommonCfg.MlmeRate >= RATE_6)
	{
		pAd->CommonCfg.MlmeTransmit.field.MODE = MODE_OFDM;
		pAd->CommonCfg.MlmeTransmit.field.MCS = OfdmRateToRxwiMCS[pAd->CommonCfg.MlmeRate];
		pAd->MacTab.Content[BSS0Mcast_WCID].HTPhyMode.field.MODE = MODE_OFDM;
		pAd->MacTab.Content[BSS0Mcast_WCID].HTPhyMode.field.MCS = OfdmRateToRxwiMCS[pAd->CommonCfg.MlmeRate];
	}
	else
	{
		pAd->CommonCfg.MlmeTransmit.field.MODE = MODE_CCK;
		pAd->CommonCfg.MlmeTransmit.field.MCS = pAd->CommonCfg.MlmeRate;
		pAd->MacTab.Content[BSS0Mcast_WCID].HTPhyMode.field.MODE = MODE_CCK;
		pAd->MacTab.Content[BSS0Mcast_WCID].HTPhyMode.field.MCS = pAd->CommonCfg.MlmeRate;
	}

	DBGPRINT(RT_DEBUG_TRACE, ("RTMPUpdateMlmeRate ==>   MlmeTransmit = 0x%x  \n" , pAd->CommonCfg.MlmeTransmit.word));
}


char RTMPAvgRssi(
	struct rtmp_adapter *pAd,
	RSSI_SAMPLE 		*pRssi)
{
	char Rssi;

	if(pAd->Antenna.field.RxPath == 3)
	{
		Rssi = (pRssi->AvgRssi0 + pRssi->AvgRssi1 + pRssi->AvgRssi2)/3;
	}
	else if(pAd->Antenna.field.RxPath == 2)
	{
		Rssi = (pRssi->AvgRssi0 + pRssi->AvgRssi1)>>1;
	}
	else
	{
		Rssi = pRssi->AvgRssi0;
	}

	return Rssi;
}


char RTMPMaxRssi(
	struct rtmp_adapter *pAd,
	char				Rssi0,
	char				Rssi1,
	char				Rssi2)
{
	char	larger = -127;

	if ((pAd->Antenna.field.RxPath == 1) && (Rssi0 != 0))
	{
		larger = Rssi0;
	}

	if ((pAd->Antenna.field.RxPath >= 2) && (Rssi1 != 0))
	{
		larger = max(Rssi0, Rssi1);
	}

	if ((pAd->Antenna.field.RxPath == 3) && (Rssi2 != 0))
	{
		larger = max(larger, Rssi2);
	}

	if (larger == -127)
		larger = 0;

	return larger;
}


char RTMPMinSnr(
	struct rtmp_adapter *pAd,
	char				Snr0,
	char				Snr1)
{
	char	smaller = Snr0;

	if (pAd->Antenna.field.RxPath == 1)
	{
		smaller = Snr0;
	}

	if ((pAd->Antenna.field.RxPath >= 2) && (Snr1 != 0))
	{
		smaller = min(Snr0, Snr1);
	}

	return smaller;
}

/*
    ========================================================================
    Routine Description:
        Periodic evaluate antenna link status

    Arguments:
        pAd         - Adapter pointer

    Return Value:
        None

    ========================================================================
*/
void AsicEvaluateRxAnt(
	struct rtmp_adapter *pAd)
{

#ifdef RTMP_MAC_USB
#ifdef CONFIG_STA_SUPPORT
	if(RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_IDLE_RADIO_OFF))
		return;
#endif /* CONFIG_STA_SUPPORT */
#endif /* RTMP_MAC_USB */

	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_RESET_IN_PROGRESS |
							fRTMP_ADAPTER_HALT_IN_PROGRESS |
							fRTMP_ADAPTER_RADIO_OFF |
							fRTMP_ADAPTER_NIC_NOT_EXIST |
							fRTMP_ADAPTER_BSS_SCAN_IN_PROGRESS)
		|| OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_DOZE)
	)
		return;


	{
#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{

			if (pAd->StaCfg.Psm == PWR_SAVE)
				return;

			rtmp_bbp_set_rxpath(pAd, pAd->Antenna.field.RxPath);
			if (OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED)
			)
			{
				unsigned long	TxTotalCnt = pAd->RalinkCounters.OneSecTxNoRetryOkCount +
									pAd->RalinkCounters.OneSecTxRetryOkCount +
									pAd->RalinkCounters.OneSecTxFailCount;

				/* dynamic adjust antenna evaluation period according to the traffic*/
				if (TxTotalCnt > 50)
				{
					RTMPSetTimer(&pAd->Mlme.RxAntEvalTimer, 20);
					pAd->Mlme.bLowThroughput = false;
				}
				else
				{
					RTMPSetTimer(&pAd->Mlme.RxAntEvalTimer, 300);
					pAd->Mlme.bLowThroughput = true;
				}
			}
		}
#endif /* CONFIG_STA_SUPPORT */
	}
}


/*
    ========================================================================
    Routine Description:
        After evaluation, check antenna link status

    Arguments:
        pAd         - Adapter pointer

    Return Value:
        None

    ========================================================================
*/
void AsicRxAntEvalTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3)
{
	struct rtmp_adapter*pAd = (struct rtmp_adapter*)FunctionContext;
#ifdef CONFIG_STA_SUPPORT
	char			larger = -127, rssi0, rssi1, rssi2;
#endif /* CONFIG_STA_SUPPORT */

	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_RESET_IN_PROGRESS |
							fRTMP_ADAPTER_HALT_IN_PROGRESS |
							fRTMP_ADAPTER_RADIO_OFF |
							fRTMP_ADAPTER_NIC_NOT_EXIST)
		|| OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_DOZE)
	)
		return;

	{
#ifdef CONFIG_STA_SUPPORT
		IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		{
			if (pAd->StaCfg.Psm == PWR_SAVE)
				return;


			/* if the traffic is low, use average rssi as the criteria*/
			if (pAd->Mlme.bLowThroughput == true)
			{
				rssi0 = pAd->StaCfg.RssiSample.LastRssi0;
				rssi1 = pAd->StaCfg.RssiSample.LastRssi1;
				rssi2 = pAd->StaCfg.RssiSample.LastRssi2;
			}
			else
			{
				rssi0 = pAd->StaCfg.RssiSample.AvgRssi0;
				rssi1 = pAd->StaCfg.RssiSample.AvgRssi1;
				rssi2 = pAd->StaCfg.RssiSample.AvgRssi2;
			}

			if(pAd->Antenna.field.RxPath == 3)
			{
				larger = max(rssi0, rssi1);
#ifdef DOT11N_SS3_SUPPORT
				if (pAd->CommonCfg.TxStream >= 3)
				{
					pAd->Mlme.RealRxPath = 3;
				}
				else
#endif /* DOT11N_SS3_SUPPORT */
				if (larger > (rssi2 + 20))
					pAd->Mlme.RealRxPath = 2;
				else
					pAd->Mlme.RealRxPath = 3;
			}
			else if(pAd->Antenna.field.RxPath == 2)
			{
				if (rssi0 > (rssi1 + 20))
					pAd->Mlme.RealRxPath = 1;
				else
					pAd->Mlme.RealRxPath = 2;
			}

			rtmp_bbp_set_rxpath(pAd, pAd->Mlme.RealRxPath);
		}
#endif /* CONFIG_STA_SUPPORT */
	}
}


void APSDPeriodicExec(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3)
{
	struct rtmp_adapter*pAd = (struct rtmp_adapter*)FunctionContext;

	if (!OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED) &&
		!OPSTATUS_TEST_FLAG(pAd, fOP_AP_STATUS_MEDIA_STATE_CONNECTED))
		return;

	pAd->CommonCfg.TriggerTimerCount++;

/* Driver should not send trigger frame, it should be send by application layer*/
/*
	if (pAd->CommonCfg.bAPSDCapable && pAd->CommonCfg.APEdcaParm.bAPSDCapable
		&& (pAd->CommonCfg.bNeedSendTriggerFrame ||
		(((pAd->CommonCfg.TriggerTimerCount%20) == 19) && (!pAd->CommonCfg.bAPSDAC_BE || !pAd->CommonCfg.bAPSDAC_BK || !pAd->CommonCfg.bAPSDAC_VI || !pAd->CommonCfg.bAPSDAC_VO))))
	{
		DBGPRINT(RT_DEBUG_TRACE,("Sending trigger frame and enter service period when support APSD\n"));
		RTMPSendNullFrame(pAd, pAd->CommonCfg.TxRate, true);
		pAd->CommonCfg.bNeedSendTriggerFrame = false;
		pAd->CommonCfg.TriggerTimerCount = 0;
		pAd->CommonCfg.bInServicePeriod = true;
	}*/
}

/*
    ========================================================================
    Routine Description:
        Set/reset MAC registers according to bPiggyBack parameter

    Arguments:
        pAd         - Adapter pointer
        bPiggyBack  - Enable / Disable Piggy-Back

    Return Value:
        None

    ========================================================================
*/
void RTMPSetPiggyBack(
    struct rtmp_adapter *   pAd,
    bool          bPiggyBack)
{
	TX_LINK_CFG_STRUC  TxLinkCfg;

	TxLinkCfg.word = mt7610u_read32(pAd, TX_LINK_CFG);

	TxLinkCfg.field.TxCFAckEn = bPiggyBack;
	mt7610u_write32(pAd, TX_LINK_CFG, TxLinkCfg.word);
}

/*
    ========================================================================
    Routine Description:
        check if this entry need to switch rate automatically

    Arguments:
        pAd
        pEntry

    Return Value:
        TURE
        false

    ========================================================================
*/
bool RTMPCheckEntryEnableAutoRateSwitch(
	struct rtmp_adapter *   pAd,
	PMAC_TABLE_ENTRY	pEntry)
{
	bool 	result = true;


#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		/* only associated STA counts*/
		if ((pEntry && IS_ENTRY_CLIENT(pEntry) && (pEntry->Sst == SST_ASSOC))
#ifdef QOS_DLS_SUPPORT
			|| (pEntry && IS_ENTRY_DLS(pEntry))
#endif /* QOS_DLS_SUPPORT */
			)
		{
			result = pAd->StaCfg.bAutoTxRateSwitch;
		}
		else
			result = false;
	}
#endif /* CONFIG_STA_SUPPORT */



	return result;
}


bool RTMPAutoRateSwitchCheck(
	struct rtmp_adapter *   pAd)
{

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		if (pAd->StaCfg.bAutoTxRateSwitch)
			return true;
	}
#endif /* CONFIG_STA_SUPPORT */
	return false;
}


/*
    ========================================================================
    Routine Description:
        check if this entry need to fix tx legacy rate

    Arguments:
        pAd
        pEntry

    Return Value:
        TURE
        false

    ========================================================================
*/
u8 RTMPStaFixedTxMode(
	struct rtmp_adapter *   pAd,
	PMAC_TABLE_ENTRY	pEntry)
{
	u8 tx_mode = FIXED_TXMODE_HT;


#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		tx_mode = (u8)pAd->StaCfg.DesiredTransmitSetting.field.FixedTxMode;
	}
#endif /* CONFIG_STA_SUPPORT */

	return tx_mode;
}

/*
    ========================================================================
    Routine Description:
        Overwrite HT Tx Mode by Fixed Legency Tx Mode, if specified.

    Arguments:
        pAd
        pEntry

    Return Value:
        TURE
        false

    ========================================================================
*/
void RTMPUpdateLegacyTxSetting(
		u8 			fixed_tx_mode,
		PMAC_TABLE_ENTRY	pEntry)
{
	HTTRANSMIT_SETTING TransmitSetting;

	if (fixed_tx_mode == FIXED_TXMODE_HT)
		return;

	TransmitSetting.word = 0;

	TransmitSetting.field.MODE = pEntry->HTPhyMode.field.MODE;
	TransmitSetting.field.MCS = pEntry->HTPhyMode.field.MCS;

	if (fixed_tx_mode == FIXED_TXMODE_CCK)
	{
		TransmitSetting.field.MODE = MODE_CCK;
		/* CCK mode allow MCS 0~3*/
		if (TransmitSetting.field.MCS > MCS_3)
			TransmitSetting.field.MCS = MCS_3;
	}
	else
	{
		TransmitSetting.field.MODE = MODE_OFDM;
		/* OFDM mode allow MCS 0~7*/
		if (TransmitSetting.field.MCS > MCS_7)
			TransmitSetting.field.MCS = MCS_7;
	}

	if (pEntry->HTPhyMode.field.MODE >= TransmitSetting.field.MODE)
	{
		pEntry->HTPhyMode.word = TransmitSetting.word;
		DBGPRINT(RT_DEBUG_TRACE, ("RTMPUpdateLegacyTxSetting : wcid-%d, MODE=%s, MCS=%d \n",
				pEntry->Aid, get_phymode_str(pEntry->HTPhyMode.field.MODE), pEntry->HTPhyMode.field.MCS));
	}
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s : the fixed TxMode is invalid \n", __FUNCTION__));
	}
}

#ifdef CONFIG_STA_SUPPORT
/*
	==========================================================================
	Description:
		dynamic tune BBP R66 to find a balance between sensibility and
		noise isolation

	IRQL = DISPATCH_LEVEL

	==========================================================================
 */
void AsicStaBbpTuning(
	struct rtmp_adapter *pAd)
{
	u8 OrigR66Value = 0, R66;/*, R66UpperBound = 0x30, R66LowerBound = 0x30;*/
	char	Rssi;

	/* 2860C did not support Fase CCA, therefore can't tune*/
	if (pAd->MACVersion == 0x28600100)
		return;


	/* work as a STA*/
	if (pAd->Mlme.CntlMachine.CurrState != CNTL_IDLE)  /* no R66 tuning when SCANNING*/
		return;

	if ((pAd->OpMode == OPMODE_STA)
		&& (OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_MEDIA_STATE_CONNECTED)
			)
		&& !(OPSTATUS_TEST_FLAG(pAd, fOP_STATUS_DOZE))
		)
	{
		rtmp_bbp_get_agc(pAd, &OrigR66Value, RX_CHAIN_0);
		R66 = OrigR66Value;

		if (pAd->Antenna.field.RxPath > 1)
			Rssi = (pAd->StaCfg.RssiSample.AvgRssi0 + pAd->StaCfg.RssiSample.AvgRssi1) >> 1;
		else
			Rssi = pAd->StaCfg.RssiSample.AvgRssi0;

		// TODO: shiang,I didn't find AsicAGCAdjust for RT30xx, so I move following code from upper #if case.

	}
}
#endif /* CONFIG_STA_SUPPORT */

/*
========================================================================
Routine Description:
	Check if the channel has the property.

Arguments:
	pAd				- WLAN control block pointer
	ChanNum			- channel number
	Property		- channel property, CHANNEL_PASSIVE_SCAN, etc.

Return Value:
	true			- YES
	false			- NO

Note:
========================================================================
*/
bool CHAN_PropertyCheck(
	struct rtmp_adapter *pAd,
	u32			ChanNum,
	u8 		Property)
{
	u32 IdChan;


	/* look for all registered channels */
	for(IdChan=0; IdChan<pAd->ChannelListNum; IdChan++)
	{
		if (pAd->ChannelList[IdChan].Channel == ChanNum)
		{
			if ((pAd->ChannelList[IdChan].Flags & Property) == Property)
				return true;

			break;
		}
	}

	return false;
}



