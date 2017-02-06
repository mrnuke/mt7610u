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

/*----- 802.11H -----*/

/* Periodic Radar detection, switch channel will occur in RTMPHandleTBTTInterrupt()*/
/* Before switch channel, driver needs doing channel switch announcement.*/
void RadarDetectPeriodic(
	struct rtmp_adapter *pAd)
{
	/* need to check channel availability, after switch channel*/
	if (pAd->Dot11_H.RDMode != RD_SILENCE_MODE)
			return;

	/* channel availability check time is 60sec, use 65 for assurance*/
	if (pAd->Dot11_H.RDCount++ > pAd->Dot11_H.ChMovingTime)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("Not found radar signal, start send beacon and radar detection in service monitor\n\n"));
		AsicEnableBssSync(pAd);
		pAd->Dot11_H.RDMode = RD_NORMAL_MODE;
		return;
	}
}

/*
	========================================================================

	Routine Description:
		Radar channel check routine

	Arguments:
		pAd 	Pointer to our adapter

	Return Value:
		true	need to do radar detect
		false	need not to do radar detect

	========================================================================
*/
bool RadarChannelCheck(
	struct rtmp_adapter *pAd,
	u8 		Ch)
{
	INT 	i;
	bool result = false;

	for (i=0; i<pAd->ChannelListNum; i++)
	{
		if (Ch == pAd->ChannelList[i].Channel)
		{
			result = pAd->ChannelList[i].DfsReq;
			break;
		}
	}

	return result;
}

unsigned long JapRadarType(
	struct rtmp_adapter *pAd)
{
	unsigned long		i;
	const u8 Channel[15]={52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140};

	if (pAd->CommonCfg.RDDurRegion != JAP)
	{
		return pAd->CommonCfg.RDDurRegion;
	}

	for (i=0; i<15; i++)
	{
		if (pAd->CommonCfg.Channel == Channel[i])
		{
			break;
		}
	}

	if (i < 4)
		return JAP_W53;
	else if (i < 15)
		return JAP_W56;
	else
		return JAP; /* W52*/

}


/*
    ==========================================================================
    Description:
        Set channel switch Period
    Return:
        true if all parameters are OK, false otherwise
    ==========================================================================
*/
INT	Set_CSPeriod_Proc(
	struct rtmp_adapter *pAd,
	char *		arg)
{
	pAd->Dot11_H.CSPeriod = (USHORT) simple_strtol(arg, 0, 10);

	DBGPRINT(RT_DEBUG_TRACE, ("Set_CSPeriod_Proc::(CSPeriod=%d)\n", pAd->Dot11_H.CSPeriod));

	return true;
}

/*
    ==========================================================================
    Description:
		change channel moving time for DFS testing.

	Arguments:
	    pAdapter                    Pointer to our adapter
	    wrq                         Pointer to the ioctl argument

    Return Value:
        None

    Note:
        Usage:
               1.) iwpriv ra0 set ChMovTime=[value]
    ==========================================================================
*/
INT Set_ChMovingTime_Proc(
	struct rtmp_adapter *pAd,
	char *arg)
{
	u8 Value;

	Value = (u8) simple_strtol(arg, 0, 10);

	pAd->Dot11_H.ChMovingTime = Value;

	DBGPRINT(RT_DEBUG_TRACE, ("%s: %d\n", __FUNCTION__,
		pAd->Dot11_H.ChMovingTime));

	return true;
}


/*
    ==========================================================================
    Description:
		Reset channel block status.
	Arguments:
	    pAd				Pointer to our adapter
	    arg				Not used

    Return Value:
        None

    Note:
        Usage:
               1.) iwpriv ra0 set ChMovTime=[value]
    ==========================================================================
*/
INT Set_BlockChReset_Proc(
	struct rtmp_adapter *pAd,
	char *arg)
{
	INT i;

	DBGPRINT(RT_DEBUG_TRACE, ("%s: Reset channel block status.\n", __FUNCTION__));

	for (i=0; i<pAd->ChannelListNum; i++)
		pAd->ChannelList[i].RemainingTimeForUse = 0;

	return true;
}


#if defined(DFS_SUPPORT)

INT	Set_RadarShow_Proc(
	struct rtmp_adapter *pAd,
	char *		arg)
{
#ifdef DFS_SUPPORT
	int i;
	u8 idx;
	PRADAR_DETECT_STRUCT pRadarDetect = &pAd->CommonCfg.RadarDetect;
	PDFS_PROGRAM_PARAM pDfsProgramParam = &pRadarDetect->DfsProgramParam;
	PDFS_SW_DETECT_PARAM pDfsSwParam = &pRadarDetect->DfsSwParam;

		printk("DFSUseTasklet = %d\n", pRadarDetect->use_tasklet);
		printk("McuRadarDebug = %x\n", (unsigned int)pRadarDetect->McuRadarDebug);
		printk("PollTime = %d\n", pRadarDetect->PollTime);
		printk("ChEnable = %d (0x%x)\n", pDfsProgramParam->ChEnable, pDfsProgramParam->ChEnable);
		printk("DeltaDelay = %d\n", pDfsProgramParam->DeltaDelay);
		printk("Fcc5Thrd = %d\n", pDfsSwParam->fcc_5_threshold);
		printk("PeriodErr = %d\n", pDfsSwParam->dfs_period_err);
		printk("MaxPeriod = %d\n", (unsigned int)pDfsSwParam->dfs_max_period);
		printk("Ch0LErr = %d\n", pDfsSwParam->dfs_width_ch0_err_L);
		printk("Ch0HErr = %d\n", pDfsSwParam->dfs_width_ch0_err_H);
		printk("Ch1Shift = %d\n", pDfsSwParam->dfs_width_diff_ch1_Shift);
		printk("Ch2Shift = %d\n", pDfsSwParam->dfs_width_diff_ch2_Shift);
		/*printk("CeSwCheck = %d\n", pAd->CommonCfg.ce_sw_check);*/
		/*printk("CEStagCheck = %d\n", pAd->CommonCfg.ce_staggered_check);*/
		/*printk("HWDFSDisabled = %d\n", pAd->CommonCfg.hw_dfs_disabled);*/
		printk("DfsRssiHigh = %d\n", pRadarDetect->DfsRssiHigh);
		printk("DfsRssiLow = %d\n", pRadarDetect->DfsRssiLow);
		printk("DfsSwDisable = %u\n", pRadarDetect->bDfsSwDisable);
		printk("CheckLoop = %d\n", pDfsSwParam->dfs_check_loop);
		printk("DeclareThres = %d\n", pDfsSwParam->dfs_declare_thres);
		for (i =0; i < pRadarDetect->fdf_num; i++)
		{
			printk("ChBusyThrd[%d] = %d\n", i, pRadarDetect->ch_busy_threshold[i]);
			printk("RssiThrd[%d] = %d\n", i, pRadarDetect->rssi_threshold[i]);
		}
		for (idx=0; idx < pAd->chipCap.DfsEngineNum; idx++)
			printk("sw_idx[%u] = %u\n", idx, pDfsSwParam->sw_idx[idx]);
		for (idx=0; idx < pAd->chipCap.DfsEngineNum; idx++)
			printk("hw_idx[%u] = %u\n", idx, pDfsSwParam->hw_idx[idx]);
#ifdef DFS_DEBUG
		printk("Total[0] = %lu\n", pDfsSwParam->TotalEntries[0]);
		printk("Total[1] = %lu\n", pDfsSwParam->TotalEntries[1]);
		printk("Total[2] = %lu\n", pDfsSwParam->TotalEntries[2]);
		printk("Total[3] = %lu\n", pDfsSwParam->TotalEntries[3]);

		pDfsSwParam->TotalEntries[0] = pDfsSwParam->TotalEntries[1] = pDfsSwParam->TotalEntries[2] = pDfsSwParam->TotalEntries[3] = 0;

		printk("T_Matched_2 = %lu\n", pDfsSwParam->T_Matched_2);
		printk("T_Matched_3 = %lu\n", pDfsSwParam->T_Matched_3);
		printk("T_Matched_4 = %lu\n", pDfsSwParam->T_Matched_4);
		printk("T_Matched_5 = %lu\n", pDfsSwParam->T_Matched_5);
#endif /* DFS_DEBUG */

	printk("pAd->Dot11_H.ChMovingTime = %d\n", pAd->Dot11_H.ChMovingTime);
	printk("pAd->Dot11_H.RDMode = %d\n", pAd->Dot11_H.RDMode);
#endif /* DFS_SUPPORT */

	return true;
}

/*
	========================================================================
       Routine Description:
               Control CCK_MRC Status
       Arguments:
               pAd     Pointer to our adapter
       Return Value:

       ========================================================================
*/
void CckMrcStatusCtrl(struct rtmp_adapter *pAd)
{
}


/*
       ========================================================================
       Routine Description:
               Enhance DFS/CS when using GLRT.
       Arguments:
               pAd     Pointer to our adapter
       Return Value:

       ========================================================================
*/
void RadarGLRTCompensate(struct rtmp_adapter *pAd)
{
}
#endif /*defined(DFS_SUPPORT)  */

