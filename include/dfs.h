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


#ifndef __DFS_H__
#define __DFS_H__

/*************************************************************************
  *
  *	DFS Radar related definitions.
  *
  ************************************************************************/

#ifdef DFS_SUPPORT
#define RADAR_DEBUG_SHOW_RAW_EVENT		0x01  /* Show the 384-bytes raw data of event buffer */
#define RADAR_DEBUG_EVENT					0x02  /* Show effective event reads out from the event buffer */
#define RADAR_DEBUG_SILENCE				0x04
#define RADAR_DEBUG_SW_SILENCE			0x08
#define RADAR_DONT_SWITCH		0x10 /* Don't Switch channel when hit */
#define RADAR_DEBUG_DONT_CHECK_BUSY		0x20
#define RADAR_DEBUG_DONT_CHECK_RSSI		0x40
#define RADAR_SIMULATE						0x80 /* simulate a short pulse hit this channel */

/* McuCmd */
#define DFS_ONOFF_MCU_CMD					0x64

/*#define DFS_SW_RADAR_DECLARE_THRES	3*/
#ifdef MT76x0
#define DFS_EVENT_SIZE						4    /* Number of uint32_t of each DFS event buffer data */
#else
#define DFS_EVENT_SIZE						6    /* Number of bytes of each DFS event */
#endif
#define DFS_EVENT_BUFFER_SIZE				384  /* Number of bytes of a DFS event buffer */
#define DFS_SW_RADAR_CHECK_LOOP				50
#define DFS_SW_RADAR_SHIFT          		3
#define DFS_SW_RADAR_CH0_ERR				8
#define DFS_SW_RADAR_PERIOD_ERR				4
#define CE_STAGGERED_RADAR_CH0_H_ERR		(DFS_SW_RADAR_CH0_ERR + 16) // the step is 16 for every 0.1 us different in width
#define CE_STAGGERED_RADAR_DECLARE_THRES	2

#define NEW_DFS_FCC_5_ENT_NUM			5
#define NEW_DFS_DBG_PORT_ENT_NUM_POWER	8
#define NEW_DFS_DBG_PORT_ENT_NUM		(1 << NEW_DFS_DBG_PORT_ENT_NUM_POWER)	/* CE Debug Port entry number, 256 */
#define NEW_DFS_DBG_PORT_MASK			(NEW_DFS_DBG_PORT_ENT_NUM - 1)	/* 0xff */

#define CH_BUSY_SAMPLE_POWER 3
#define CH_BUSY_SAMPLE 		(1 << CH_BUSY_SAMPLE_POWER)
#define CH_BUSY_MASK  		(CH_BUSY_SAMPLE - 1)

#define MAX_FDF_NUMBER 5	/* max false-detection-filter number */

/* Matched Period definition */
#define NEW_DFS_MPERIOD_ENT_NUM_POWER	8
#define NEW_DFS_MPERIOD_ENT_NUM			(1 << NEW_DFS_MPERIOD_ENT_NUM_POWER)	/* CE Period Table entry number, 512 */
#define NEW_DFS_CHANNEL_0				1
#define NEW_DFS_CHANNEL_1				2
#define NEW_DFS_CHANNEL_2				4
#define NEW_DFS_CHANNEL_3				8
#define NEW_DFS_CHANNEL_4				16
#define NEW_DFS_CHANNEL_5				32

#ifdef MT76x0
#define NEW_DFS_MAX_CHANNEL			4
#else
#define NEW_DFS_MAX_CHANNEL			5
#endif

#define CE_SW_CHECK						3

#define NEW_DFS_WATCH_DOG_TIME		1 /* note that carrier detection also need timer interrupt hook*/

#define NEW_DFS_FCC		0x1 /* include Japan*/
#define NEW_DFS_EU		0x2
#define NEW_DFS_JAP		0x4
#define NEW_DFS_JAP_W53	0x8
#define NEW_DFS_END		0xff
#define MAX_VALID_RADAR_W	5
#define MAX_VALID_RADAR_T	5

#define DFS_SW_RADAR_CH1_SHIFT		3
#define DFS_SW_RADAR_CH2_SHIFT		3

#define CE_STAGGERED_RADAR_PERIOD_MAX		((133333 + 125000 + 117647 + 1000) * 2)
#define FCC_RADAR_PERIOD_MAX				(((28570 << 1) + 1000) * 2)
#define JAP_RADAR_PERIOD_MAX				(((80000 << 1) + 1000) * 2)

#define NEW_DFS_BANDWITH_MONITOR_TIME 	(NEW_DFS_CHECK_TIME / NEW_DFS_CHECK_TIME_TASKLET)
#define NEW_DFS_CHECK_TIME				300
#define NEW_DFS_CHECK_TIME_TASKLET		3

/*#define DFS_SW_RADAR_DECLARE_THRES	3*/

#define DFS_SW_RADAR_SHIFT          3

#define DFS_SW_RADAR_CH0_ERR		8

#define CE_STAGGERED_RADAR_CH0_H_ERR		(DFS_SW_RADAR_CH0_ERR + 16) /* the step is 16 for every 0.1 us different in width*/

#define CE_STAGGERED_RADAR_DECLARE_THRES	2


/* DFS Macros */
#define PERIOD_MATCH(a, b, c)			((a >= b)? ((a-b) <= c):((b-a) <= c))
#define ENTRY_PLUS(a, b, c)				(((a+b) < c)? (a+b) : (a+b-c))
#define ENTRY_MINUS(a, b, c)			((a >= b)? (a - b) : (a+c-b))
#define MAX_PROCESS_ENTRY 				16

#define IS_FCC_RADAR_1(HT_BW, T)			(((HT_BW)? ((T > 57120) && (T < 57160)) : (T > 28560) && (T < 28580)))
#define IS_W53_RADAR_2(HT_BW, T)			(((HT_BW)? ((T > 153820) && (T < 153872)) : (T > 76910) && (T < 76936)))
#define IS_W56_RADAR_3(HT_BW, T)			(((HT_BW)? ((T > 159900) && (T < 160100)) : (T > 79950) && (T < 80050)))

#define DFS_EVENT_SANITY_CHECK(_pAd, _DfsEvent)	\
		!(((_DfsEvent).EngineId >= _pAd->chipCap.DfsEngineNum) ||	\
		 ((_DfsEvent).TimeStamp & 0xffc00000) ||	\
		 ((_DfsEvent).Width & 0xe000))

#ifdef MT76x0
#define MT7650_DFS_EVENT_SANITY_CHECK(_pAd, _DfsEvent)	\
		!(((_DfsEvent).EngineId >= _pAd->chipCap.DfsEngineNum) ||	\
		 ((_DfsEvent).TimeStamp & 0xffc00000) ||	\
		 ((_DfsEvent).Width & 0xF000))

#define MT7650_DFS_EVENT_BUFF_PRINT(_StarIdx,  _TableIdx, _BufSize)				\
{																				\
	uint32_t __k;																	\
	for (__k = _StarIdx; __k < _BufSize; __k++)									\
	{																			\
		DBGPRINT(RT_DEBUG_TRACE, ("0x%08x ", _TableIdx[__k]));					\
		if(__k%DFS_EVENT_SIZE == ((DFS_EVENT_SIZE-1+_StarIdx)%DFS_EVENT_SIZE)) 	\
			DBGPRINT(RT_DEBUG_TRACE, ("\n"));									\
	}																			\
}
#endif /* MT76x0 */

#define DFS_EVENT_PRINT(_DfsEvent)		\
		DBGPRINT(RT_DEBUG_ERROR, ( "EngineId = %u, Timestamp = %u, Width = %u\n",	\
		_DfsEvent.EngineId, _DfsEvent.TimeStamp, _DfsEvent.Width));


#define DFS_EVENT_BUFF_PRINT(_StarIdx,  _TableIdx, _BufSize)						\
{																				\
	uint32_t k;																	\
	for (k = _StarIdx; k < _BufSize; k++)											\
	{																			\
		DBGPRINT(RT_DEBUG_TRACE, ("0x%02x ", _TableIdx[k]));						\
		if(k%DFS_EVENT_SIZE == ((DFS_EVENT_SIZE-1+_StarIdx)%DFS_EVENT_SIZE)) 	\
			DBGPRINT(RT_DEBUG_TRACE, ("\n"));									\
	}																			\
}

/* check whether we can do DFS detection or not */
#define DFS_CHECK_FLAGS(_pAd, _pRadarDetect)					\
		!((_pAd->Dot11_H.RDMode == RD_SWITCHING_MODE) ||		\
		(_pRadarDetect->bDfsInit == false) ||						\
		(_pRadarDetect->DFSAPRestart == 1))

#ifdef RTMP_MAC_USB
#define INIT_DFS_EVENT_BUFF_SHARED_MEMORY(_pAd, _StartOffset, _NumOfPages, _InitVal)	\
{																						\
	uint32_t i = 0;																			\
	for (i = _StartOffset; i < _StartOffset + (_NumOfPages*384); i++)							\
		RTUSBSingleWrite(_pAd, i, _InitVal, false);											\
																						\
	RTMP_IO_WRITE32(_pAd, BBPR127TABLE_OWNERID, 0x01010101);							\
	RTMP_IO_WRITE32(_pAd, BBPR127TABLE_OWNERID + 4, 0x01010101);						\
}
#endif /* RTMP_MAC_USB */

typedef enum _DFS_VERSION {
	SOFTWARE_DFS = 0,
	HARDWARE_DFS_V1,
	HARDWARE_DFS_V2
} DFS_VERSION;

typedef struct _NewDFSValidRadar
{
	unsigned short type;
	unsigned short channel; /* bit map*/
	unsigned short WLow;
	unsigned short WHigh;
	unsigned short W;  /* for fixed width radar*/
	unsigned short WMargin;
	unsigned long TLow;
	unsigned long THigh;
	unsigned long T;  /* for fixed period radar */
	unsigned short TMargin;
}NewDFSValidRadar, *pNewDFSValidRadar;

typedef struct _NewDFSDebugPort {
	unsigned long counter;
	unsigned long timestamp;
	unsigned short width;
	unsigned short start_idx;	/* start index to period table */
	unsigned short end_idx;		/* end index to period table */
} NewDFSDebugPort, *pNewDFSDebugPort;

/* Matched Period Table */
typedef struct _NewDFSMPeriod {
	unsigned short idx;
	unsigned short width;
	unsigned short idx2;
	unsigned short width2;
	unsigned long period;
} NewDFSMPeriod, *pNewDFSMPeriod;



typedef struct _NewDFSParam {
	bool valid;
	u8 mode;
	unsigned short avgLen;
	unsigned short ELow;
	unsigned short EHigh;
	unsigned short WLow;
	unsigned short WHigh;
	u8 EpsilonW;
	unsigned long TLow;
	unsigned long THigh;
	u8 EpsilonT;
	unsigned long BLow;
	unsigned long BHigh;
} NewDFSParam, *pNewDFSParam;

typedef struct _DFS_PROGRAM_PARAM{
	NewDFSParam NewDFSTableEntry[NEW_DFS_MAX_CHANNEL*4];
	unsigned short ChEnable;	/* Enabled Dfs channels (bit wise)*/
	u8 DeltaDelay;
	/* Support after dfs_func >= 2 */
	u8 Symmetric_Round;
	u8 VGA_Mask;
	u8 Packet_End_Mask;
	u8 Rx_PE_Mask;
	unsigned long RadarEventExpire[NEW_DFS_MAX_CHANNEL];
}DFS_PROGRAM_PARAM, *PDFS_PROGRAM_PARAM;

typedef struct _NewDFSTable
{
	unsigned short type;
	NewDFSParam entry[NEW_DFS_MAX_CHANNEL];
}NewDFSTable, *pNewDFSTable;

#ifdef DFS_DEBUG
typedef struct _NewDFSDebugResult
{
	char delta_delay_shift;
	char EL_shift;
	char EH_shift;
	char WL_shift;
	char WH_shift;
	unsigned long hit_time;
	unsigned long false_time;
}NewDFSDebugResult, *pNewDFSDebugResult;
#endif

typedef struct _DFS_EVENT{
	u8  EngineId;
	uint32_t TimeStamp;
	uint16_t Width;
#ifdef MT76x0
	uint16_t phase;
	u8 power_stable_counter;
	uint16_t current_power;
#endif /* MT76x0 */
}DFS_EVENT, *PDFS_EVENT;

typedef struct _DFS_SW_DETECT_PARAM{
	NewDFSDebugPort FCC_5[NEW_DFS_FCC_5_ENT_NUM];
	u8 fcc_5_idx;
	u8 fcc_5_last_idx;
	unsigned short fcc_5_threshold; /* to check the width of long pulse radar */
	unsigned short dfs_width_diff_ch1_Shift;
	unsigned short dfs_width_diff_ch2_Shift;
	unsigned short dfs_period_err;
	unsigned long dfs_max_period;	/* Max possible Period */
	unsigned short dfs_width_diff;
	unsigned short dfs_width_ch0_err_L;
	unsigned short dfs_width_ch0_err_H;
	u8 dfs_check_loop;
	u8 dfs_declare_thres;
	unsigned long dfs_w_counter;
	DFS_EVENT PreDfsEvent;		/* previous radar event */
	uint32_t EvtDropAdjTime;		/* timing threshold for adjacent event */
	unsigned int sw_idx[NEW_DFS_MAX_CHANNEL];
	unsigned int hw_idx[NEW_DFS_MAX_CHANNEL];
	unsigned int pr_idx[NEW_DFS_MAX_CHANNEL];
	unsigned short dfs_t_idx[NEW_DFS_MAX_CHANNEL];
	unsigned short dfs_w_idx[NEW_DFS_MAX_CHANNEL];
	unsigned short dfs_w_last_idx[NEW_DFS_MAX_CHANNEL];
	NewDFSDebugPort DFS_W[NEW_DFS_MAX_CHANNEL][NEW_DFS_DBG_PORT_ENT_NUM];
	NewDFSMPeriod DFS_T[NEW_DFS_MAX_CHANNEL][NEW_DFS_MPERIOD_ENT_NUM];	/* period table */
	/*u8 ce_sw_id_check;*/
	/*unsigned short	ce_sw_t_diff;*/
	/*unsigned long fcc_5_counter;*/
	/* CE Staggered radar / weather radar */
#ifdef DFS_DEBUG
	/* Roger debug */
	u8 DebugPort[384];
	u8 DebugPortPrint;	/* 0 = stop, 1 = log req, 2 = loging, 3 = log done */
	unsigned long TotalEntries[4];
	unsigned long T_Matched_2;
	unsigned long T_Matched_3;
	unsigned long T_Matched_4;
	unsigned long T_Matched_5;
	u8 BBP127Repeat;
	unsigned long CounterStored[5];
	unsigned long CounterStored2[5];
	unsigned long CounterStored3;
	NewDFSDebugPort CE_DebugCh0[NEW_DFS_DBG_PORT_ENT_NUM];
	NewDFSMPeriod CE_TCh0[NEW_DFS_MPERIOD_ENT_NUM];
#endif
}DFS_SW_DETECT_PARAM, *PDFS_SW_DETECT_PARAM;

/***************************************************************************
  *	structure for radar detection and channel switch
  **************************************************************************/
typedef struct _RADAR_DETECT_STRUCT {
	u8 DFSAPRestart;
	unsigned long MCURadarRegion;
	CHAR  AvgRssiReq;
	unsigned long DfsLowerLimit;
	unsigned long DfsUpperLimit;
	unsigned long upperlimit;
	unsigned long lowerlimit;
	unsigned long TimeStamp; /*unit: 1us*/
	u8 ChirpCheck; /* anounce on second detection of chirp radar */
	u8 bChannelSwitchInProgress; /* RDMode could cover this*/
	bool bDfsSwDisable; /* disable sotfwre check */
	bool bDfsInit;		/* to indicate if dfs regs has been initialized */
	unsigned short PollTime;
	INT DfsRssiHigh;
	INT DfsRssiLow;
	bool DfsRssiHighFromCfg;
	bool DfsRssiLowFromCfg;
	bool DfsRssiHighCfgValid;
	bool DfsRssiLowCfgValid;
	bool DFSParamFromConfig;
	bool use_tasklet;
	DFS_VERSION dfs_func;
	bool DFSWatchDogIsRunning;
	u8 radarDeclared;
	bool SymRoundFromCfg;
	bool SymRoundCfgValid;
	unsigned long idle_time;
	unsigned long busy_time;
	u8 ch_busy;
	CHAR	ch_busy_countdown;
	u8 busy_channel;
	u8 ch_busy_idle_ratio;
	bool BusyIdleFromCfg;
	bool BusyIdleCfgValid;
	u8 print_ch_busy_sta;
	unsigned long ch_busy_sta[CH_BUSY_SAMPLE];
	unsigned long ch_idle_sta[CH_BUSY_SAMPLE];
	u8 ch_busy_sta_index;
	INT		ch_busy_sum;
	INT		ch_idle_sum;
	u8 fdf_num;
	unsigned short ch_busy_threshold[MAX_FDF_NUMBER];
	INT		rssi_threshold[MAX_FDF_NUMBER];
	u8 McuRadarDebug;
	unsigned short McuRadarTick;
	unsigned long RadarTimeStampHigh;
	unsigned long RadarTimeStampLow;
	u8 EnabledChMask;				/* Bit-wise mask for enabled DFS channels */
	DFS_PROGRAM_PARAM DfsProgramParam;
	DFS_SW_DETECT_PARAM DfsSwParam;
} RADAR_DETECT_STRUCT, *PRADAR_DETECT_STRUCT;

typedef struct _NewDFSProgParam
{
	u8 channel;
	u8 mode;			/* reg 0x10, Detection Mode[2:0]*/
	unsigned short avgLen;		/* reg 0x11~0x12, M[7:0] & M[8]*/
	unsigned short ELow;		/* reg 0x13~0x14, Energy Low[7:0] & Energy Low[11:8]*/
	unsigned short EHigh;		/* reg 0x15~0x16, Energy High[7:0] & Energy High[11:8]*/
	unsigned short WLow;		/* reg 0x28~0x29, Width Low[7:0] & Width Low[11:8]*/
	unsigned short WHigh;		/* reg 0x2a~0x2b, Width High[7:0] & Width High[11:8]*/
	u8 EpsilonW;		/* reg 0x2c, Width Delta[7:0], (Width Measurement Uncertainty) */
	unsigned long TLow;			/* reg 0x17~0x1a, Period Low[7:0] & Period Low[15:8] & Period Low[23:16] & Period Low[31:24]*/
	unsigned long THigh;		/* reg 0x1b~0x1e, Period High[7:0] & Period High[15:8] & Period High[23:16] & Period High[31:24]*/
	u8 EpsilonT;		/* reg 0x27, Period Delt[7:0], (Period Measurement Uncertainty) */
	unsigned long BLow;			/* reg 0x1f~0x22, Burst Low[7:0] & Burst Low[15:8] & Burst Low[23:16] & Burst Low[31:24]*/
	unsigned long BHigh;		/* reg 0x23~0x26, Burst High[7:0] & Burst High[15:8] & Burst High[23:16] & Burst High[31:24]		*/
}NewDFSProgParam, *pNewDFSProgParam;

#endif /* DFS_SUPPORT */

#endif /*_DFS_H__*/

