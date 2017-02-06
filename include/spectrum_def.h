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


#ifndef __SPECTRUM_DEF_H__
#define __SPECTRUM_DEF_H__


#define MAX_MEASURE_REQ_TAB_SIZE		32
/* Size of hash tab must be power of 2. */
#define MAX_HASH_MEASURE_REQ_TAB_SIZE	MAX_MEASURE_REQ_TAB_SIZE

#define MAX_TPC_REQ_TAB_SIZE			32
/* Size of hash tab must be power of 2. */
#define MAX_HASH_TPC_REQ_TAB_SIZE		MAX_TPC_REQ_TAB_SIZE

#define MIN_RCV_PWR				100		/* Negative value ((dBm) */

#define TPC_REQ_AGE_OUT			500		/* ms */
#define MQ_REQ_AGE_OUT			500		/* ms */

#define TPC_DIALOGTOKEN_HASH_INDEX(_DialogToken)	((_DialogToken) & (MAX_HASH_TPC_REQ_TAB_SIZE - 1))
#define MQ_DIALOGTOKEN_HASH_INDEX(_DialogToken)		((_DialogToken) & (MAX_MEASURE_REQ_TAB_SIZE - 1))

typedef struct _MEASURE_REQ_ENTRY
{
	struct _MEASURE_REQ_ENTRY *pNext;
	unsigned long lastTime;
	bool Valid;
	u8 DialogToken;
	u8 MeasureDialogToken[3];	/* 0:basic measure, 1: CCA measure, 2: RPI_Histogram measure. */
} MEASURE_REQ_ENTRY, *PMEASURE_REQ_ENTRY;

typedef struct _MEASURE_REQ_TAB
{
	u8 Size;
	PMEASURE_REQ_ENTRY Hash[MAX_HASH_MEASURE_REQ_TAB_SIZE];
	MEASURE_REQ_ENTRY Content[MAX_MEASURE_REQ_TAB_SIZE];
} MEASURE_REQ_TAB, *PMEASURE_REQ_TAB;

typedef struct _TPC_REQ_ENTRY
{
	struct _TPC_REQ_ENTRY *pNext;
	unsigned long lastTime;
	bool Valid;
	u8 DialogToken;
} TPC_REQ_ENTRY, *PTPC_REQ_ENTRY;

typedef struct _TPC_REQ_TAB
{
	u8 Size;
	PTPC_REQ_ENTRY Hash[MAX_HASH_TPC_REQ_TAB_SIZE];
	TPC_REQ_ENTRY Content[MAX_TPC_REQ_TAB_SIZE];
} TPC_REQ_TAB, *PTPC_REQ_TAB;


/* The regulatory information */
typedef struct _DOT11_CHANNEL_SET
{
	u8 NumberOfChannels;
	u8 MaxTxPwr;
	u8 ChannelList[16];
} DOT11_CHANNEL_SET, *PDOT11_CHANNEL_SET;

typedef struct _DOT11_REGULATORY_INFORMATION
{
	u8 RegulatoryClass;
	DOT11_CHANNEL_SET ChannelSet;
} DOT11_REGULATORY_INFORMATION, *PDOT11_REGULATORY_INFORMATION;



#define RM_TPC_REQ				0
#define RM_MEASURE_REQ			1

#define RM_BASIC				0
#define RM_CCA					1
#define RM_RPI_HISTOGRAM		2
#define RM_CH_LOAD				3
#define RM_NOISE_HISTOGRAM		4


typedef struct __attribute__ ((packed)) _TPC_REPORT_INFO
{
	u8 TxPwr;
	u8 LinkMargin;
} TPC_REPORT_INFO, *PTPC_REPORT_INFO;

typedef struct __attribute__ ((packed)) _CH_SW_ANN_INFO
{
	u8 ChSwMode;
	u8 Channel;
	u8 ChSwCnt;
} CH_SW_ANN_INFO, *PCH_SW_ANN_INFO;

typedef union __attribute__ ((packed)) _MEASURE_REQ_MODE
{
#ifdef RT_BIG_ENDIAN
	struct __attribute__ ((packed))
	{

		u8 :3;
		u8 DurationMandatory:1;
		u8 Report:1;
		u8 Request:1;
		u8 Enable:1;
		u8 Parallel:1;
	} field;
#else
	struct __attribute__ ((packed))
	{
		u8 Parallel:1;
		u8 Enable:1;
		u8 Request:1;
		u8 Report:1;
		u8 DurationMandatory:1;
		u8 :3;
	} field;
#endif /* RT_BIG_ENDIAN */
	u8 word;
} MEASURE_REQ_MODE, *PMEASURE_REQ_MODE;

typedef struct __attribute__ ((packed)) _MEASURE_REQ
{
	u8 ChNum;
	uint64_t MeasureStartTime;
	uint16_t MeasureDuration;
} MEASURE_REQ, *PMEASURE_REQ;

typedef struct __attribute__ ((packed)) _MEASURE_REQ_INFO
{
	u8 Token;
	MEASURE_REQ_MODE ReqMode;
	u8 ReqType;
	u8 Oct[0];
} MEASURE_REQ_INFO, *PMEASURE_REQ_INFO;

typedef union __attribute__ ((packed)) _MEASURE_BASIC_REPORT_MAP
{
#ifdef RT_BIG_ENDIAN
	struct __attribute__ ((packed))
	{
		u8 Rev:3;

		u8 Unmeasure:1;
		u8 Radar:1;
		u8 UnidentifiedSignal:1;
		u8 OfdmPreamble:1;
		u8 BSS:1;
	} field;
#else
	struct __attribute__ ((packed))
	{
		u8 BSS:1;

		u8 OfdmPreamble:1;
		u8 UnidentifiedSignal:1;
		u8 Radar:1;
		u8 Unmeasure:1;
		u8 Rev:3;
	} field;
#endif /* RT_BIG_ENDIAN */
	u8 word;
} MEASURE_BASIC_REPORT_MAP, *PMEASURE_BASIC_REPORT_MAP;

typedef struct __attribute__ ((packed)) _MEASURE_BASIC_REPORT
{
	u8 ChNum;
	uint64_t MeasureStartTime;
	uint16_t MeasureDuration;
	MEASURE_BASIC_REPORT_MAP Map;
} MEASURE_BASIC_REPORT, *PMEASURE_BASIC_REPORT;

typedef struct __attribute__ ((packed)) _MEASURE_CCA_REPORT
{
	u8 ChNum;
	uint64_t MeasureStartTime;
	uint16_t MeasureDuration;
	u8 CCA_Busy_Fraction;
} MEASURE_CCA_REPORT, *PMEASURE_CCA_REPORT;

typedef struct __attribute__ ((packed)) _MEASURE_RPI_REPORT
{
	u8 ChNum;
	uint64_t MeasureStartTime;
	uint16_t MeasureDuration;
	u8 RPI_Density[8];
} MEASURE_RPI_REPORT, *PMEASURE_RPI_REPORT;

typedef union __attribute__ ((packed)) _MEASURE_REPORT_MODE
{
	struct __attribute__ ((packed))
	{
#ifdef RT_BIG_ENDIAN
		u8 Rev:5;
		u8 Refused:1;
		u8 Incapable:1;
		u8 Late:1;
#else
		u8 Late:1;
		u8 Incapable:1;
		u8 Refused:1;
		u8 Rev:5;
#endif /* RT_BIG_ENDIAN */
	} field;
	u8 word;
} MEASURE_REPORT_MODE, *PMEASURE_REPORT_MODE;

typedef struct __attribute__ ((packed)) _MEASURE_REPORT_INFO
{
	u8 Token;
	u8 ReportMode;
	u8 ReportType;
	u8 Octect[0];
} MEASURE_REPORT_INFO, *PMEASURE_REPORT_INFO;

typedef struct __attribute__ ((packed)) _QUIET_INFO
{
	u8 QuietCnt;
	u8 QuietPeriod;
	uint16_t QuietDuration;
	uint16_t QuietOffset;
} QUIET_INFO, *PQUIET_INFO;

#endif /* __SPECTRUM_DEF_H__ */

