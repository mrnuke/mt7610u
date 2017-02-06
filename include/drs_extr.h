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


#ifndef __DRS_EXTR_H__
#define __DRS_EXTR_H__

struct rtmp_adapter;
struct _MAC_TABLE_ENTRY;


typedef struct _RTMP_TX_RATE {
	u8 mode;
	u8 bw;
	u8 mcs;
	u8 nss;
	u8 sgi;
	u8 stbc;
}RTMP_TX_RATE;


typedef struct _RTMP_RA_LEGACY_TB
{
	u8   ItemNo;
#ifdef RT_BIG_ENDIAN
	u8 Rsv2:1;
	u8 Mode:3;
	u8 BW:2;
	u8 ShortGI:1;
	u8 STBC:1;
#else
	u8 STBC:1;
	u8 ShortGI:1;
	u8 BW:2;
	u8 Mode:3;
	u8 Rsv2:1;
#endif
	u8   CurrMCS;
	u8   TrainUp;
	u8   TrainDown;
} RTMP_RA_LEGACY_TB;

#define PTX_RA_LEGACY_ENTRY(pTable, idx)	((RTMP_RA_LEGACY_TB *)&(pTable[(idx+1)*5]))


#ifdef NEW_RATE_ADAPT_SUPPORT
typedef struct  _RTMP_RA_GRP_TB
{
	u8   ItemNo;
#ifdef RT_BIG_ENDIAN
	u8 Rsv2:1;
	u8 Mode:3;
	u8 BW:2;
	u8 ShortGI:1;
	u8 STBC:1;
#else
	u8 STBC:1;
	u8 ShortGI:1;
	u8 BW:2;
	u8 Mode:3;
	u8 Rsv2:1;
#endif
	u8   CurrMCS;
	u8   TrainUp;
	u8   TrainDown;
	u8 downMcs;
	u8 upMcs3;
	u8 upMcs2;
	u8 upMcs1;
	u8 dataRate;
} RTMP_RA_GRP_TB;

#define PTX_RA_GRP_ENTRY(pTable, idx)	((RTMP_RA_GRP_TB *)&(pTable[(idx+1)*10]))
#endif /* NEW_RATE_ADAPT_SUPPORT */

#define RATE_TABLE_SIZE(pTable)			((pTable)[0])		/* Byte 0 is number of rate indices */
#define RATE_TABLE_INIT_INDEX(pTable)	((pTable)[1])		/* Byte 1 is initial rate index */

enum RATE_ADAPT_ALG{
	RATE_ALG_GRP = 2,
	RATE_ALG_MAX_NUM
};


typedef enum {
	RAL_OLD_DRS,
	RAL_NEW_DRS,
	RAL_QUICK_DRS
}RA_LOG_TYPE;


extern u8 RateSwitchTable11B[];
extern u8 RateSwitchTable11G[];
extern u8 RateSwitchTable11BG[];

#ifdef DOT11_N_SUPPORT
extern u8 RateSwitchTable11BGN1S[];
extern u8 RateSwitchTable11BGN2S[];
extern u8 RateSwitchTable11BGN2SForABand[];
extern u8 RateSwitchTable11N1S[];
extern u8 RateSwitchTable11N1SForABand[];
extern u8 RateSwitchTable11N2S[];
extern u8 RateSwitchTable11N2SForABand[];
extern u8 RateSwitchTable11BGN3S[];
extern u8 RateSwitchTable11BGN3SForABand[];

#ifdef NEW_RATE_ADAPT_SUPPORT
extern u8 RateSwitchTableAdapt11N1S[];
extern u8 RateSwitchTableAdapt11N2S[];
extern u8 RateSwitchTableAdapt11N3S[];

#define PER_THRD_ADJ			1

/* ADAPT_RATE_TABLE - true if pTable is one of the Adaptive Rate Switch tables */
#ifdef DOT11_VHT_AC
extern u8 RateTableVht1S[];
extern u8 RateTableVht1S_MCS7[];
extern u8 RateTableVht2S[];

#define ADAPT_RATE_TABLE(pTable)	((pTable)==RateSwitchTableAdapt11N1S ||\
									(pTable)==RateSwitchTableAdapt11N2S ||\
									(pTable)==RateSwitchTableAdapt11N3S ||\
									(pTable)==RateTableVht1S ||\
									(pTable)==RateTableVht1S_MCS7 ||\
									(pTable)==RateTableVht2S)
#else
#define ADAPT_RATE_TABLE(pTable)	((pTable)==RateSwitchTableAdapt11N1S || \
									(pTable)==RateSwitchTableAdapt11N2S || \
									(pTable)==RateSwitchTableAdapt11N3S)
#endif /* DOT11_VHT_AC */
#endif /* NEW_RATE_ADAPT_SUPPORT */
#endif /* DOT11_N_SUPPORT */


/* FUNCTION */
void MlmeGetSupportedMcs(
	struct rtmp_adapter *pAd,
	u8 *pTable,
	CHAR mcs[]);

u8 MlmeSelectTxRate(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry,
	CHAR mcs[],
	CHAR Rssi,
	CHAR RssiOffset);

void MlmeClearTxQuality(struct _MAC_TABLE_ENTRY *pEntry);
void MlmeClearAllTxQuality(struct _MAC_TABLE_ENTRY *pEntry);
void MlmeDecTxQuality(struct _MAC_TABLE_ENTRY *pEntry, u8 rateIndex);
USHORT MlmeGetTxQuality(struct _MAC_TABLE_ENTRY *pEntry, u8 rateIndex);
void MlmeSetTxQuality(
	struct _MAC_TABLE_ENTRY *pEntry,
	u8 rateIndex,
	USHORT txQuality);



void MlmeOldRateAdapt(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry,
	u8 		CurrRateIdx,
	u8 		UpRateIdx,
	u8 		DownRateIdx,
	ULONG			TrainUp,
	ULONG			TrainDown,
	ULONG			TxErrorRatio);

void MlmeRestoreLastRate(
	struct _MAC_TABLE_ENTRY *pEntry);

void MlmeCheckRDG(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry);

void RTMPSetSupportMCS(
	struct rtmp_adapter *pAd,
	u8 OpMode,
	struct _MAC_TABLE_ENTRY *pEntry,
	u8 SupRate[],
	u8 SupRateLen,
	u8 ExtRate[],
	u8 ExtRateLen,
#ifdef DOT11_VHT_AC
	u8 vht_cap_len,
	VHT_CAP_IE *vht_cap,
#endif /* DOT11_VHT_AC */
	HT_CAPABILITY_IE *pHtCapability,
	u8 HtCapabilityLen);

#ifdef NEW_RATE_ADAPT_SUPPORT
void MlmeSetMcsGroup(struct rtmp_adapter *pAd, struct _MAC_TABLE_ENTRY *pEnt);

u8 MlmeSelectUpRate(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry,
	RTMP_RA_GRP_TB *pCurrTxRate);

u8 MlmeSelectDownRate(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry,
	u8 		CurrRateIdx);

void MlmeGetSupportedMcsAdapt(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry,
	u8 mcs23GI,
	CHAR 	mcs[]);

u8 MlmeSelectTxRateAdapt(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry,
	CHAR		mcs[],
	CHAR		Rssi,
	CHAR		RssiOffset);

bool MlmeRAHybridRule(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry,
	RTMP_RA_GRP_TB *pCurrTxRate,
	ULONG			NewTxOkCount,
	ULONG			TxErrorRatio);

void MlmeNewRateAdapt(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry,
	u8 		UpRateIdx,
	u8 		DownRateIdx,
	ULONG			TrainUp,
	ULONG			TrainDown,
	ULONG			TxErrorRatio);

INT	Set_PerThrdAdj_Proc(
	struct rtmp_adapter *pAd,
	char *arg);

INT	Set_LowTrafficThrd_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_TrainUpRule_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_TrainUpRuleRSSI_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_TrainUpLowThrd_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT	Set_TrainUpHighThrd_Proc(
	struct rtmp_adapter *pAd,
	char *		arg);

INT Set_RateTable_Proc(
	struct rtmp_adapter *pAd,
	char *arg);


#ifdef CONFIG_STA_SUPPORT
void StaQuickResponeForRateUpExecAdapt(
	struct rtmp_adapter *pAd,
	ULONG i,
	CHAR Rssi);

void MlmeDynamicTxRateSwitchingAdapt(
	struct rtmp_adapter *pAd,
	ULONG i,
	ULONG TxSuccess,
	ULONG TxRetransmit,
	ULONG TxFailCount);
#endif /* CONFIG_STA_SUPPORT */
#endif /* NEW_RATE_ADAPT_SUPPORT */


#ifdef CONFIG_STA_SUPPORT
void MlmeDynamicTxRateSwitching(
	struct rtmp_adapter *pAd);

void StaQuickResponeForRateUpExec(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3);

void MlmeSetTxRate(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry,
	RTMP_RA_LEGACY_TB *pTxRate);
#endif /* CONFIG_STA_SUPPORT */

void MlmeRAInit(struct rtmp_adapter *pAd, struct _MAC_TABLE_ENTRY *pEntry);
void MlmeNewTxRate(struct rtmp_adapter *pAd, struct _MAC_TABLE_ENTRY *pEntry);

void MlmeRALog(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry,
	RA_LOG_TYPE raLogType,
	ULONG TxErrorRatio,
	ULONG TxTotalCnt);

void MlmeSelectTxRateTable(
	struct rtmp_adapter *pAd,
	struct _MAC_TABLE_ENTRY *pEntry,
	u8 **ppTable,
	u8 *pTableSize,
	u8 *pInitTxRateIdx);

#endif /* __DRS_EXTR_H__ */

/* End of drs_extr.h */
