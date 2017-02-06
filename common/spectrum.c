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
#include "action.h"


/* The regulatory information in the USA (US) */
DOT11_REGULATORY_INFORMATION USARegulatoryInfo[] =
{
/*  "regulatory class"  "number of channels"  "Max Tx Pwr"  "channel list" */
    {0,	                {0,                   0,           {0}}}, /* Invlid entry*/
    {1,                 {4,                   16,           {36, 40, 44, 48}}},
    {2,                 {4,                   23,           {52, 56, 60, 64}}},
    {3,                 {4,                   29,           {149, 153, 157, 161}}},
    {4,                 {11,                  23,           {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140}}},
    {5,                 {5,                   30,           {149, 153, 157, 161, 165}}},
    {6,                 {10,                  14,           {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}},
    {7,                 {10,                  27,           {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}},
    {8,                 {5,                   17,           {11, 13, 15, 17, 19}}},
    {9,                 {5,                   30,           {11, 13, 15, 17, 19}}},
    {10,                {2,                   20,           {21, 25}}},
    {11,                {2,                   33,            {21, 25}}},
    {12,                {11,                  30,            {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}}
};
#define USA_REGULATORY_INFO_SIZE (sizeof(USARegulatoryInfo) / sizeof(DOT11_REGULATORY_INFORMATION))


/* The regulatory information in Europe */
DOT11_REGULATORY_INFORMATION EuropeRegulatoryInfo[] =
{
/*  "regulatory class"  "number of channels"  "Max Tx Pwr"  "channel list" */
    {0,                 {0,                   0,           {0}}}, /* Invalid entry*/
    {1,                 {4,                   20,           {36, 40, 44, 48}}},
    {2,                 {4,                   20,           {52, 56, 60, 64}}},
    {3,                 {11,                  30,           {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140}}},
    {4,                 {13,                  20,           {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}}}
};
#define EU_REGULATORY_INFO_SIZE (sizeof(EuropeRegulatoryInfo) / sizeof(DOT11_REGULATORY_INFORMATION))


/* The regulatory information in Japan */
DOT11_REGULATORY_INFORMATION JapanRegulatoryInfo[] =
{
/*  "regulatory class"  "number of channels"  "Max Tx Pwr"  "channel list" */
    {0,                 {0,                   0,           {0}}}, /* Invalid entry*/
    {1,                 {4,                   22,           {34, 38, 42, 46}}},
    {2,                 {3,                   24,           {8, 12, 16}}},
    {3,                 {3,                   24,           {8, 12, 16}}},
    {4,                 {3,                   24,           {8, 12, 16}}},
    {5,                 {3,                   24,           {8, 12, 16}}},
    {6,                 {3,                   22,           {8, 12, 16}}},
    {7,                 {4,                   24,           {184, 188, 192, 196}}},
    {8,                 {4,                   24,           {184, 188, 192, 196}}},
    {9,                 {4,                   24,           {184, 188, 192, 196}}},
    {10,                {4,                   24,           {184, 188, 192, 196}}},
    {11,                {4,                   22,           {184, 188, 192, 196}}},
    {12,                {4,                   24,           {7, 8, 9, 11}}},
    {13,                {4,                   24,           {7, 8, 9, 11}}},
    {14,                {4,                   24,           {7, 8, 9, 11}}},
    {15,                {4,                   24,           {7, 8, 9, 11}}},
    {16,                {6,                   24,           {183, 184, 185, 187, 188, 189}}},
    {17,                {6,                   24,           {183, 184, 185, 187, 188, 189}}},
    {18,                {6,                   24,           {183, 184, 185, 187, 188, 189}}},
    {19,                {6,                   24,           {183, 184, 185, 187, 188, 189}}},
    {20,                {6,                   17,           {183, 184, 185, 187, 188, 189}}},
    {21,                {6,                   24,           {6, 7, 8, 9, 10, 11}}},
    {22,                {6,                   24,           {6, 7, 8, 9, 10, 11}}},
    {23,                {6,                   24,           {6, 7, 8, 9, 10, 11}}},
    {24,                {6,                   24,           {6, 7, 8, 9, 10, 11}}},
    {25,                {8,                   24,           {182, 183, 184, 185, 186, 187, 188, 189}}},
    {26,                {8,                   24,           {182, 183, 184, 185, 186, 187, 188, 189}}},
    {27,                {8,                   24,           {182, 183, 184, 185, 186, 187, 188, 189}}},
    {28,                {8,                   24,           {182, 183, 184, 185, 186, 187, 188, 189}}},
    {29,                {8,                   17,           {182, 183, 184, 185, 186, 187, 188, 189}}},
    {30,                {13,                  23,           {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}}},
    {31,                {1,                   23,           {14}}},
    {32,                {4,                   22,           {52, 56, 60, 64}}}
};
#define JP_REGULATORY_INFO_SIZE (sizeof(JapanRegulatoryInfo) / sizeof(DOT11_REGULATORY_INFORMATION))


u8 GetRegulatoryMaxTxPwr(
	struct rtmp_adapter *pAd,
	u8 channel)
{
	unsigned long RegulatoryClassLoop, ChIdx;
	u8 RegulatoryClass;
	u8 MaxRegulatoryClassNum;
	PDOT11_REGULATORY_INFORMATION pRegulatoryClass;
	char *pCountry = (char *)(pAd->CommonCfg.CountryCode);


	if (strncmp(pCountry, "US", 2) == 0)
	{
		MaxRegulatoryClassNum = USA_REGULATORY_INFO_SIZE;
		pRegulatoryClass = &USARegulatoryInfo[0];
	}
	else if (strncmp(pCountry, "JP", 2) == 0)
	{
		MaxRegulatoryClassNum = JP_REGULATORY_INFO_SIZE;
		pRegulatoryClass = &JapanRegulatoryInfo[0];
	}
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: Unknow Country (%s)\n",
					__FUNCTION__, pCountry));
		return 0xff;
	}

	for (RegulatoryClassLoop = 0;
			RegulatoryClassLoop<MAX_NUM_OF_REGULATORY_CLASS;
			RegulatoryClassLoop++)
	{
		PDOT11_CHANNEL_SET pChannelSet;

		RegulatoryClass = pAd->CommonCfg.RegulatoryClass[RegulatoryClassLoop];
		if (RegulatoryClass >= MaxRegulatoryClassNum)
		{
			DBGPRINT(RT_DEBUG_ERROR, ("%s: %c%c Unknow Requlatory class (%d)\n",
						__FUNCTION__, pCountry[0], pCountry[1], RegulatoryClass));
			return 0xff;
		}
		pChannelSet = &pRegulatoryClass[RegulatoryClass].ChannelSet;
		for (ChIdx=0; ChIdx<pChannelSet->NumberOfChannels; ChIdx++)
		{
			if (channel == pChannelSet->ChannelList[ChIdx])
				return pChannelSet->MaxTxPwr;

		}
		if (ChIdx == pChannelSet->NumberOfChannels)
			return 0xff;
	}

	return 0xff;
}

typedef struct __TX_PWR_CFG
{
	u8 Mode;
	u8 MCS;
	uint16_t req;
	u8 shift;
	u32 BitMask;
} TX_PWR_CFG;

/* Note: the size of TxPwrCfg is too large, do not put it to function */
TX_PWR_CFG TxPwrCfg[] = {
	{MODE_CCK, 0, 0, 4, 0x000000f0},
	{MODE_CCK, 1, 0, 0, 0x0000000f},
	{MODE_CCK, 2, 0, 12, 0x0000f000},
	{MODE_CCK, 3, 0, 8, 0x00000f00},

	{MODE_OFDM, 0, 0, 20, 0x00f00000},
	{MODE_OFDM, 1, 0, 16, 0x000f0000},
	{MODE_OFDM, 2, 0, 28, 0xf0000000},
	{MODE_OFDM, 3, 0, 24, 0x0f000000},
	{MODE_OFDM, 4, 1, 4, 0x000000f0},
	{MODE_OFDM, 5, 1, 0, 0x0000000f},
	{MODE_OFDM, 6, 1, 12, 0x0000f000},
	{MODE_OFDM, 7, 1, 8, 0x00000f00}
#ifdef DOT11_N_SUPPORT
	,{MODE_HTMIX, 0, 1, 20, 0x00f00000},
	{MODE_HTMIX, 1, 1, 16, 0x000f0000},
	{MODE_HTMIX, 2, 1, 28, 0xf0000000},
	{MODE_HTMIX, 3, 1, 24, 0x0f000000},
	{MODE_HTMIX, 4, 2, 4, 0x000000f0},
	{MODE_HTMIX, 5, 2, 0, 0x0000000f},
	{MODE_HTMIX, 6, 2, 12, 0x0000f000},
	{MODE_HTMIX, 7, 2, 8, 0x00000f00},
	{MODE_HTMIX, 8, 2, 20, 0x00f00000},
	{MODE_HTMIX, 9, 2, 16, 0x000f0000},
	{MODE_HTMIX, 10, 2, 28, 0xf0000000},
	{MODE_HTMIX, 11, 2, 24, 0x0f000000},
	{MODE_HTMIX, 12, 3, 4, 0x000000f0},
	{MODE_HTMIX, 13, 3, 0, 0x0000000f},
	{MODE_HTMIX, 14, 3, 12, 0x0000f000},
	{MODE_HTMIX, 15, 3, 8, 0x00000f00}
#endif /* DOT11_N_SUPPORT */
};
#define MAX_TXPWR_TAB_SIZE (sizeof(TxPwrCfg) / sizeof(TX_PWR_CFG))

int	MeasureReqTabInit(
	struct rtmp_adapter *pAd)
{
	int     Status = NDIS_STATUS_SUCCESS;

	spin_lock_init(&pAd->CommonCfg.MeasureReqTabLock);

/*	pAd->CommonCfg.pMeasureReqTab = kmalloc(sizeof(MEASURE_REQ_TAB), GFP_ATOMIC);*/
	pAd->CommonCfg.pMeasureReqTab =
		kmalloc(sizeof(MEASURE_REQ_TAB), GFP_ATOMIC);
	if (pAd->CommonCfg.pMeasureReqTab)
		memset(pAd->CommonCfg.pMeasureReqTab, 0, sizeof(MEASURE_REQ_TAB));
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s Fail to alloc memory for pAd->CommonCfg.pMeasureReqTab.\n", __FUNCTION__));
		Status = NDIS_STATUS_FAILURE;
	}

	return Status;
}

void MeasureReqTabExit(
	struct rtmp_adapter *pAd)
{
	if (pAd->CommonCfg.pMeasureReqTab)
/*		kfree(pAd->CommonCfg.pMeasureReqTab);*/
		kfree(pAd->CommonCfg.pMeasureReqTab);
	pAd->CommonCfg.pMeasureReqTab = NULL;

	return;
}

PMEASURE_REQ_ENTRY MeasureReqLookUp(
	struct rtmp_adapter *pAd,
	u8			DialogToken)
{
	UINT HashIdx;
	PMEASURE_REQ_TAB pTab = pAd->CommonCfg.pMeasureReqTab;
	PMEASURE_REQ_ENTRY pEntry = NULL;
	PMEASURE_REQ_ENTRY pPrevEntry = NULL;

	if (pTab == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: pMeasureReqTab doesn't exist.\n", __FUNCTION__));
		return NULL;
	}

	RTMP_SEM_LOCK(&pAd->CommonCfg.MeasureReqTabLock);

	HashIdx = MQ_DIALOGTOKEN_HASH_INDEX(DialogToken);
	pEntry = pTab->Hash[HashIdx];

	while (pEntry)
	{
		if (pEntry->DialogToken == DialogToken)
			break;
		else
		{
			pPrevEntry = pEntry;
			pEntry = pEntry->pNext;
		}
	}

	RTMP_SEM_UNLOCK(&pAd->CommonCfg.MeasureReqTabLock);

	return pEntry;
}

PMEASURE_REQ_ENTRY MeasureReqInsert(
	struct rtmp_adapter *pAd,
	u8			DialogToken)
{
	INT i;
	unsigned long HashIdx;
	PMEASURE_REQ_TAB pTab = pAd->CommonCfg.pMeasureReqTab;
	PMEASURE_REQ_ENTRY pEntry = NULL, pCurrEntry;
	unsigned long Now;

	if(pTab == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: pMeasureReqTab doesn't exist.\n", __FUNCTION__));
		return NULL;
	}

	pEntry = MeasureReqLookUp(pAd, DialogToken);
	if (pEntry == NULL)
	{
		RTMP_SEM_LOCK(&pAd->CommonCfg.MeasureReqTabLock);
		for (i = 0; i < MAX_MEASURE_REQ_TAB_SIZE; i++)
		{
			NdisGetSystemUpTime(&Now);
			pEntry = &pTab->Content[i];

			if ((pEntry->Valid == true)
				&& RTMP_TIME_AFTER((unsigned long)Now, (unsigned long)(pEntry->lastTime + MQ_REQ_AGE_OUT)))
			{
				PMEASURE_REQ_ENTRY pPrevEntry = NULL;
				unsigned long HashIdx = MQ_DIALOGTOKEN_HASH_INDEX(pEntry->DialogToken);
				PMEASURE_REQ_ENTRY pProbeEntry = pTab->Hash[HashIdx];

				/* update Hash list*/
				do
				{
					if (pProbeEntry == pEntry)
					{
						if (pPrevEntry == NULL)
						{
							pTab->Hash[HashIdx] = pEntry->pNext;
						}
						else
						{
							pPrevEntry->pNext = pEntry->pNext;
						}
						break;
					}

					pPrevEntry = pProbeEntry;
					pProbeEntry = pProbeEntry->pNext;
				} while (pProbeEntry);

				memset(pEntry, 0, sizeof(MEASURE_REQ_ENTRY));
				pTab->Size--;

				break;
			}

			if (pEntry->Valid == false)
				break;
		}

		if (i < MAX_MEASURE_REQ_TAB_SIZE)
		{
			NdisGetSystemUpTime(&Now);
			pEntry->lastTime = Now;
			pEntry->Valid = true;
			pEntry->DialogToken = DialogToken;
			pTab->Size++;
		}
		else
		{
			pEntry = NULL;
			DBGPRINT(RT_DEBUG_ERROR, ("%s: pMeasureReqTab tab full.\n", __FUNCTION__));
		}

		/* add this Neighbor entry into HASH table*/
		if (pEntry)
		{
			HashIdx = MQ_DIALOGTOKEN_HASH_INDEX(DialogToken);
			if (pTab->Hash[HashIdx] == NULL)
			{
				pTab->Hash[HashIdx] = pEntry;
			}
			else
			{
				pCurrEntry = pTab->Hash[HashIdx];
				while (pCurrEntry->pNext != NULL)
					pCurrEntry = pCurrEntry->pNext;
				pCurrEntry->pNext = pEntry;
			}
		}

		RTMP_SEM_UNLOCK(&pAd->CommonCfg.MeasureReqTabLock);
	}

	return pEntry;
}

void MeasureReqDelete(
	struct rtmp_adapter *pAd,
	u8			DialogToken)
{
	PMEASURE_REQ_TAB pTab = pAd->CommonCfg.pMeasureReqTab;
	PMEASURE_REQ_ENTRY pEntry = NULL;

	if(pTab == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: pMeasureReqTab doesn't exist.\n", __FUNCTION__));
		return;
	}

	/* if empty, return*/
	if (pTab->Size == 0)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("pMeasureReqTab empty.\n"));
		return;
	}

	pEntry = MeasureReqLookUp(pAd, DialogToken);
	if (pEntry != NULL)
	{
		PMEASURE_REQ_ENTRY pPrevEntry = NULL;
		unsigned long HashIdx = MQ_DIALOGTOKEN_HASH_INDEX(pEntry->DialogToken);
		PMEASURE_REQ_ENTRY pProbeEntry = pTab->Hash[HashIdx];

		RTMP_SEM_LOCK(&pAd->CommonCfg.MeasureReqTabLock);
		/* update Hash list*/
		do
		{
			if (pProbeEntry == pEntry)
			{
				if (pPrevEntry == NULL)
				{
					pTab->Hash[HashIdx] = pEntry->pNext;
				}
				else
				{
					pPrevEntry->pNext = pEntry->pNext;
				}
				break;
			}

			pPrevEntry = pProbeEntry;
			pProbeEntry = pProbeEntry->pNext;
		} while (pProbeEntry);

		memset(pEntry, 0, sizeof(MEASURE_REQ_ENTRY));
		pTab->Size--;

		RTMP_SEM_UNLOCK(&pAd->CommonCfg.MeasureReqTabLock);
	}

	return;
}

int	TpcReqTabInit(
	struct rtmp_adapter *pAd)
{
	int     Status = NDIS_STATUS_SUCCESS;

	spin_lock_init(&pAd->CommonCfg.TpcReqTabLock);

/*	pAd->CommonCfg.pTpcReqTab = kmalloc(sizeof(TPC_REQ_TAB), GFP_ATOMIC);*/
	pAd->CommonCfg.pTpcReqTab = kmalloc(sizeof(TPC_REQ_TAB), GFP_ATOMIC);
	if (pAd->CommonCfg.pTpcReqTab)
		memset(pAd->CommonCfg.pTpcReqTab, 0, sizeof(TPC_REQ_TAB));
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s Fail to alloc memory for pAd->CommonCfg.pTpcReqTab.\n", __FUNCTION__));
		Status = NDIS_STATUS_FAILURE;
	}

	return Status;
}

void TpcReqTabExit(
	struct rtmp_adapter *pAd)
{
	if (pAd->CommonCfg.pTpcReqTab)
/*		kfree(pAd->CommonCfg.pTpcReqTab);*/
		kfree(pAd->CommonCfg.pTpcReqTab);
	pAd->CommonCfg.pTpcReqTab = NULL;

	return;
}

static PTPC_REQ_ENTRY TpcReqLookUp(
	struct rtmp_adapter *pAd,
	u8			DialogToken)
{
	UINT HashIdx;
	PTPC_REQ_TAB pTab = pAd->CommonCfg.pTpcReqTab;
	PTPC_REQ_ENTRY pEntry = NULL;
	PTPC_REQ_ENTRY pPrevEntry = NULL;

	if (pTab == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: pTpcReqTab doesn't exist.\n", __FUNCTION__));
		return NULL;
	}

	RTMP_SEM_LOCK(&pAd->CommonCfg.TpcReqTabLock);

	HashIdx = TPC_DIALOGTOKEN_HASH_INDEX(DialogToken);
	pEntry = pTab->Hash[HashIdx];

	while (pEntry)
	{
		if (pEntry->DialogToken == DialogToken)
			break;
		else
		{
			pPrevEntry = pEntry;
			pEntry = pEntry->pNext;
		}
	}

	RTMP_SEM_UNLOCK(&pAd->CommonCfg.TpcReqTabLock);

	return pEntry;
}


static PTPC_REQ_ENTRY TpcReqInsert(
	struct rtmp_adapter *pAd,
	u8			DialogToken)
{
	INT i;
	unsigned long HashIdx;
	PTPC_REQ_TAB pTab = pAd->CommonCfg.pTpcReqTab;
	PTPC_REQ_ENTRY pEntry = NULL, pCurrEntry;
	unsigned long Now;

	if(pTab == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: pTpcReqTab doesn't exist.\n", __FUNCTION__));
		return NULL;
	}

	pEntry = TpcReqLookUp(pAd, DialogToken);
	if (pEntry == NULL)
	{
		RTMP_SEM_LOCK(&pAd->CommonCfg.TpcReqTabLock);
		for (i = 0; i < MAX_TPC_REQ_TAB_SIZE; i++)
		{
			NdisGetSystemUpTime(&Now);
			pEntry = &pTab->Content[i];

			if ((pEntry->Valid == true)
				&& RTMP_TIME_AFTER((unsigned long)Now, (unsigned long)(pEntry->lastTime + TPC_REQ_AGE_OUT)))
			{
				PTPC_REQ_ENTRY pPrevEntry = NULL;
				unsigned long HashIdx = TPC_DIALOGTOKEN_HASH_INDEX(pEntry->DialogToken);
				PTPC_REQ_ENTRY pProbeEntry = pTab->Hash[HashIdx];

				/* update Hash list*/
				do
				{
					if (pProbeEntry == pEntry)
					{
						if (pPrevEntry == NULL)
						{
							pTab->Hash[HashIdx] = pEntry->pNext;
						}
						else
						{
							pPrevEntry->pNext = pEntry->pNext;
						}
						break;
					}

					pPrevEntry = pProbeEntry;
					pProbeEntry = pProbeEntry->pNext;
				} while (pProbeEntry);

				memset(pEntry, 0, sizeof(TPC_REQ_ENTRY));
				pTab->Size--;

				break;
			}

			if (pEntry->Valid == false)
				break;
		}

		if (i < MAX_TPC_REQ_TAB_SIZE)
		{
			NdisGetSystemUpTime(&Now);
			pEntry->lastTime = Now;
			pEntry->Valid = true;
			pEntry->DialogToken = DialogToken;
			pTab->Size++;
		}
		else
		{
			pEntry = NULL;
			DBGPRINT(RT_DEBUG_ERROR, ("%s: pTpcReqTab tab full.\n", __FUNCTION__));
		}

		/* add this Neighbor entry into HASH table*/
		if (pEntry)
		{
			HashIdx = TPC_DIALOGTOKEN_HASH_INDEX(DialogToken);
			if (pTab->Hash[HashIdx] == NULL)
			{
				pTab->Hash[HashIdx] = pEntry;
			}
			else
			{
				pCurrEntry = pTab->Hash[HashIdx];
				while (pCurrEntry->pNext != NULL)
					pCurrEntry = pCurrEntry->pNext;
				pCurrEntry->pNext = pEntry;
			}
		}

		RTMP_SEM_UNLOCK(&pAd->CommonCfg.TpcReqTabLock);
	}

	return pEntry;
}

static void TpcReqDelete(
	struct rtmp_adapter *pAd,
	u8			DialogToken)
{
	PTPC_REQ_TAB pTab = pAd->CommonCfg.pTpcReqTab;
	PTPC_REQ_ENTRY pEntry = NULL;

	if(pTab == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: pTpcReqTab doesn't exist.\n", __FUNCTION__));
		return;
	}

	/* if empty, return*/
	if (pTab->Size == 0)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("pTpcReqTab empty.\n"));
		return;
	}

	pEntry = TpcReqLookUp(pAd, DialogToken);
	if (pEntry != NULL)
	{
		PTPC_REQ_ENTRY pPrevEntry = NULL;
		unsigned long HashIdx = TPC_DIALOGTOKEN_HASH_INDEX(pEntry->DialogToken);
		PTPC_REQ_ENTRY pProbeEntry = pTab->Hash[HashIdx];

		RTMP_SEM_LOCK(&pAd->CommonCfg.TpcReqTabLock);
		/* update Hash list*/
		do
		{
			if (pProbeEntry == pEntry)
			{
				if (pPrevEntry == NULL)
				{
					pTab->Hash[HashIdx] = pEntry->pNext;
				}
				else
				{
					pPrevEntry->pNext = pEntry->pNext;
				}
				break;
			}

			pPrevEntry = pProbeEntry;
			pProbeEntry = pProbeEntry->pNext;
		} while (pProbeEntry);

		memset(pEntry, 0, sizeof(TPC_REQ_ENTRY));
		pTab->Size--;

		RTMP_SEM_UNLOCK(&pAd->CommonCfg.TpcReqTabLock);
	}

	return;
}

/*
	==========================================================================
	Description:
		Get Current TimeS tamp.

	Parametrs:

	Return	: Current Time Stamp.
	==========================================================================
 */
static uint64_t GetCurrentTimeStamp(
	struct rtmp_adapter *pAd)
{
	/* get current time stamp.*/
	return 0;
}

/*
	==========================================================================
	Description:
		Get Current Transmit Power.

	Parametrs:

	Return	: Current Time Stamp.
	==========================================================================
 */
static u8 GetCurTxPwr(
	struct rtmp_adapter *pAd,
	u8 Wcid)
{
	return 16; /* 16 dBm */
}

/*
	==========================================================================
	Description:
		Get Current Transmit Power.

	Parametrs:

	Return	: Current Time Stamp.
	==========================================================================
 */
void InsertChannelRepIE(
	struct rtmp_adapter *pAd,
	u8 *pFrameBuf,
	unsigned long *pFrameLen,
	char *pCountry,
	u8 RegulatoryClass)
{
	unsigned long TempLen;
	u8 Len;
	u8 IEId = IE_AP_CHANNEL_REPORT;
	u8 *pChListPtr = NULL;
	PDOT11_CHANNEL_SET pChannelSet = NULL;

	Len = 1;
	if (strncmp(pCountry, "US", 2) == 0)
	{
		if (RegulatoryClass >= USA_REGULATORY_INFO_SIZE)
		{
			DBGPRINT(RT_DEBUG_ERROR, ("%s: USA Unknow Requlatory class (%d)\n",
						__FUNCTION__, RegulatoryClass));
			return;
		}
		pChannelSet = &USARegulatoryInfo[RegulatoryClass].ChannelSet;
	}
	else if (strncmp(pCountry, "JP", 2) == 0)
	{
		if (RegulatoryClass >= JP_REGULATORY_INFO_SIZE)
		{
			DBGPRINT(RT_DEBUG_ERROR, ("%s: JP Unknow Requlatory class (%d)\n",
						__FUNCTION__, RegulatoryClass));
			return;
		}

		pChannelSet = &JapanRegulatoryInfo[RegulatoryClass].ChannelSet;
	}
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: Unknow Country (%s)\n",
					__FUNCTION__, pCountry));
		return;
	}

	/* no match channel set. */
	if (pChannelSet == NULL)
		return;

	/* empty channel set. */
	if (pChannelSet->NumberOfChannels == 0)
		return;

	Len += pChannelSet->NumberOfChannels;
	pChListPtr = pChannelSet->ChannelList;

	if (Len > 1)
	{
		MakeOutgoingFrame(pFrameBuf,	&TempLen,
						1,				&IEId,
						1,				&Len,
						1,				&RegulatoryClass,
						Len -1,			pChListPtr,
						END_OF_ARGS);

		*pFrameLen = *pFrameLen + TempLen;
	}
	return;
}

/*
	==========================================================================
	Description:
		Insert Dialog Token into frame.

	Parametrs:
		1. frame buffer pointer.
		2. frame length.
		3. Dialog token.

	Return	: None.
	==========================================================================
 */
void InsertDialogToken(
	struct rtmp_adapter *pAd,
	u8 *pFrameBuf,
	unsigned long *pFrameLen,
	u8 DialogToken)
{
	unsigned long TempLen;
	MakeOutgoingFrame(pFrameBuf,	&TempLen,
					1,				&DialogToken,
					END_OF_ARGS);

	*pFrameLen = *pFrameLen + TempLen;

	return;
}

/*
	==========================================================================
	Description:
		Insert TPC Request IE into frame.

	Parametrs:
		1. frame buffer pointer.
		2. frame length.

	Return	: None.
	==========================================================================
 */
 static void InsertTpcReqIE(
	struct rtmp_adapter *pAd,
	u8 *pFrameBuf,
	unsigned long *pFrameLen)
{
	unsigned long TempLen;
	u8 Len = 0;
	u8 ElementID = IE_TPC_REQUEST;

	MakeOutgoingFrame(pFrameBuf,					&TempLen,
						1,							&ElementID,
						1,							&Len,
						END_OF_ARGS);

	*pFrameLen = *pFrameLen + TempLen;

	return;
}

/*
	==========================================================================
	Description:
		Insert TPC Report IE into frame.

	Parametrs:
		1. frame buffer pointer.
		2. frame length.
		3. Transmit Power.
		4. Link Margin.

	Return	: None.
	==========================================================================
 */
void InsertTpcReportIE(
	struct rtmp_adapter *pAd,
	u8 *pFrameBuf,
	unsigned long *pFrameLen,
	u8 TxPwr,
	u8 LinkMargin)
{
	unsigned long TempLen;
	u8 Len = sizeof(TPC_REPORT_INFO);
	u8 ElementID = IE_TPC_REPORT;
	TPC_REPORT_INFO TpcReportIE;

	TpcReportIE.TxPwr = TxPwr;
	TpcReportIE.LinkMargin = LinkMargin;

	MakeOutgoingFrame(pFrameBuf,					&TempLen,
						1,							&ElementID,
						1,							&Len,
						Len,						&TpcReportIE,
						END_OF_ARGS);

	*pFrameLen = *pFrameLen + TempLen;


	return;
}

/*
	==========================================================================
	Description:
		Insert Measure Request IE into frame.

	Parametrs:
		1. frame buffer pointer.
		2. frame length.
		3. Measure Token.
		4. Measure Request Mode.
		5. Measure Request Type.
		6. Measure Channel.
		7. Measure Start time.
		8. Measure Duration.


	Return	: None.
	==========================================================================
 */
static void InsertMeasureReqIE(
	struct rtmp_adapter *pAd,
	u8 *pFrameBuf,
	unsigned long *pFrameLen,
	u8 Len,
	PMEASURE_REQ_INFO pMeasureReqIE)
{
	unsigned long TempLen;
	u8 ElementID = IE_MEASUREMENT_REQUEST;

	MakeOutgoingFrame(pFrameBuf,					&TempLen,
						1,							&ElementID,
						1,							&Len,
						sizeof(MEASURE_REQ_INFO),	pMeasureReqIE,
						END_OF_ARGS);

	*pFrameLen = *pFrameLen + TempLen;

	return;
}

/*
	==========================================================================
	Description:
		Insert Measure Report IE into frame.

	Parametrs:
		1. frame buffer pointer.
		2. frame length.
		3. Measure Token.
		4. Measure Request Mode.
		5. Measure Request Type.
		6. Length of Report Infomation
		7. Pointer of Report Infomation Buffer.

	Return	: None.
	==========================================================================
 */
static void InsertMeasureReportIE(
	struct rtmp_adapter *pAd,
	u8 *pFrameBuf,
	unsigned long *pFrameLen,
	PMEASURE_REPORT_INFO pMeasureReportIE,
	u8 ReportLnfoLen,
	u8 * pReportInfo)
{
	unsigned long TempLen;
	u8 Len;
	u8 ElementID = IE_MEASUREMENT_REPORT;

	Len = sizeof(MEASURE_REPORT_INFO) + ReportLnfoLen;

	MakeOutgoingFrame(pFrameBuf,					&TempLen,
						1,							&ElementID,
						1,							&Len,
						Len,						pMeasureReportIE,
						END_OF_ARGS);

	*pFrameLen = *pFrameLen + TempLen;

	if ((ReportLnfoLen > 0) && (pReportInfo != NULL))
	{
		MakeOutgoingFrame(pFrameBuf + *pFrameLen,		&TempLen,
							ReportLnfoLen,				pReportInfo,
							END_OF_ARGS);

		*pFrameLen = *pFrameLen + TempLen;
	}
	return;
}

/*
	==========================================================================
	Description:
		Prepare Measurement request action frame and enqueue it into
		management queue waiting for transmition.

	Parametrs:
		1. the destination mac address of the frame.

	Return	: None.
	==========================================================================
 */
void MakeMeasurementReqFrame(
	struct rtmp_adapter *pAd,
	u8 *pOutBuffer,
	unsigned long *pFrameLen,
	u8 TotalLen,
	u8 Category,
	u8 Action,
	u8 MeasureToken,
	u8 MeasureReqMode,
	u8 MeasureReqType,
	uint16_t NumOfRepetitions)
{
	unsigned long TempLen;
	MEASURE_REQ_INFO MeasureReqIE;

	InsertActField(pAd, (pOutBuffer + *pFrameLen), pFrameLen, Category, Action);

	/* fill Dialog Token*/
	InsertDialogToken(pAd, (pOutBuffer + *pFrameLen), pFrameLen, MeasureToken);

	/* fill Number of repetitions. */
	if (Category == CATEGORY_RM)
	{
		MakeOutgoingFrame((pOutBuffer+*pFrameLen),	&TempLen,
						2,							&NumOfRepetitions,
						END_OF_ARGS);

		*pFrameLen += TempLen;
	}

	/* prepare Measurement IE.*/
	memset(&MeasureReqIE, 0, sizeof(MEASURE_REQ_INFO));
	MeasureReqIE.Token = MeasureToken;
	MeasureReqIE.ReqMode.word = MeasureReqMode;
	MeasureReqIE.ReqType = MeasureReqType;
	InsertMeasureReqIE(pAd, (pOutBuffer+*pFrameLen), pFrameLen,
		TotalLen, &MeasureReqIE);

	return;
}

/*
	==========================================================================
	Description:
		Prepare Measurement report action frame and enqueue it into
		management queue waiting for transmition.

	Parametrs:
		1. the destination mac address of the frame.

	Return	: None.
	==========================================================================
 */
void EnqueueMeasurementRep(
	struct rtmp_adapter *pAd,
	u8 *pDA,
	u8 DialogToken,
	u8 MeasureToken,
	u8 MeasureReqMode,
	u8 MeasureReqType,
	u8 ReportInfoLen,
	u8 * pReportInfo)
{
	u8 *pOutBuffer = NULL;
	unsigned long FrameLen;
	HEADER_802_11 ActHdr;
	MEASURE_REPORT_INFO MeasureRepIE;

	/* build action frame header.*/
	MgtMacHeaderInit(pAd, &ActHdr, SUBTYPE_ACTION, 0, pDA,
						pAd->CurrentAddress);

	pOutBuffer = kmalloc(MGMT_DMA_BUFFER_SIZE, GFP_ATOMIC);  /*Get an unused nonpaged memory*/
	if(pOutBuffer == NULL)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("%s() allocate memory failed \n", __FUNCTION__));
		return;
	}
	memmove(pOutBuffer, (char *)&ActHdr, sizeof(HEADER_802_11));
	FrameLen = sizeof(HEADER_802_11);

	InsertActField(pAd, (pOutBuffer + FrameLen), &FrameLen, CATEGORY_SPECTRUM, SPEC_MRP);

	/* fill Dialog Token*/
	InsertDialogToken(pAd, (pOutBuffer + FrameLen), &FrameLen, DialogToken);

	/* prepare Measurement IE.*/
	memset(&MeasureRepIE, 0, sizeof(MEASURE_REPORT_INFO));
	MeasureRepIE.Token = MeasureToken;
	MeasureRepIE.ReportMode = MeasureReqMode;
	MeasureRepIE.ReportType = MeasureReqType;
	InsertMeasureReportIE(pAd, (pOutBuffer + FrameLen), &FrameLen, &MeasureRepIE, ReportInfoLen, pReportInfo);

	MiniportMMRequest(pAd, QID_AC_BE, pOutBuffer, FrameLen);
	kfree(pOutBuffer);

	return;
}

/*
	==========================================================================
	Description:
		Prepare TPC Request action frame and enqueue it into
		management queue waiting for transmition.

	Parametrs:
		1. the destination mac address of the frame.

	Return	: None.
	==========================================================================
 */
void EnqueueTPCReq(
	struct rtmp_adapter *pAd,
	u8 *pDA,
	u8 DialogToken)
{
	u8 *pOutBuffer = NULL;
	unsigned long FrameLen;

	HEADER_802_11 ActHdr;

	/* build action frame header.*/
	MgtMacHeaderInit(pAd, &ActHdr, SUBTYPE_ACTION, 0, pDA,
						pAd->CurrentAddress);

	pOutBuffer = kmalloc(MGMT_DMA_BUFFER_SIZE, GFP_ATOMIC);  /*Get an unused nonpaged memory*/
	if(pOutBuffer == NULL)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("%s() allocate memory failed \n", __FUNCTION__));
		return;
	}
	memmove(pOutBuffer, (char *)&ActHdr, sizeof(HEADER_802_11));
	FrameLen = sizeof(HEADER_802_11);

	InsertActField(pAd, (pOutBuffer + FrameLen), &FrameLen, CATEGORY_SPECTRUM, SPEC_TPCRQ);

	/* fill Dialog Token*/
	InsertDialogToken(pAd, (pOutBuffer + FrameLen), &FrameLen, DialogToken);

	/* Insert TPC Request IE.*/
	InsertTpcReqIE(pAd, (pOutBuffer + FrameLen), &FrameLen);

	MiniportMMRequest(pAd, QID_AC_BE, pOutBuffer, FrameLen);
	kfree(pOutBuffer);

	return;
}

/*
	==========================================================================
	Description:
		Prepare TPC Report action frame and enqueue it into
		management queue waiting for transmition.

	Parametrs:
		1. the destination mac address of the frame.

	Return	: None.
	==========================================================================
 */
void EnqueueTPCRep(
	struct rtmp_adapter *pAd,
	u8 *pDA,
	u8 DialogToken,
	u8 TxPwr,
	u8 LinkMargin)
{
	u8 *pOutBuffer = NULL;
	unsigned long FrameLen;

	HEADER_802_11 ActHdr;

	/* build action frame header.*/
	MgtMacHeaderInit(pAd, &ActHdr, SUBTYPE_ACTION, 0, pDA,
						pAd->CurrentAddress);

	pOutBuffer = kmalloc(MGMT_DMA_BUFFER_SIZE, GFP_ATOMIC);  /*Get an unused nonpaged memory*/
	if(pOutBuffer == NULL)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("%s() allocate memory failed \n", __FUNCTION__));
		return;
	}
	memmove(pOutBuffer, (char *)&ActHdr, sizeof(HEADER_802_11));
	FrameLen = sizeof(HEADER_802_11);

	InsertActField(pAd, (pOutBuffer + FrameLen), &FrameLen, CATEGORY_SPECTRUM, SPEC_TPCRP);

	/* fill Dialog Token*/
	InsertDialogToken(pAd, (pOutBuffer + FrameLen), &FrameLen, DialogToken);

	/* Insert TPC Request IE.*/
	InsertTpcReportIE(pAd, (pOutBuffer + FrameLen), &FrameLen, TxPwr, LinkMargin);

	MiniportMMRequest(pAd, QID_AC_BE, pOutBuffer, FrameLen);
	kfree(pOutBuffer);

	return;
}

static bool DfsRequirementCheck(
	struct rtmp_adapter *pAd,
	u8 Channel)
{
	bool Result = false;
	INT i;

	do
	{
		/* check DFS procedure is running.*/
		/* make sure DFS procedure won't start twice.*/
		if (pAd->Dot11_H.RDMode != RD_NORMAL_MODE)
		{
			Result = false;
			break;
		}

		/* check the new channel carried from Channel Switch Announcemnet is valid.*/
		for (i=0; i<pAd->ChannelListNum; i++)
		{
			if ((Channel == pAd->ChannelList[i].Channel)
				&&(pAd->ChannelList[i].RemainingTimeForUse == 0))
			{
				/* found radar signal in the channel. the channel can't use at least for 30 minutes.*/
				pAd->ChannelList[i].RemainingTimeForUse = 1800;/*30 min = 1800 sec*/
				Result = true;
				break;
			}
		}
	} while(false);

	return Result;
}

void NotifyChSwAnnToPeerAPs(
	struct rtmp_adapter *pAd,
	u8 *pRA,
	u8 *pTA,
	u8 ChSwMode,
	u8 Channel)
{
}

static void StartDFSProcedure(
	struct rtmp_adapter *pAd,
	u8 Channel,
	u8 ChSwMode)
{
	/* start DFS procedure*/
	pAd->CommonCfg.Channel = Channel;
#ifdef DOT11_N_SUPPORT
	N_ChannelCheck(pAd);
#endif /* DOT11_N_SUPPORT */
	pAd->Dot11_H.RDMode = RD_SWITCHING_MODE;
	pAd->Dot11_H.CSCount = 0;
}

/*
	==========================================================================
	Description:
		Channel Switch Announcement action frame sanity check.

	Parametrs:
		1. MLME message containing the received frame
		2. message length.
		3. Channel switch announcement infomation buffer.


	Return	: None.
	==========================================================================
 */

/*
  Channel Switch Announcement IE.
  +----+-----+-----------+------------+-----------+
  | ID | Len |Ch Sw Mode | New Ch Num | Ch Sw Cnt |
  +----+-----+-----------+------------+-----------+
    1    1        1           1            1
*/
static bool PeerChSwAnnSanity(
	struct rtmp_adapter *pAd,
	void *pMsg,
	unsigned long MsgLen,
	PCH_SW_ANN_INFO pChSwAnnInfo)
{
	PFRAME_802_11 Fr = (PFRAME_802_11)pMsg;
	u8 *pFramePtr = Fr->Octet;
	bool result = false;
	PEID_STRUCT eid_ptr;

	/* skip 802.11 header.*/
	MsgLen -= sizeof(HEADER_802_11);

	/* skip category and action code.*/
	pFramePtr += 2;
	MsgLen -= 2;

	if (pChSwAnnInfo == NULL)
		return result;

	eid_ptr = (PEID_STRUCT)pFramePtr;
	while (((u8 *)eid_ptr + eid_ptr->Len + 1) < ((u8 *)pFramePtr + MsgLen))
	{
		switch(eid_ptr->Eid)
		{
			case IE_CHANNEL_SWITCH_ANNOUNCEMENT:
				memmove(&pChSwAnnInfo->ChSwMode, eid_ptr->Octet, 1);
				memmove(&pChSwAnnInfo->Channel, eid_ptr->Octet + 1, 1);
				memmove(&pChSwAnnInfo->ChSwCnt, eid_ptr->Octet + 2, 1);

				result = true;
                break;

			default:
				break;
		}
		eid_ptr = (PEID_STRUCT)((u8 *)eid_ptr + 2 + eid_ptr->Len);
	}

	return result;
}

/*
	==========================================================================
	Description:
		Measurement request action frame sanity check.

	Parametrs:
		1. MLME message containing the received frame
		2. message length.
		3. Measurement request infomation buffer.

	Return	: None.
	==========================================================================
 */
static bool PeerMeasureReqSanity(
	struct rtmp_adapter *pAd,
	void *pMsg,
	unsigned long MsgLen,
	u8 * pDialogToken,
	PMEASURE_REQ_INFO pMeasureReqInfo,
	PMEASURE_REQ pMeasureReq)
{
	PFRAME_802_11 Fr = (PFRAME_802_11)pMsg;
	u8 *pFramePtr = Fr->Octet;
	bool result = false;
	PEID_STRUCT eid_ptr;
	u8 *ptr;
	uint64_t MeasureStartTime;
	uint16_t MeasureDuration;

	/* skip 802.11 header.*/
	MsgLen -= sizeof(HEADER_802_11);

	/* skip category and action code.*/
	pFramePtr += 2;
	MsgLen -= 2;

	if (pMeasureReqInfo == NULL)
		return result;

	memmove(pDialogToken, pFramePtr, 1);
	pFramePtr += 1;
	MsgLen -= 1;

	eid_ptr = (PEID_STRUCT)pFramePtr;
	while (((u8 *)eid_ptr + eid_ptr->Len + 1) < ((u8 *)pFramePtr + MsgLen))
	{
		switch(eid_ptr->Eid)
		{
			case IE_MEASUREMENT_REQUEST:
				memmove(&pMeasureReqInfo->Token, eid_ptr->Octet, 1);
				memmove(&pMeasureReqInfo->ReqMode.word, eid_ptr->Octet + 1, 1);
				memmove(&pMeasureReqInfo->ReqType, eid_ptr->Octet + 2, 1);
				ptr = (u8 *)(eid_ptr->Octet + 3);
				memmove(&pMeasureReq->ChNum, ptr, 1);
				memmove(&MeasureStartTime, ptr + 1, 8);
				pMeasureReq->MeasureStartTime = SWAP64(MeasureStartTime);
				memmove(&MeasureDuration, ptr + 9, 2);
				pMeasureReq->MeasureDuration = SWAP16(MeasureDuration);

				result = true;
				break;

			default:
				break;
		}
		eid_ptr = (PEID_STRUCT)((u8 *)eid_ptr + 2 + eid_ptr->Len);
	}

	return result;
}

/*
	==========================================================================
	Description:
		Measurement report action frame sanity check.

	Parametrs:
		1. MLME message containing the received frame
		2. message length.
		3. Measurement report infomation buffer.
		4. basic report infomation buffer.

	Return	: None.
	==========================================================================
 */

/*
  Measurement Report IE.
  +----+-----+-------+-------------+--------------+----------------+
  | ID | Len | Token | Report Mode | Measure Type | Measure Report |
  +----+-----+-------+-------------+--------------+----------------+
    1     1      1          1             1            variable

  Basic Report.
  +--------+------------+----------+-----+
  | Ch Num | Start Time | Duration | Map |
  +--------+------------+----------+-----+
      1          8           2        1

  Map Field Bit Format.
  +-----+---------------+---------------------+-------+------------+----------+
  | Bss | OFDM Preamble | Unidentified signal | Radar | Unmeasured | Reserved |
  +-----+---------------+---------------------+-------+------------+----------+
     0          1                  2              3         4          5-7
*/
static bool PeerMeasureReportSanity(
	struct rtmp_adapter *pAd,
	void *pMsg,
	unsigned long MsgLen,
	u8 * pDialogToken,
	PMEASURE_REPORT_INFO pMeasureReportInfo,
	u8 * pReportBuf)
{
	PFRAME_802_11 Fr = (PFRAME_802_11)pMsg;
	u8 *pFramePtr = Fr->Octet;
	bool result = false;
	PEID_STRUCT eid_ptr;
	u8 *ptr;

	/* skip 802.11 header.*/
	MsgLen -= sizeof(HEADER_802_11);

	/* skip category and action code.*/
	pFramePtr += 2;
	MsgLen -= 2;

	if (pMeasureReportInfo == NULL)
		return result;

	memmove(pDialogToken, pFramePtr, 1);
	pFramePtr += 1;
	MsgLen -= 1;

	eid_ptr = (PEID_STRUCT)pFramePtr;
	while (((u8 *)eid_ptr + eid_ptr->Len + 1) < ((u8 *)pFramePtr + MsgLen))
	{
		switch(eid_ptr->Eid)
		{
			case IE_MEASUREMENT_REPORT:
				memmove(&pMeasureReportInfo->Token, eid_ptr->Octet, 1);
				memmove(&pMeasureReportInfo->ReportMode, eid_ptr->Octet + 1, 1);
				memmove(&pMeasureReportInfo->ReportType, eid_ptr->Octet + 2, 1);
				if (pMeasureReportInfo->ReportType == RM_BASIC)
				{
					PMEASURE_BASIC_REPORT pReport = (PMEASURE_BASIC_REPORT)pReportBuf;
					ptr = (u8 *)(eid_ptr->Octet + 3);
					memmove(&pReport->ChNum, ptr, 1);
					memmove(&pReport->MeasureStartTime, ptr + 1, 8);
					memmove(&pReport->MeasureDuration, ptr + 9, 2);
					memmove(&pReport->Map, ptr + 11, 1);

				}
				else if (pMeasureReportInfo->ReportType == RM_CCA)
				{
					PMEASURE_CCA_REPORT pReport = (PMEASURE_CCA_REPORT)pReportBuf;
					ptr = (u8 *)(eid_ptr->Octet + 3);
					memmove(&pReport->ChNum, ptr, 1);
					memmove(&pReport->MeasureStartTime, ptr + 1, 8);
					memmove(&pReport->MeasureDuration, ptr + 9, 2);
					memmove(&pReport->CCA_Busy_Fraction, ptr + 11, 1);

				}
				else if (pMeasureReportInfo->ReportType == RM_RPI_HISTOGRAM)
				{
					PMEASURE_RPI_REPORT pReport = (PMEASURE_RPI_REPORT)pReportBuf;
					ptr = (u8 *)(eid_ptr->Octet + 3);
					memmove(&pReport->ChNum, ptr, 1);
					memmove(&pReport->MeasureStartTime, ptr + 1, 8);
					memmove(&pReport->MeasureDuration, ptr + 9, 2);
					memmove(&pReport->RPI_Density, ptr + 11, 8);
				}
				result = true;
                break;

			default:
				break;
		}
		eid_ptr = (PEID_STRUCT)((u8 *)eid_ptr + 2 + eid_ptr->Len);
	}

	return result;
}

/*
	==========================================================================
	Description:
		TPC Request action frame sanity check.

	Parametrs:
		1. MLME message containing the received frame
		2. message length.
		3. Dialog Token.

	Return	: None.
	==========================================================================
 */
static bool PeerTpcReqSanity(
	struct rtmp_adapter *pAd,
	void *pMsg,
	unsigned long MsgLen,
	u8 * pDialogToken)
{
	PFRAME_802_11 Fr = (PFRAME_802_11)pMsg;
	u8 *pFramePtr = Fr->Octet;
	bool result = false;
	PEID_STRUCT eid_ptr;

	MsgLen -= sizeof(HEADER_802_11);

	/* skip category and action code.*/
	pFramePtr += 2;
	MsgLen -= 2;

	if (pDialogToken == NULL)
		return result;

	memmove(pDialogToken, pFramePtr, 1);
	pFramePtr += 1;
	MsgLen -= 1;

	eid_ptr = (PEID_STRUCT)pFramePtr;
	while (((u8 *)eid_ptr + eid_ptr->Len + 1) < ((u8 *)pFramePtr + MsgLen))
	{
		switch(eid_ptr->Eid)
		{
			case IE_TPC_REQUEST:
				result = true;
                break;

			default:
				break;
		}
		eid_ptr = (PEID_STRUCT)((u8 *)eid_ptr + 2 + eid_ptr->Len);
	}

	return result;
}

/*
	==========================================================================
	Description:
		TPC Report action frame sanity check.

	Parametrs:
		1. MLME message containing the received frame
		2. message length.
		3. Dialog Token.
		4. TPC Report IE.

	Return	: None.
	==========================================================================
 */
static bool PeerTpcRepSanity(
	struct rtmp_adapter *pAd,
	void *pMsg,
	unsigned long MsgLen,
	u8 * pDialogToken,
	PTPC_REPORT_INFO pTpcRepInfo)
{
	PFRAME_802_11 Fr = (PFRAME_802_11)pMsg;
	u8 *pFramePtr = Fr->Octet;
	bool result = false;
	PEID_STRUCT eid_ptr;

	MsgLen -= sizeof(HEADER_802_11);

	/* skip category and action code.*/
	pFramePtr += 2;
	MsgLen -= 2;

	if (pDialogToken == NULL)
		return result;

	memmove(pDialogToken, pFramePtr, 1);
	pFramePtr += 1;
	MsgLen -= 1;

	eid_ptr = (PEID_STRUCT)pFramePtr;
	while (((u8 *)eid_ptr + eid_ptr->Len + 1) < ((u8 *)pFramePtr + MsgLen))
	{
		switch(eid_ptr->Eid)
		{
			case IE_TPC_REPORT:
				memmove(&pTpcRepInfo->TxPwr, eid_ptr->Octet, 1);
				memmove(&pTpcRepInfo->LinkMargin, eid_ptr->Octet + 1, 1);
				result = true;
                break;

			default:
				break;
		}
		eid_ptr = (PEID_STRUCT)((u8 *)eid_ptr + 2 + eid_ptr->Len);
	}

	return result;
}

/*
	==========================================================================
	Description:
		Channel Switch Announcement action frame handler.

	Parametrs:
		Elme - MLME message containing the received frame

	Return	: None.
	==========================================================================
 */
static void PeerChSwAnnAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{
	CH_SW_ANN_INFO ChSwAnnInfo;
	PFRAME_802_11 pFr = (PFRAME_802_11)Elem->Msg;
#ifdef CONFIG_STA_SUPPORT
	u8 index = 0, Channel = 0, NewChannel = 0;
	unsigned long Bssidx = 0;
#endif /* CONFIG_STA_SUPPORT */

	memset(&ChSwAnnInfo, 0, sizeof(CH_SW_ANN_INFO));
	if (! PeerChSwAnnSanity(pAd, Elem->Msg, Elem->MsgLen, &ChSwAnnInfo))
	{
		DBGPRINT(RT_DEBUG_TRACE, ("Invalid Channel Switch Action Frame.\n"));
		return;
	}


#ifdef CONFIG_STA_SUPPORT
	if (pAd->OpMode == OPMODE_STA)
	{
		Bssidx = BssTableSearch(&pAd->ScanTab, pFr->Hdr.Addr3, pAd->CommonCfg.Channel);
		if (Bssidx == BSS_NOT_FOUND)
		{
			DBGPRINT(RT_DEBUG_TRACE, ("PeerChSwAnnAction - Bssidx is not found\n"));
			return;
		}

		DBGPRINT(RT_DEBUG_TRACE, ("\n****Bssidx is %d, Channel = %d\n", index, pAd->ScanTab.BssEntry[Bssidx].Channel));

		Channel = pAd->CommonCfg.Channel;
		NewChannel = ChSwAnnInfo.Channel;

		if ((pAd->CommonCfg.bIEEE80211H == 1) && (NewChannel != 0) && (Channel != NewChannel))
		{
			/* Switching to channel 1 can prevent from rescanning the current channel immediately (by auto reconnection).*/
			/* In addition, clear the MLME queue and the scan table to discard the RX packets and previous scanning results.*/
			AsicSwitchChannel(pAd, 1, false);
			AsicLockChannel(pAd, 1);
			LinkDown(pAd, false);
			MlmeQueueInit(pAd, &pAd->Mlme.Queue);
		    RTMPusecDelay(1000000);		/* use delay to prevent STA do reassoc*/

			/* channel sanity check*/
			for (index = 0 ; index < pAd->ChannelListNum; index++)
			{
				if (pAd->ChannelList[index].Channel == NewChannel)
				{
					pAd->ScanTab.BssEntry[Bssidx].Channel = NewChannel;
					pAd->CommonCfg.Channel = NewChannel;
					AsicSwitchChannel(pAd, pAd->CommonCfg.Channel, false);
					AsicLockChannel(pAd, pAd->CommonCfg.Channel);
					DBGPRINT(RT_DEBUG_TRACE, ("&&&&&&&&&&&&&&&&PeerChSwAnnAction - STA receive channel switch announcement IE (New Channel =%d)\n", NewChannel));
					break;
				}
			}

			if (index >= pAd->ChannelListNum)
			{
				DBGPRINT_ERR(("&&&&&&&&&&&&&&&&&&&&&&&&&&PeerChSwAnnAction(can not find New Channel=%d in ChannelList[%d]\n", pAd->CommonCfg.Channel, pAd->ChannelListNum));
			}
		}
	}
#endif /* CONFIG_STA_SUPPORT */

	return;
}


/*
	==========================================================================
	Description:
		Measurement Request action frame handler.

	Parametrs:
		Elme - MLME message containing the received frame

	Return	: None.
	==========================================================================
 */
static void PeerMeasureReqAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{
	PFRAME_802_11 pFr = (PFRAME_802_11)Elem->Msg;
	u8 DialogToken;
	MEASURE_REQ_INFO MeasureReqInfo;
	MEASURE_REQ	MeasureReq;
	MEASURE_REPORT_MODE ReportMode;

	if(PeerMeasureReqSanity(pAd, Elem->Msg, Elem->MsgLen, &DialogToken, &MeasureReqInfo, &MeasureReq))
	{
		ReportMode.word = 0;
		ReportMode.field.Incapable = 1;
		EnqueueMeasurementRep(pAd, pFr->Hdr.Addr2, DialogToken, MeasureReqInfo.Token, ReportMode.word, MeasureReqInfo.ReqType, 0, NULL);
	}

	return;
}

/*
	==========================================================================
	Description:
		Measurement Report action frame handler.

	Parametrs:
		Elme - MLME message containing the received frame

	Return	: None.
	==========================================================================
 */
static void PeerMeasureReportAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{
	MEASURE_REPORT_INFO MeasureReportInfo;
	PFRAME_802_11 pFr = (PFRAME_802_11)Elem->Msg;
	u8 DialogToken;
	u8 * pMeasureReportInfo;

/*	if (pAd->CommonCfg.bIEEE80211H != true)*/
/*		return;*/

	pMeasureReportInfo = kmalloc(sizeof(MEASURE_RPI_REPORT), GFP_ATOMIC);
/*	if ((pMeasureReportInfo = kmalloc(sizeof(MEASURE_RPI_REPORT), GFP_ATOMIC)) == NULL)*/
	if (pMeasureReportInfo == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s unable to alloc memory for measure report buffer (size=%d).\n",
			__FUNCTION__, (int) sizeof(MEASURE_RPI_REPORT)));
		return;
	}

	memset(&MeasureReportInfo, 0, sizeof(MEASURE_REPORT_INFO));
	memset(pMeasureReportInfo, 0, sizeof(MEASURE_RPI_REPORT));
	if (PeerMeasureReportSanity(pAd, Elem->Msg, Elem->MsgLen, &DialogToken, &MeasureReportInfo, pMeasureReportInfo))
	{
		do {
			PMEASURE_REQ_ENTRY pEntry = NULL;

			/* Not a autonomous measure report.*/
			/* check the dialog token field. drop it if the dialog token doesn't match.*/
			if ((DialogToken != 0)
				&& ((pEntry = MeasureReqLookUp(pAd, DialogToken)) == NULL))
				break;

			if (pEntry != NULL)
				MeasureReqDelete(pAd, pEntry->DialogToken);

			if (MeasureReportInfo.ReportType == RM_BASIC)
			{
				PMEASURE_BASIC_REPORT pBasicReport = (PMEASURE_BASIC_REPORT)pMeasureReportInfo;
				if ((pBasicReport->Map.field.Radar)
					&& (DfsRequirementCheck(pAd, pBasicReport->ChNum) == true))
				{
					NotifyChSwAnnToPeerAPs(pAd, pFr->Hdr.Addr1, pFr->Hdr.Addr2, 1, pBasicReport->ChNum);
					StartDFSProcedure(pAd, pBasicReport->ChNum, 1);
				}
			}
		} while (false);
	}
	else
		DBGPRINT(RT_DEBUG_TRACE, ("Invalid Measurement Report Frame.\n"));

/*	kfree(pMeasureReportInfo);*/
	kfree(pMeasureReportInfo);

	return;
}

/*
	==========================================================================
	Description:
		TPC Request action frame handler.

	Parametrs:
		Elme - MLME message containing the received frame

	Return	: None.
	==========================================================================
 */
static void PeerTpcReqAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{
	PFRAME_802_11 pFr = (PFRAME_802_11)Elem->Msg;
	u8 *pFramePtr = pFr->Octet;
	u8 DialogToken;
	u8 TxPwr = GetCurTxPwr(pAd, Elem->Wcid);
	u8 LinkMargin = 0;
	CHAR RealRssi;

	/* link margin: Ratio of the received signal power to the minimum desired by the station (STA). The*/
	/*				STA may incorporate rate information and channel conditions, including interference, into its computation*/
	/*				of link margin.*/

	RealRssi = RTMPMaxRssi(pAd, ConvertToRssi(pAd, Elem->Rssi0, RSSI_0),
								ConvertToRssi(pAd, Elem->Rssi1, RSSI_1),
								ConvertToRssi(pAd, Elem->Rssi2, RSSI_2));

	/* skip Category and action code.*/
	pFramePtr += 2;

	/* Dialog token.*/
	memmove(&DialogToken, pFramePtr, 1);

	LinkMargin = (RealRssi / MIN_RCV_PWR);
	if (PeerTpcReqSanity(pAd, Elem->Msg, Elem->MsgLen, &DialogToken))
		EnqueueTPCRep(pAd, pFr->Hdr.Addr2, DialogToken, TxPwr, LinkMargin);

	return;
}

/*
	==========================================================================
	Description:
		TPC Report action frame handler.

	Parametrs:
		Elme - MLME message containing the received frame

	Return	: None.
	==========================================================================
 */
static void PeerTpcRepAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{
	u8 DialogToken;
	TPC_REPORT_INFO TpcRepInfo;
	PTPC_REQ_ENTRY pEntry = NULL;

	memset(&TpcRepInfo, 0, sizeof(TPC_REPORT_INFO));
	if (PeerTpcRepSanity(pAd, Elem->Msg, Elem->MsgLen, &DialogToken, &TpcRepInfo))
	{
		if ((pEntry = TpcReqLookUp(pAd, DialogToken)) != NULL)
		{
			TpcReqDelete(pAd, pEntry->DialogToken);
			DBGPRINT(RT_DEBUG_TRACE, ("%s: DialogToken=%x, TxPwr=%d, LinkMargin=%d\n",
				__FUNCTION__, DialogToken, TpcRepInfo.TxPwr, TpcRepInfo.LinkMargin));
		}
	}

	return;
}

/*
	==========================================================================
	Description:
		Spectrun action frames Handler such as channel switch annoucement,
		measurement report, measurement request actions frames.

	Parametrs:
		Elme - MLME message containing the received frame

	Return	: None.
	==========================================================================
 */
void PeerSpectrumAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{

	u8 Action = Elem->Msg[LENGTH_802_11+1];

	if (pAd->CommonCfg.bIEEE80211H != true)
		return;

	switch(Action)
	{
		case SPEC_MRQ:
			/* current rt2860 unable do such measure specified in Measurement Request.*/
			/* reject all measurement request.*/
			PeerMeasureReqAction(pAd, Elem);
			break;

		case SPEC_MRP:
			PeerMeasureReportAction(pAd, Elem);
			break;

		case SPEC_TPCRQ:
			PeerTpcReqAction(pAd, Elem);
			break;

		case SPEC_TPCRP:
			PeerTpcRepAction(pAd, Elem);
			break;

		case SPEC_CHANNEL_SWITCH:

#ifdef DOT11N_DRAFT3
			{
				SEC_CHA_OFFSET_IE	Secondary;
				CHA_SWITCH_ANNOUNCE_IE	ChannelSwitch;

				/* 802.11h only has Channel Switch Announcement IE. */
				memmove(&ChannelSwitch, &Elem->Msg[LENGTH_802_11+4], sizeof (CHA_SWITCH_ANNOUNCE_IE));

				/* 802.11n D3.03 adds secondary channel offset element in the end.*/
				if (Elem->MsgLen ==  (LENGTH_802_11 + 2 + sizeof (CHA_SWITCH_ANNOUNCE_IE) + sizeof (SEC_CHA_OFFSET_IE)))
				{
					memmove(&Secondary, &Elem->Msg[LENGTH_802_11+9], sizeof (SEC_CHA_OFFSET_IE));
				}
				else
				{
					Secondary.SecondaryChannelOffset = 0;
				}

				if ((Elem->Msg[LENGTH_802_11+2] == IE_CHANNEL_SWITCH_ANNOUNCEMENT) && (Elem->Msg[LENGTH_802_11+3] == 3))
				{
					ChannelSwitchAction(pAd, Elem->Wcid, ChannelSwitch.NewChannel, Secondary.SecondaryChannelOffset);
				}
			}
#endif /* DOT11N_DRAFT3 */

			PeerChSwAnnAction(pAd, Elem);
			break;
	}

	return;
}

/*
	==========================================================================
	Description:

	Parametrs:

	Return	: None.
	==========================================================================
 */
INT Set_MeasureReq_Proc(
	struct rtmp_adapter *pAd,
	char *		arg)
{
	UINT Aid = 1;
	UINT ArgIdx;
	char *thisChar;

	MEASURE_REQ_MODE MeasureReqMode;
	u8 MeasureReqToken = RandomByte(pAd);
	u8 MeasureReqType = RM_BASIC;
	u8 MeasureCh = 1;
	uint64_t MeasureStartTime = GetCurrentTimeStamp(pAd);
	MEASURE_REQ MeasureReq;
	u8 TotalLen;

	HEADER_802_11 ActHdr;
	u8 *pOutBuffer = NULL;
	unsigned long FrameLen;

	pOutBuffer = kmalloc(MGMT_DMA_BUFFER_SIZE, GFP_ATOMIC);  /*Get an unused nonpaged memory*/
	if(pOutBuffer != NDIS_STATUS_SUCCESS)
	{
		DBGPRINT(RT_DEBUG_TRACE, ("%s() allocate memory failed \n", __FUNCTION__));
		goto END_OF_MEASURE_REQ;
	}

	ArgIdx = 1;
	while ((thisChar = strsep((char **)&arg, "-")) != NULL)
	{
		switch(ArgIdx)
		{
			case 1:	/* Aid.*/
				Aid = (u8) simple_strtol(thisChar, 0, 16);
				break;

			case 2: /* Measurement Request Type.*/
				MeasureReqType = simple_strtol(thisChar, 0, 16);
				if (MeasureReqType > 3)
				{
					DBGPRINT(RT_DEBUG_ERROR, ("%s: unknow MeasureReqType(%d)\n", __FUNCTION__, MeasureReqType));
					goto END_OF_MEASURE_REQ;
				}
				break;

			case 3: /* Measurement channel.*/
				MeasureCh = (u8) simple_strtol(thisChar, 0, 16);
				break;
		}
		ArgIdx++;
	}

	DBGPRINT(RT_DEBUG_TRACE, ("%s::Aid = %d, MeasureReqType=%d MeasureCh=%d\n", __FUNCTION__, Aid, MeasureReqType, MeasureCh));
	if (!VALID_WCID(Aid))
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: unknow sta of Aid(%d)\n", __FUNCTION__, Aid));
		goto END_OF_MEASURE_REQ;
	}

	MeasureReqMode.word = 0;
	MeasureReqMode.field.Enable = 1;

	MeasureReqInsert(pAd, MeasureReqToken);

	/* build action frame header.*/
	MgtMacHeaderInit(pAd, &ActHdr, SUBTYPE_ACTION, 0, pAd->MacTab.Content[Aid].Addr,
						pAd->CurrentAddress);

	memmove(pOutBuffer, (char *)&ActHdr, sizeof(HEADER_802_11));
	FrameLen = sizeof(HEADER_802_11);

	TotalLen = sizeof(MEASURE_REQ_INFO) + sizeof(MEASURE_REQ);

	MakeMeasurementReqFrame(pAd, pOutBuffer, &FrameLen,
		sizeof(MEASURE_REQ_INFO), CATEGORY_RM, RM_BASIC,
		MeasureReqToken, MeasureReqMode.word,
		MeasureReqType, 1);

	MeasureReq.ChNum = MeasureCh;
	MeasureReq.MeasureStartTime = cpu2le64(MeasureStartTime);
	MeasureReq.MeasureDuration = cpu2le16(2000);

	{
		unsigned long TempLen;
		MakeOutgoingFrame(	pOutBuffer+FrameLen,	&TempLen,
							sizeof(MEASURE_REQ),	&MeasureReq,
							END_OF_ARGS);
		FrameLen += TempLen;
	}

	MiniportMMRequest(pAd, QID_AC_BE, pOutBuffer, (UINT)FrameLen);

END_OF_MEASURE_REQ:
	kfree(pOutBuffer);

	return true;
}

INT Set_TpcReq_Proc(
	struct rtmp_adapter *pAd,
	char *		arg)
{
	UINT Aid;

	u8 TpcReqToken = RandomByte(pAd);

	Aid = (UINT) simple_strtol(arg, 0, 16);

	DBGPRINT(RT_DEBUG_TRACE, ("%s::Aid = %d\n", __FUNCTION__, Aid));
	if (!VALID_WCID(Aid))
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s: unknow sta of Aid(%d)\n", __FUNCTION__, Aid));
		return true;
	}

	TpcReqInsert(pAd, TpcReqToken);

	EnqueueTPCReq(pAd, pAd->MacTab.Content[Aid].Addr, TpcReqToken);

	return true;
}


