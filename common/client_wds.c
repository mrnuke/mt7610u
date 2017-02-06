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


#ifdef CLIENT_WDS

#include "rt_config.h"

void CliWds_ProxyTabInit(
	struct rtmp_adapter *pAd)
{
	INT idx;
	unsigned long i;

	spin_lock_init(pAd, &pAd->ApCfg.CliWdsTabLock);

/*	pAd->ApCfg.pCliWdsEntryPool = kmalloc(sizeof(CLIWDS_PROXY_ENTRY) * CLIWDS_POOL_SIZE, GFP_ATOMIC);*/
	pAd->ApCfg.pCliWdsEntryPool =
		kmalloc(sizeof(CLIWDS_PROXY_ENTRY) * CLIWDS_POOL_SIZE, GFP_ATOMIC);
	if (pAd->ApCfg.pCliWdsEntryPool)
	{
		memset(pAd->ApCfg.pCliWdsEntryPool, 0, sizeof(CLIWDS_PROXY_ENTRY) * CLIWDS_POOL_SIZE);
		initList(&pAd->ApCfg.CliWdsEntryFreeList);
		for (i = 0; i < CLIWDS_POOL_SIZE; i++)
			insertTailList(&pAd->ApCfg.CliWdsEntryFreeList, (PLIST_ENTRY)(pAd->ApCfg.pCliWdsEntryPool + (unsigned long)i));
	}
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s Fail to alloc memory for pAd->CommonCfg.pCliWdsEntryPool", __FUNCTION__));
	}

	for (idx = 0; idx < CLIWDS_HASH_TAB_SIZE; idx++)
		initList(&pAd->ApCfg.CliWdsProxyTab[idx]);

	return;
}


void CliWds_ProxyTabDestory(
	struct rtmp_adapter *pAd)
{
	INT idx;
	PCLIWDS_PROXY_ENTRY pCliWdsEntry;

	for (idx = 0; idx < CLIWDS_HASH_TAB_SIZE; idx++)
	{
		pCliWdsEntry =
			(PCLIWDS_PROXY_ENTRY)pAd->ApCfg.CliWdsProxyTab[idx].pHead;
		while(pCliWdsEntry)
		{
			PCLIWDS_PROXY_ENTRY pCliWdsEntryNext = pCliWdsEntry->pNext;
			CliWdsEntyFree(pAd, pCliWdsEntry);
			pCliWdsEntry = pCliWdsEntryNext;
		}
	}

	if (pAd->ApCfg.pCliWdsEntryPool)
/*		kfree(pAd->ApCfg.pCliWdsEntryPool);*/
		kfree(pAd->ApCfg.pCliWdsEntryPool);
	pAd->ApCfg.pCliWdsEntryPool = NULL;

	return;
}


PCLIWDS_PROXY_ENTRY CliWdsEntyAlloc(
	struct rtmp_adapter *pAd)
{
	PCLIWDS_PROXY_ENTRY pCliWdsEntry;

	RTMP_SEM_LOCK(&pAd->ApCfg.CliWdsTabLock);

	pCliWdsEntry = (PCLIWDS_PROXY_ENTRY)removeHeadList(&pAd->ApCfg.CliWdsEntryFreeList);

	RTMP_SEM_UNLOCK(&pAd->ApCfg.CliWdsTabLock);

	return pCliWdsEntry;
}


void CliWdsEntyFree(
	struct rtmp_adapter *pAd,
	PCLIWDS_PROXY_ENTRY pCliWdsEntry)
{
	RTMP_SEM_LOCK(&pAd->ApCfg.CliWdsTabLock);

	insertTailList(&pAd->ApCfg.CliWdsEntryFreeList, (PLIST_ENTRY)pCliWdsEntry);

	RTMP_SEM_UNLOCK(&pAd->ApCfg.CliWdsTabLock);

	return;
}


u8 *CliWds_ProxyLookup(
	struct rtmp_adapter *pAd,
	u8 *pMac)
{
	u8 HashId = (*(pMac + 5) & (CLIWDS_HASH_TAB_SIZE - 1));
	PCLIWDS_PROXY_ENTRY pCliWdsEntry;

	pCliWdsEntry =
		(PCLIWDS_PROXY_ENTRY)pAd->ApCfg.CliWdsProxyTab[HashId].pHead;
	while (pCliWdsEntry)
	{
		if (MAC_ADDR_EQUAL(pMac, pCliWdsEntry->Addr))
		{
			unsigned long Now;
			NdisGetSystemUpTime(&Now);

			pCliWdsEntry->LastRefTime = Now;
			if (VALID_WCID(pCliWdsEntry->Aid))
				return pAd->MacTab.Content[pCliWdsEntry->Aid].Addr;
			else
				return NULL;
		}
		pCliWdsEntry = pCliWdsEntry->pNext;
	}
	return NULL;
}


void CliWds_ProxyTabUpdate(
	struct rtmp_adapter *pAd,
	SHORT Aid,
	u8 *pMac)
{
	u8 HashId = (*(pMac + 5) & (CLIWDS_HASH_TAB_SIZE - 1));
	PCLIWDS_PROXY_ENTRY pCliWdsEntry;

	if (CliWds_ProxyLookup(pAd, pMac) != NULL)
		return;

	pCliWdsEntry = CliWdsEntyAlloc(pAd);
	if (pCliWdsEntry)
	{
		unsigned long Now;
		NdisGetSystemUpTime(&Now);

		pCliWdsEntry->Aid = Aid;
		memcpy(&pCliWdsEntry->Addr, pMac, ETH_ALEN);
		pCliWdsEntry->LastRefTime = Now;
		pCliWdsEntry->pNext = NULL;
		insertTailList(&pAd->ApCfg.CliWdsProxyTab[HashId], (PLIST_ENTRY)pCliWdsEntry);
	}
	return;
}


void CliWds_ProxyTabMaintain(
	struct rtmp_adapter *pAd)
{
	unsigned long idx;
	PCLIWDS_PROXY_ENTRY pCliWdsEntry;
	unsigned long Now;

	NdisGetSystemUpTime(&Now);
	for (idx = 0; idx < CLIWDS_HASH_TAB_SIZE; idx++)
	{
		pCliWdsEntry = (PCLIWDS_PROXY_ENTRY)(pAd->ApCfg.CliWdsProxyTab[idx].pHead);
		while(pCliWdsEntry)
		{
			PCLIWDS_PROXY_ENTRY pCliWdsEntryNext = pCliWdsEntry->pNext;
			if (RTMP_TIME_AFTER(Now, pCliWdsEntry->LastRefTime + (CLI_WDS_ENTRY_AGEOUT * OS_HZ / 1000)))
			{
				delEntryList(&pAd->ApCfg.CliWdsProxyTab[idx], (PLIST_ENTRY)pCliWdsEntry);
				CliWdsEntyFree(pAd, pCliWdsEntry);
			}
			pCliWdsEntry = pCliWdsEntryNext;
		}
	}
	return;
}

#endif /* CLIENT_WDS */

