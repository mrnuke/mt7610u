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

/*
    ==========================================================================
    Description:
        authenticate state machine init, including state transition and timer init
    Parameters:
        Sm - pointer to the auth state machine
    Note:
        The state machine looks like this

                        AUTH_REQ_IDLE           AUTH_WAIT_SEQ2                   AUTH_WAIT_SEQ4
    MT2_MLME_AUTH_REQ   mlme_auth_req_action    invalid_state_when_auth          invalid_state_when_auth
    MT2_PEER_AUTH_EVEN  drop                    peer_auth_even_at_seq2_action    peer_auth_even_at_seq4_action
    MT2_AUTH_TIMEOUT    Drop                    auth_timeout_action              auth_timeout_action

	IRQL = PASSIVE_LEVEL

    ==========================================================================
 */

void AuthStateMachineInit(
	struct rtmp_adapter *pAd,
	STATE_MACHINE *Sm,
	STATE_MACHINE_FUNC Trans[])
{
	StateMachineInit(Sm, Trans, MAX_AUTH_STATE, MAX_AUTH_MSG,
			 (STATE_MACHINE_FUNC) Drop, AUTH_REQ_IDLE,
			 AUTH_MACHINE_BASE);

	/* the first column */
	StateMachineSetAction(Sm, AUTH_REQ_IDLE, MT2_MLME_AUTH_REQ,
			      (STATE_MACHINE_FUNC) MlmeAuthReqAction);

	/* the second column */
	StateMachineSetAction(Sm, AUTH_WAIT_SEQ2, MT2_MLME_AUTH_REQ,
			      (STATE_MACHINE_FUNC) InvalidStateWhenAuth);
	StateMachineSetAction(Sm, AUTH_WAIT_SEQ2, MT2_PEER_AUTH_EVEN,
			      (STATE_MACHINE_FUNC) PeerAuthRspAtSeq2Action);
	StateMachineSetAction(Sm, AUTH_WAIT_SEQ2, MT2_AUTH_TIMEOUT,
			      (STATE_MACHINE_FUNC) AuthTimeoutAction);

	/* the third column */
	StateMachineSetAction(Sm, AUTH_WAIT_SEQ4, MT2_MLME_AUTH_REQ,
			      (STATE_MACHINE_FUNC) InvalidStateWhenAuth);
	StateMachineSetAction(Sm, AUTH_WAIT_SEQ4, MT2_PEER_AUTH_EVEN,
			      (STATE_MACHINE_FUNC) PeerAuthRspAtSeq4Action);
	StateMachineSetAction(Sm, AUTH_WAIT_SEQ4, MT2_AUTH_TIMEOUT,
			      (STATE_MACHINE_FUNC) AuthTimeoutAction);

	RTMPInitTimer(pAd, &pAd->MlmeAux.AuthTimer,
		      GET_TIMER_FUNCTION(AuthTimeout), pAd, false);
}

/*
    ==========================================================================
    Description:
        function to be executed at timer thread when auth timer expires

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
void AuthTimeout(
	void *SystemSpecific1,
	void *FunctionContext,
	void *SystemSpecific2,
	void *SystemSpecific3)
{
	struct rtmp_adapter*pAd = (struct rtmp_adapter*) FunctionContext;

	DBGPRINT(RT_DEBUG_TRACE, ("AUTH - AuthTimeout\n"));

	/* Do nothing if the driver is starting halt state. */
	/* This might happen when timer already been fired before cancel timer with mlmehalt */
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
		return;

	/* send a de-auth to reset AP's state machine (Patch AP-Dir635) */
	if (pAd->Mlme.AuthMachine.CurrState == AUTH_WAIT_SEQ2)
		Cls2errAction(pAd, pAd->MlmeAux.Bssid);

	MlmeEnqueue(pAd, AUTH_STATE_MACHINE, MT2_AUTH_TIMEOUT, 0, NULL, 0);
	RTMP_MLME_HANDLER(pAd);
}

/*
    ==========================================================================
    Description:

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
void MlmeAuthReqAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{
	if (AUTH_ReqSend(pAd, Elem, &pAd->MlmeAux.AuthTimer, "AUTH", 1, NULL, 0))
		pAd->Mlme.AuthMachine.CurrState = AUTH_WAIT_SEQ2;
	else {
		USHORT Status;

		pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
		Status = MLME_INVALID_FORMAT;
		MlmeEnqueue(pAd, MLME_CNTL_STATE_MACHINE, MT2_AUTH_CONF, 2, &Status, 0);
	}
}

/*
    ==========================================================================
    Description:

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
void PeerAuthRspAtSeq2Action(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM * Elem)
{
	u8 Addr2[ETH_ALEN];
	USHORT Seq, Status, RemoteStatus, Alg;
	u8 iv_hdr[4];
/*    u8         ChlgText[CIPHER_TEXT_LEN]; */
	u8 *ChlgText = NULL;
/*    u8         CyperChlgText[CIPHER_TEXT_LEN + 8 + 8]; */
	u8 *CyperChlgText = NULL;
	ULONG c_len = 0;
	HEADER_802_11 AuthHdr;
	bool TimerCancelled;
	u8 *pOutBuffer = NULL;
	ULONG FrameLen = 0;
	USHORT Status2;
	u8 ChallengeIe = IE_CHALLENGE_TEXT;
	u8 len_challengeText = CIPHER_TEXT_LEN;

	/* allocate memory */
	ChlgText = kmalloc(CIPHER_TEXT_LEN, GFP_ATOMIC);
	if (ChlgText == NULL) {
		DBGPRINT(RT_DEBUG_ERROR,
			 ("%s: ChlgText Allocate memory fail!!!\n",
			  __FUNCTION__));
		return;
	}

	CyperChlgText = kmalloc(CIPHER_TEXT_LEN + 8 + 8, GFP_ATOMIC);
	if (CyperChlgText == NULL) {
		DBGPRINT(RT_DEBUG_ERROR,
			 ("%s: CyperChlgText Allocate memory fail!!!\n",
			  __FUNCTION__));
		kfree(ChlgText);
		return;
	}

	if (PeerAuthSanity
	    (pAd, Elem->Msg, Elem->MsgLen, Addr2, &Alg, &Seq, &Status,
	     (char *) ChlgText)) {
		if (MAC_ADDR_EQUAL(pAd->MlmeAux.Bssid, Addr2) && Seq == 2) {
			DBGPRINT(RT_DEBUG_TRACE,
				 ("AUTH - Receive AUTH_RSP seq#2 to me (Alg=%d, Status=%d)\n",
				  Alg, Status));
			RTMPCancelTimer(&pAd->MlmeAux.AuthTimer,
					&TimerCancelled);

			if (Status == MLME_SUCCESS) {
				/* Authentication Mode "LEAP" has allow for CCX 1.X */
				if (pAd->MlmeAux.Alg == Ndis802_11AuthModeOpen) {
					pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
					MlmeEnqueue(pAd,
						    MLME_CNTL_STATE_MACHINE,
						    MT2_AUTH_CONF, 2, &Status,
						    0);
				} else {
					/* 2. shared key, need to be challenged */
					Seq++;
					RemoteStatus = MLME_SUCCESS;

					/* Get an unused nonpaged memory */
					pOutBuffer =
					    kmalloc(MGMT_DMA_BUFFER_SIZE, GFP_ATOMIC);
					if (pOutBuffer == NULL) {
						DBGPRINT(RT_DEBUG_TRACE,
							 ("AUTH - PeerAuthRspAtSeq2Action() allocate memory fail\n"));
						pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
						Status2 = MLME_FAIL_NO_RESOURCE;
						MlmeEnqueue(pAd,
							    MLME_CNTL_STATE_MACHINE,
							    MT2_AUTH_CONF, 2,
							    &Status2, 0);
						goto LabelOK;
					}

					DBGPRINT(RT_DEBUG_TRACE,
						 ("AUTH - Send AUTH request seq#3...\n"));
					MgtMacHeaderInit(pAd, &AuthHdr,
							 SUBTYPE_AUTH, 0, Addr2,
							 pAd->MlmeAux.Bssid);
					AuthHdr.FC.Wep = 1;

					/* TSC increment */
					INC_TX_TSC(pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].TxTsc, LEN_WEP_TSC);

					/* Construct the 4-bytes WEP IV header */
					RTMPConstructWEPIVHdr(pAd->StaCfg.DefaultKeyId,
							      pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId].TxTsc, iv_hdr);

					Alg = cpu2le16(*(USHORT *) & Alg);
					Seq = cpu2le16(*(USHORT *) & Seq);
					RemoteStatus = cpu2le16(*(USHORT *) &RemoteStatus);

					/* Construct message text */
					MakeOutgoingFrame(CyperChlgText, &c_len,
							  2, &Alg,
							  2, &Seq,
							  2, &RemoteStatus,
							  1, &ChallengeIe,
							  1, &len_challengeText,
							  len_challengeText,
							  ChlgText,
							  END_OF_ARGS);

					if (RTMPSoftEncryptWEP(pAd,
							       iv_hdr,
							       &pAd->SharedKey[BSS0][pAd->StaCfg.DefaultKeyId],
							       CyperChlgText, c_len) == false) {
						kfree(pOutBuffer);
						pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
						Status2 = MLME_FAIL_NO_RESOURCE;
						MlmeEnqueue(pAd,
							    MLME_CNTL_STATE_MACHINE,
							    MT2_AUTH_CONF, 2,
							    &Status2, 0);
						goto LabelOK;
					}

					/* Update the total length for 4-bytes ICV */
					c_len += LEN_ICV;

					MakeOutgoingFrame(pOutBuffer, &FrameLen,
							  sizeof
							  (HEADER_802_11),
							  &AuthHdr,
							  LEN_WEP_IV_HDR,
							  iv_hdr, c_len,
							  CyperChlgText,
							  END_OF_ARGS);

					MiniportMMRequest(pAd, 0, pOutBuffer, FrameLen);
					kfree(pOutBuffer);

					RTMPSetTimer(&pAd->MlmeAux.AuthTimer, AUTH_TIMEOUT);
					pAd->Mlme.AuthMachine.CurrState = AUTH_WAIT_SEQ4;
				}
			} else {
				pAd->StaCfg.AuthFailReason = Status;
				memcpy(pAd->StaCfg.AuthFailSta, Addr2, ETH_ALEN);
				pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
				MlmeEnqueue(pAd, MLME_CNTL_STATE_MACHINE,
					    MT2_AUTH_CONF, 2, &Status, 0);
			}
		}
	} else {
		DBGPRINT(RT_DEBUG_TRACE,
			 ("AUTH - PeerAuthSanity() sanity check fail\n"));
	}

      LabelOK:
	if (ChlgText != NULL)
		kfree(ChlgText);

	if (CyperChlgText != NULL)
		kfree(CyperChlgText);
	return;
}

/*
    ==========================================================================
    Description:

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
void PeerAuthRspAtSeq4Action(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{
	u8 Addr2[ETH_ALEN];
	USHORT Alg, Seq, Status;
/*    CHAR          ChlgText[CIPHER_TEXT_LEN]; */
	CHAR *ChlgText = NULL;
	bool TimerCancelled;

	/* allocate memory */
	ChlgText = kmalloc(CIPHER_TEXT_LEN, GFP_ATOMIC);
	if (ChlgText == NULL) {
		DBGPRINT(RT_DEBUG_ERROR,
			 ("%s: ChlgText Allocate memory fail!!!\n",
			  __FUNCTION__));
		return;
	}

	if (PeerAuthSanity
	    (pAd, Elem->Msg, Elem->MsgLen, Addr2, &Alg, &Seq, &Status,
	     ChlgText)) {
		if (MAC_ADDR_EQUAL(pAd->MlmeAux.Bssid, Addr2) && Seq == 4) {
			DBGPRINT(RT_DEBUG_TRACE,
				 ("AUTH - Receive AUTH_RSP seq#4 to me\n"));
			RTMPCancelTimer(&pAd->MlmeAux.AuthTimer,
					&TimerCancelled);

			if (Status != MLME_SUCCESS) {
				pAd->StaCfg.AuthFailReason = Status;
				memcpy(pAd->StaCfg.AuthFailSta, Addr2, ETH_ALEN);
			}

			pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
			MlmeEnqueue(pAd, MLME_CNTL_STATE_MACHINE, MT2_AUTH_CONF,
				    2, &Status, 0);
		}
	} else {
		DBGPRINT(RT_DEBUG_TRACE,
			 ("AUTH - PeerAuthRspAtSeq4Action() sanity check fail\n"));
	}

	if (ChlgText != NULL)
		kfree(ChlgText);
}

/*
    ==========================================================================
    Description:

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
void MlmeDeauthReqAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{
	MLME_DEAUTH_REQ_STRUCT *pInfo;
	HEADER_802_11 DeauthHdr;
	u8 *pOutBuffer = NULL;
	ULONG FrameLen = 0;
	USHORT Status;

	pInfo = (MLME_DEAUTH_REQ_STRUCT *) Elem->Msg;

	pOutBuffer = kmalloc(MGMT_DMA_BUFFER_SIZE, GFP_ATOMIC);	/*Get an unused nonpaged memory */
	if (pOutBuffer == NULL) {
		DBGPRINT(RT_DEBUG_TRACE,
			 ("AUTH - MlmeDeauthReqAction() allocate memory fail\n"));
		pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
		Status = MLME_FAIL_NO_RESOURCE;
		MlmeEnqueue(pAd, MLME_CNTL_STATE_MACHINE, MT2_DEAUTH_CONF, 2,
			    &Status, 0);
		return;
	}

	DBGPRINT(RT_DEBUG_TRACE,
		 ("AUTH - Send DE-AUTH request (Reason=%d)...\n",
		  pInfo->Reason));
	MgtMacHeaderInit(pAd, &DeauthHdr, SUBTYPE_DEAUTH, 0, pInfo->Addr,
						pAd->MlmeAux.Bssid);
	MakeOutgoingFrame(pOutBuffer, &FrameLen, sizeof (HEADER_802_11),
			  &DeauthHdr, 2, &pInfo->Reason, END_OF_ARGS);
	MiniportMMRequest(pAd, 0, pOutBuffer, FrameLen);
	kfree(pOutBuffer);

	pAd->StaCfg.DeauthReason = pInfo->Reason;
	memcpy(pAd->StaCfg.DeauthSta, pInfo->Addr, ETH_ALEN);
	pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
	Status = MLME_SUCCESS;
	MlmeEnqueue(pAd, MLME_CNTL_STATE_MACHINE, MT2_DEAUTH_CONF, 2, &Status,
		    0);

	/* send wireless event - for deauthentication */
}

/*
    ==========================================================================
    Description:

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
void AuthTimeoutAction(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{
	USHORT Status;
	DBGPRINT(RT_DEBUG_TRACE, ("AUTH - AuthTimeoutAction\n"));
	pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
	Status = MLME_REJ_TIMEOUT;
	MlmeEnqueue(pAd, MLME_CNTL_STATE_MACHINE, MT2_AUTH_CONF, 2, &Status, 0);
}

/*
    ==========================================================================
    Description:

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
void InvalidStateWhenAuth(
	struct rtmp_adapter *pAd,
	MLME_QUEUE_ELEM *Elem)
{
	USHORT Status;
	DBGPRINT(RT_DEBUG_TRACE,
		 ("AUTH - InvalidStateWhenAuth (state=%ld), reset AUTH state machine\n",
		  pAd->Mlme.AuthMachine.CurrState));
	pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
	Status = MLME_STATE_MACHINE_REJECT;
	MlmeEnqueue(pAd, MLME_CNTL_STATE_MACHINE, MT2_AUTH_CONF, 2, &Status, 0);
}

/*
    ==========================================================================
    Description:
        Some STA/AP
    Note:
        This action should never trigger AUTH state transition, therefore we
        separate it from AUTH state machine, and make it as a standalone service

	IRQL = DISPATCH_LEVEL

    ==========================================================================
 */
void Cls2errAction(
	struct rtmp_adapter *pAd,
	u8 *pAddr)
{
	HEADER_802_11 DeauthHdr;
	u8 *pOutBuffer = NULL;
	ULONG FrameLen = 0;
	USHORT Reason = REASON_CLS2ERR;

	pOutBuffer = kmalloc(MGMT_DMA_BUFFER_SIZE, GFP_ATOMIC);	/*Get an unused nonpaged memory */
	if (pOutBuffer == NULL)
		return;

	DBGPRINT(RT_DEBUG_TRACE,
		 ("AUTH - Class 2 error, Send DEAUTH frame...\n"));
	MgtMacHeaderInit(pAd, &DeauthHdr, SUBTYPE_DEAUTH, 0, pAddr,
						pAd->MlmeAux.Bssid);
	MakeOutgoingFrame(pOutBuffer, &FrameLen, sizeof (HEADER_802_11),
			  &DeauthHdr, 2, &Reason, END_OF_ARGS);
	MiniportMMRequest(pAd, 0, pOutBuffer, FrameLen);
	kfree(pOutBuffer);

	pAd->StaCfg.DeauthReason = Reason;
	memcpy(pAd->StaCfg.DeauthSta, pAddr, ETH_ALEN);
}

bool AUTH_ReqSend(
	struct rtmp_adapter *pAd,
	PMLME_QUEUE_ELEM pElem,
	PRALINK_TIMER_STRUCT pAuthTimer,
	char *pSMName,
	USHORT SeqNo,
	u8 *pNewElement,
	ULONG ElementLen)
{
	USHORT Alg, Seq, Status;
	u8 Addr[6];
	ULONG Timeout;
	HEADER_802_11 AuthHdr;
	bool TimerCancelled;
	u8 *pOutBuffer = NULL;
	ULONG FrameLen = 0, tmp = 0;

	/* Block all authentication request durning WPA block period */
	if (pAd->StaCfg.bBlockAssoc == true) {
		DBGPRINT(RT_DEBUG_TRACE,
			 ("%s - Block Auth request durning WPA block period!\n",
			  pSMName));
		pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
		Status = MLME_STATE_MACHINE_REJECT;
		MlmeEnqueue(pAd, MLME_CNTL_STATE_MACHINE, MT2_AUTH_CONF, 2,
			    &Status, 0);
	} else
	    if (MlmeAuthReqSanity
		(pAd, pElem->Msg, pElem->MsgLen, Addr, &Timeout, &Alg)) {
		/* reset timer */
		RTMPCancelTimer(pAuthTimer, &TimerCancelled);

		memcpy(pAd->MlmeAux.Bssid, Addr, ETH_ALEN);
		pAd->MlmeAux.Alg = Alg;
		Seq = SeqNo;
		Status = MLME_SUCCESS;

		pOutBuffer = kmalloc(MGMT_DMA_BUFFER_SIZE, GFP_ATOMIC);	/*Get an unused nonpaged memory */
		if (pOutBuffer == NULL) {
			DBGPRINT(RT_DEBUG_TRACE,
				 ("%s - MlmeAuthReqAction(Alg:%d) allocate memory failed\n",
				  pSMName, Alg));
			pAd->Mlme.AuthMachine.CurrState = AUTH_REQ_IDLE;
			Status = MLME_FAIL_NO_RESOURCE;
			MlmeEnqueue(pAd, MLME_CNTL_STATE_MACHINE, MT2_AUTH_CONF,
				    2, &Status, 0);
			return false;
		}

		DBGPRINT(RT_DEBUG_TRACE,
			 ("%s - Send AUTH request seq#1 (Alg=%d)...\n", pSMName,
			  Alg));
		MgtMacHeaderInit(pAd, &AuthHdr, SUBTYPE_AUTH, 0, Addr,
							pAd->MlmeAux.Bssid);
		MakeOutgoingFrame(pOutBuffer, &FrameLen, sizeof (HEADER_802_11),
				  &AuthHdr, 2, &Alg, 2, &Seq, 2, &Status,
				  END_OF_ARGS);

		if (pNewElement && ElementLen) {
			MakeOutgoingFrame(pOutBuffer + FrameLen, &tmp,
					  ElementLen, pNewElement, END_OF_ARGS);
			FrameLen += tmp;
		}

		MiniportMMRequest(pAd, 0, pOutBuffer, FrameLen);
		kfree(pOutBuffer);

		RTMPSetTimer(pAuthTimer, Timeout);
		return true;
	} else {
		DBGPRINT_ERR(("%s - MlmeAuthReqAction() sanity check failed\n",
			      pSMName));
		return false;
	}

	return true;
}
