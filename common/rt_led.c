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


#include	"rt_config.h"

INT LED_Array[16][12]={
	{	-1,	-1,	-1,	-1,	-1,	-1,	-1,	-1,	-1,	-1,	-1,	-1},
	{ 	0, 	2,  	1,	0,	-1,	-1,	0, 	-1, 	5, 	-1, 	-1, 	17},
	{	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1},
	{	-1, 	-1,	-1,	-1,	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1},
	{	-1, 	-1,	-1,	-1,	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1},
	{	-1, 	-1, 	-1,	-1,	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1},
	{	-1, 	-1,	-1,	-1,	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1},
	{	-1, 	-1,	-1,	-1,	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1},
	{	-1, 	-1,	-1,	-1,	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1},
	{	-1, 	-1,	-1,	-1,	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1},
	{  	3,  	2,   	-1,	-1,	-1, 	-1, 	16,	1, 	5,	-1, 	-1, 	17},
	{	-1, 	-1,	-1,	-1,	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1},
	{	-1, 	-1,	-1,	-1,	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1, 	-1},
	{	-1, 	-1,	-1,	-1,	-1, 	-1, 	-1,	-1, 	-1, 	-1, 	-1, 	-1},
	{ 	1,   	2,	1,	-1,	-1, 	-1,	3, 	-1,	6, 	-1, 	-1,	0},
	{ 	1,   	2,	1,   	-1, 	-1, 	-1, 	-1,  	1,   	4, 	-1, 	-1, 	18}
};



/*
	========================================================================

	Routine Description:
		Set LED Status

	Arguments:
		pAd						Pointer to our adapter
		Status					LED Status

	Return Value:
		None

	IRQL = PASSIVE_LEVEL
	IRQL = DISPATCH_LEVEL

	Note:

	========================================================================
*/
void RTMPSetLEDStatus(
	struct rtmp_adapter *	pAd,
	u8 		Status)
{
	/*ULONG			data; */
	u8 		LedMode;
	INT LED_CMD = -1;

	if(RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_IDLE_RADIO_OFF))
		return;

	LedMode = LED_MODE(pAd);

	if (LedMode < 0 || Status < 0 || LedMode > 15 || Status > 11)
		return;

	LED_CMD = LED_Array[LedMode][Status];

	if (LED_CMD != -1)
		mt7610u_mcu_led_op(pAd, 0, LED_CMD);

	DBGPRINT(RT_DEBUG_TRACE, ("%s: LED Mode:0x%x\n", __FUNCTION__, LedMode));

    /* */
	/* Keep LED status for LED SiteSurvey mode. */
	/* After SiteSurvey, we will set the LED mode to previous status. */
	/* */
	if ((Status != LED_ON_SITE_SURVEY) && (Status != LED_POWER_UP))
		pAd->LedCntl.LedStatus = Status;

}

void RTMPGetLEDSetting(struct rtmp_adapter*pAd)
{
	u16 Value;
	struct mt7610u_led_control *led_crtl = &pAd->LedCntl;

	// TODO: wait TC6008 EEPROM format
	Value = mt7610u_read_eeprom16(pAd, EEPROM_FREQ_OFFSET);
	led_crtl->MCULedCntl.word = (Value >> 8);
}


void RTMPStartLEDMode(struct rtmp_adapter*pAd)
{
}


void RTMPInitLEDMode(struct rtmp_adapter*pAd)
{
	struct mt7610u_led_control *led_crtl = &pAd->LedCntl;

	if (led_crtl->MCULedCntl.word == 0xFF) 	{
		led_crtl->MCULedCntl.word = 0x01;
	}

	RTMPStartLEDMode(pAd);
}


inline void RTMPExitLEDMode(struct rtmp_adapter*pAd)
{

	RTMPSetLED(pAd, LED_RADIO_OFF);

	return;
}

