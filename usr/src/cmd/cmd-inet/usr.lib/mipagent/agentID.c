/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: agentID.c
 *
 * This files contains all of the routines necessary to
 * manage the Mobile-IP Replay protection mechanisms.
 */

#include "mip.h"
#include "agent.h"

/*
 * IDfreshnessSlack contains the number of seconds that
 * we allow as a difference between our clock and the
 * mobile node's clock when timestamp-based replay
 * protection is used.
 */
extern int IDfreshnessSlack;
extern uint32_t getRandomValue();
extern uint32_t CurrentTimeNTPSec();


/*
 * Function: HAinitID
 *
 * Arguments:	IDHigh - High order 32 bit ID
 *		IDLow - Low order 32 bit ID
 *		ReplayStyle - Replay type.
 *
 * Description: This function is called by the Home Agent
 *		to initialize a Mobile Node's replay
 *		identifier.
 *
 * Returns:
 */
void
HAinitID(uint32_t *IDHigh, uint32_t *IDLow, int ReplayStyle)
{
	if (ReplayStyle == TIMESTAMPS)  {
	    *IDHigh = CurrentTimeNTPSec() - IDfreshnessSlack;
	    *IDLow = getRandomValue();
	} else  {
	    *IDHigh = 0;
	    *IDLow = 0;
	}
}


/*
 * Function: isIDgreater
 *
 * Arguments:	StoredIDHigh - Locally stored high order 32 bit replay ID
 *		StoredIDLow - Locally stored low order 32 bit replay ID
 *		IDHigh - High order 32 bit replay ID
 *		IDLow - Low order 32 bit replay ID
 *
 * Description: This function will return TRUE if the ID received
 *		by the Mobile Node is higher than the value stored
 *		locally.
 *
 * Returns: boolean_t, TRUE if value is greater than stored value.
 */
static boolean_t
isIDgreater(uint32_t StoredIDHigh, uint32_t StoredIDLow,
		uint32_t IDHigh, uint32_t IDLow)
{
	if ((IDHigh > StoredIDHigh) ||
	    ((IDHigh == StoredIDHigh) && (IDLow > StoredIDLow)))
		return (_B_TRUE);
	else
		return (_B_FALSE);
}


/*
 * Function: isIDfresh
 *
 * Arguments:	IDHigh - High order 32 bit replay ID
 *		IDLow - Low order 32 bit replay ID
 *
 * Description: This value will compare the ID received
 *		with the local NTP time. Specifically, we
 *		will check if the time sent by the Mobile Node
 *		is within the current time +/- our configured
 *		clock skew.
 *
 * Returns: boolean_t, TRUE if the time is within our window.
 */
/* ARGSUSED */
static boolean_t
isIDfresh(uint32_t IDHigh, uint32_t IDLow)
{
	long diff;

	diff = (long)(IDHigh - CurrentTimeNTPSec());

	if (diff < 0)
		diff = (0 - diff);

	return ((diff < IDfreshnessSlack) ? _B_TRUE : _B_FALSE);
}


/*
 * Function: HAisIDok
 *
 * Arguments:	StoredIDHigh - Locally stored high order 32 bit replay ID
 *		StoredIDLow - Locally stored low order 32 bit replay ID
 *		IDHigh - High order 32 bit replay ID
 *		IDLow - Low order 32 bit replay ID
 *		ReplayStyle - Replay type.
 *
 * Description: This routine will validate the Mobile Node's ID
 *		using the replay style configured within the Security
 *		Assocation.
 *
 * Returns: boolean_t, TRUE if the ID is valid
 */
boolean_t
HAisIDok(uint32_t StoredIDHigh, uint32_t StoredIDLow,
		uint32_t IDHigh, uint32_t IDLow, int ReplayStyle)
{
	if (ReplayStyle == TIMESTAMPS)  {
	    if (isIDgreater(StoredIDHigh, StoredIDLow, IDHigh, IDLow) &&
		isIDfresh(IDHigh, IDLow))
			return (_B_TRUE);
	    else
		return (_B_FALSE);
	} else if (ReplayStyle == NONE) {
		return (_B_TRUE);
	} else {
		return (_B_FALSE);
	}
}


/*
 * Function: HAnewID
 *
 * Arguments:	newIDHigh - Locally stored high order 32 bit replay ID
 *		newIDLow - Locally stored low order 32 bit replay ID
 *		IDHigh - High order 32 bit replay ID
 *		IDLow - Low order 32 bit replay ID
 *		ReplayStyle - Replay type.
 *		IDmatched - specifies whether the ID provided
 *			should be used.
 *
 * Description: This function will update the locally stored ID
 *
 * Returns:
 */
void
HAnewID(uint32_t *newIDHigh, uint32_t *newIDLow, uint32_t IDHigh,
		uint32_t IDLow, int ReplayStyle, boolean_t IDmatched)
{
	if (ReplayStyle == TIMESTAMPS)  {
		*newIDHigh = IDmatched ? IDHigh : CurrentTimeNTPSec();
	} else  {
		*newIDHigh = 0;
	}

	*newIDLow = IDLow;
}


/*
 * Function: HAstoreID
 *
 * Arguments:	newIDHigh - Locally stored high order 32 bit replay ID
 *		newIDLow - Locally stored low order 32 bit replay ID
 *		IDHigh - High order 32 bit replay ID
 *		IDLow - Low order 32 bit replay ID
 *		ReplayStyle - Replay type.
 *		IDmatched - specifies whether the ID provided
 *			should be used.
 *
 * Description: This function will store the IDs locally
 *
 * Returns:
 */
void
HAstoreID(uint32_t *StoredIDHigh, uint32_t *StoredIDLow, uint32_t IDHigh,
		uint32_t IDLow, int ReplayStyle, boolean_t IDmatched)
{
	if (((ReplayStyle == TIMESTAMPS) && IDmatched)) {
	    *StoredIDHigh = IDHigh;
	    *StoredIDLow = IDLow;
	}
}
