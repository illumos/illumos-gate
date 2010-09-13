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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/obpdefs.h>
#include <sys/fhc.h>
#include <sys/ac.h>
#include <sys/sysctrl.h>
#include <sys/openpromio.h>
#include "mema_prom.h"
#include <config_admin.h>


/*
 * PROM access routines to get and set disabled lists
 * Based on code in the usr/src/cmd/eeprom directory.
 */
#define	PROMDEV		"/dev/openprom"
/*
 * 128 is the size of the largest (currently) property name
 * 8192 - MAXPROPSIZE - sizeof (int) is the size of the largest
 * (currently) property value, viz. nvramrc.
 * the sizeof(u_int) is from struct openpromio
 */

#define	MAXPROPSIZE	128
#define	MAXNAMESIZE	MAXPROPSIZE
#define	MAXVALSIZE	(8192 - MAXPROPSIZE - sizeof (u_int))
#define	BUFSIZE		(MAXPROPSIZE + MAXVALSIZE + sizeof (u_int))
typedef union {
	char buf[BUFSIZE];
	struct openpromio opp;
} Oppbuf;
#define	PROP_MEMORY_LIST	"disabled-memory-list"

static int prom_read_one(mema_disabled_t *, int, int, char *, u_int);
static int prom_write_one(mema_disabled_t *, int, int, char *, u_int);

int
prom_read_disabled_list(mema_disabled_t *dp, int bd)
{
	int prom_fd;
	int ret;

	(void) memset((void *)dp, 0, sizeof (*dp));
	prom_fd = open(PROMDEV, O_RDONLY);
	if (prom_fd == -1) {
		return (0);
	}
	ret = prom_read_one(dp, bd, prom_fd,
	    PROP_MEMORY_LIST, PROM_MEMORY_DISABLED);
	(void) close(prom_fd);
	return (ret);
}

int
prom_write_disabled_list(mema_disabled_t *dp, int bd)
{
	int prom_fd;
	int ret;

	prom_fd = open(PROMDEV, O_RDWR);
	if (prom_fd == -1) {
		return (0);
	}
	ret = prom_write_one(dp, bd, prom_fd,
	    PROP_MEMORY_LIST, PROM_MEMORY_DISABLED);
	(void) close(prom_fd);
	return (ret);
}

static int
prom_read_one(
	mema_disabled_t *dp,
	int bd,
	int prom_fd,
	char *var,
	u_int bit)
{
	Oppbuf oppbuf;
	struct openpromio *opp = &oppbuf.opp;
	int ret;

	(void) memset((void *)&oppbuf, 0, sizeof (oppbuf));
	(void) strncpy(opp->oprom_array, var, MAXNAMESIZE);
	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETOPT, opp) == -1) {
		ret = 0;
	} else
	if (opp->oprom_size == 0) {
		/* Not a failure - just not set to anything */
		ret = 1;
	} else {
		char *cp;
		int board;

		ret = 1;
		for (cp = opp->oprom_array; *cp != '\0'; cp++) {
			switch (*cp) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				board = *cp - '0';
				break;
			case 'a':
			case 'b':
			case 'c':
			case 'd':
			case 'e':
			case 'f':
				board = *cp - 'a' + 10;
				break;
			case 'A':
			case 'B':
			case 'C':
			case 'D':
			case 'E':
			case 'F':
				board = *cp - 'A' + 10;
				break;
			default:
				/* Ignore bad characters. */
				/* TODO: maybe should set ret to 0? */
				board = -1;
				break;
			}
			if (board == bd)
				*dp |= bit;
		}
	}
	return (ret);
}

static int
prom_write_one(
	mema_disabled_t *dp,
	int bd,
	int prom_fd,
	char *var,
	u_int bit)
{
	Oppbuf in_oppbuf;
	struct openpromio *in_opp = &in_oppbuf.opp;
	Oppbuf oppbuf;
	struct openpromio *opp = &oppbuf.opp;
	int ret;
	char *cp;

	/* Setup output buffer. */
	(void) memset((void *)&oppbuf, 0, sizeof (oppbuf));
	(void) strncpy(opp->oprom_array, var, MAXNAMESIZE);
	opp->oprom_size = strlen(var) + 1;
	cp = opp->oprom_array + opp->oprom_size;

	/*
	 * First read the existing list, filtering out 'bd' if 'bit'
	 * not set.
	 */
	(void) memset((void *)&in_oppbuf, 0, sizeof (in_oppbuf));
	(void) strncpy(in_opp->oprom_array, var, MAXNAMESIZE);
	in_opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETOPT, in_opp) != -1 &&
	    in_opp->oprom_size != 0) {
		char *icp;
		int board;

		for (icp = in_opp->oprom_array; *icp != '\0'; icp++) {
			switch (*icp) {
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
			case '8': case '9':
				board = *icp - '0';
				break;
			case 'a': case 'b': case 'c':
			case 'd': case 'e': case 'f':
				board = *icp - 'a' + 10;
				break;
			case 'A': case 'B': case 'C':
			case 'D': case 'E': case 'F':
				board = *icp - 'A' + 10;
				break;
			default:
				/* Ignore bad characters. */
				continue;
			}
			/* If enabling this board ... */
			if (board == bd && (*dp & bit) == 0)
				continue;
			*cp++ = "0123456789abcdef"[board];
			opp->oprom_size++;
		}
	}

	if ((*dp & bit) != 0) {
		*cp++ = "0123456789abcdef"[bd];
		opp->oprom_size++;
	}
	if (ioctl(prom_fd, OPROMSETOPT, opp) == -1) {
		ret = 0;
	} else {
		ret = 1;
	}

	return (ret);
}

/*
 * The PROM only has board-level disable of memory.  If two banks are present
 * on the board, both are either enabled or disabled at boot.
 * The caller of this routine must set the PROM_MEMORY_PRESENT bits
 * before calling this function.
 */

/*ARGSUSED*/
int
prom_viable_disabled_list(mema_disabled_t *dp)
{
#ifdef	XXX
	int board;

	for (board = 0; board < MAX_BOARDS; board++) {
		if ((dp->bank_A[board] & PROM_MEMORY_PRESENT) != 0 &&
		    (dp->bank_B[board] & PROM_MEMORY_PRESENT) != 0 &&
		    (dp->bank_A[board] & PROM_MEMORY_DISABLED) !=
		    (dp->bank_B[board] & PROM_MEMORY_DISABLED)) {
			return (0);
		}
	}
#endif
	return (1);
}
