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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/signal.h>
#include "rpld.h"

extern	int	totclnt;
extern	client_t *clntp;
extern  char	debugmsg[];

void dumpclients(void);

/* Re-read config file */
void
sighuphdr(void)
{
#define	RUNNING		1
	readconfig(RUNNING);
}

/* Dump internal variables to aid debugging or check status */
void
sigusr1hdr(void)
{
	dumpparams();
	dumpclients();
}

void
dumpclients(void)
{
	int	i;
	client_t *cp;
	bootfile_t *bp;
	char	line[80];

	sprintf(debugmsg, "Number of active clients is %d\n", totclnt);
	senddebug(MSG_ALWAYS);
	if (totclnt == 0)
		return;

	cp = clntp;
	for (i = 0; i < totclnt; i++) {
		sprintf(debugmsg,
		    "\n----------- Client %d Information ----------\n", i+1);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg, "Client structure pointer: 0x%lX\n", cp);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg, "Next pointer: 0x%lX\n", cp->next);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg, "Prev pointer: 0x%lX\n", cp->prev);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg, "Client physical address: 0x%0X 0x%0X 0x%0X "
		    "0x%0X 0x%0X 0x%0X\n",
		    cp->addr[0], cp->addr[1], cp->addr[2],
		    cp->addr[3], cp->addr[4], cp->addr[5]);
		senddebug(MSG_ALWAYS);
		switch (cp->status) {
		case ST_FIND_RCVD:
			(void) strlcpy(line,
				"FIND frame received", sizeof (line));
			break;
		case ST_FOUND_SENT:
			(void) strlcpy(line, "FOUND frame sent out",
				sizeof (line));
			break;
		case ST_DATA_XFER:
			(void) strlcpy(line, "Data transfer in progress",
				sizeof (line));
			break;
		case ST_FINISH:
			(void) strlcpy(line,
				"Data transfer finished, timing out",
				sizeof (line));
			break;
		}
		sprintf(debugmsg, "Client status: %s\n", line);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg,
		    "The list of boot files for this client is:\n");
		bp = cp->bootfp;
		senddebug(MSG_ALWAYS);
		while (bp) {
			sprintf(debugmsg,
			    "\tPointer to current boot file record: 0x%lX\n",
			    bp);
			senddebug(MSG_ALWAYS);
			sprintf(debugmsg,
			    "\tPointer to next boot file record: 0x%lX\n",
			    bp->next);
			senddebug(MSG_ALWAYS);
			sprintf(debugmsg, "\tBoot file name: %s\n",
			    bp->filename);
			senddebug(MSG_ALWAYS);
			sprintf(debugmsg, "\tBoot file load address: 0x%lX\n",
			    bp->loadaddr);
			senddebug(MSG_ALWAYS);
			sprintf(debugmsg,
			    "\tStart sequence number for this file: 0x%lX\n",
			    bp->seqnum);
			senddebug(MSG_ALWAYS);
			bp = bp->next;
		}
		sprintf(debugmsg,
		    "Currently active boot file structure pointer: 0x%lX\n",
		    cp->currfp);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg,
		    "File stream pointer for this active boot file: 0x%lX\n",
		    cp->fstr);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg,
		    "Lseek pointer to this active boot file: 0x%lX\n",
		    cp->seekp);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg,
		    "Next sequence number to use: 0x%lX\n", cp->seqnum);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg, "Final xfer address: 0x%lX\n", cp->xferaddr);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg, "Frame size to use: %d\n", cp->framesz);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg, "Final timeout to use: %d\n", cp->timeo);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg, "Delay currently pending: %d\n", cp->delay);
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg, "Reset value in use: %d\n", cp->resetdflt);
		senddebug(MSG_ALWAYS);
	}
}
