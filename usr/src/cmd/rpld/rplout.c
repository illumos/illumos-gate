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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/dlpi.h>
#include <poll.h>
#include <unistd.h>
#include <sys/stat.h>
#include "rpld.h"

#define	LLC_OVERHEAD		3
#define	RPL_OVERHEAD		29
#define	PROTOCOL_OVERHEAD	(LLC_OVERHEAD + RPL_OVERHEAD)

extern	int	totclnt;
extern	client_t *clntp;
extern	struct pollfd llc_fd;
extern	long	delayGran;
extern	int	debugLevel;
extern	int	outblocked;
extern  unsigned char myNodeAddr[];
extern	char	debugmsg[];

/* This is the framework for the FOUND frame to the client */
char	FOUNDFRAME[] = {
	0x00, 0x3a,				/* program length */
	0x00, 0x02,				/* command for FOUND frame */
	0x00, 0x08, 0x40, 0x03,			/* correlator header */
	0x00, 0x00, 0x00, 0x00,			/* correlator */
	0x00, 0x05, 0x40, 0x0B,			/* resp header */
	0x00,					/* resp code */
	0x00, 0x0A, 0x40, 0x0C,			/* dest header */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* dest address */
	0x00, 0x0A, 0x40, 0x06,			/* source header */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* source server address */
	0x00, 0x10, 0x00, 0x08,			/* info header */
	0x00, 0x06, 0x40, 0x09,			/* frame header */
	0x03, 0x00,				/* max frame */
	0x00, 0x06, 0x40, 0x0A,			/* class header */
	0x00, 0x00,				/* conn class */
	0x00, 0x05, 0x40, 0x07,			/* Lsap header */
	(char)0xFC				/* Rsap */
};

/* This is the framework for the FILEDATA response frames */
char	outFILE[1600] = {
	0x00, 0x19,				/* program length */
	0x00, 0x20,				/* FILE.DATA.RESPONSE */
	0x00, 0x08, 0x40, 0x11,			/* sequence header */
	0x00, 0x00, 0x00, 0x00,			/* sequence number of 00 */
	0x00, 0x0D, (char)0xC0, 0x14,		/* loader header */
	0x00, 0x00, 0x7C, 0x00,			/* load address */
	0x00, 0x00, 0x7C, 0x00,			/* transfer address */
	LOCATE_ENABLE,				/* flags */
	0x00, 0x44, 0x40, 0x18			/* data header */
};

int
sendFOUND(int fd, client_t *cp)
{
	struct		dl_address *addr;
	dl_priority_t	priority;

	if (debugLevel >= MSG_INFO_1) {
		sprintf(debugmsg, "Sending out FOUND Frame\n");
		senddebug(MSG_INFO_1);
	}

	addr = (struct dl_address *)dl_mkaddress(fd, cp->addr, 0xFC,
			(unsigned char *)NULL, 0);
	memcpy(&FOUNDFRAME[21], cp->addr, 6);
	memcpy(&FOUNDFRAME[31], myNodeAddr, 6);
	priority.dl_min = 10;
	priority.dl_max = 2;
	if (dl_snd(fd, FOUNDFRAME, 58, addr, &priority) == 0)
		cp->status = ST_FOUND_SENT;
	else
		outblocked = 1;
	return (0);
}

void
sendFILE(int fd, client_t *cp)
{
	char		ch;
	long		loadaddr;
	int		ncount;
	struct		dl_address *addr;
	dl_priority_t	priority;
	struct		stat statbuf;
	char		b[20];

	if (cp->delay > 0) {
		if (debugLevel >= MSG_ALWAYS) {
			sprintf(debugmsg,
			    "Delay = %d, not allowed to send yet\n",
			    cp->delay);
			senddebug(MSG_ALWAYS);
		}
		cp->delay--;
		return;
	}

	addr = (struct dl_address *)dl_mkaddress(fd, cp->addr,
					0xFC, (unsigned char *)NULL, 0);
	priority.dl_min = 10;
	priority.dl_max = 2;

	if (cp->fstr == NULL && cp->status != ST_FINISH) {
		if ((cp->fstr = fopen(cp->bootfp->filename, "r")) == NULL) {
			if (debugLevel >= MSG_ERROR_1) {
				sprintf(debugmsg, "Can't open bootfile %s\n",
						cp->bootfp->filename);
				senddebug(MSG_ERROR_1);
				sprintf(debugmsg,
				    "Terminating servicing this client\n");
				senddebug(MSG_ERROR_1);
			}
			cp->status = ST_FINISH;
			cp->timeo = time((time_t)0);
			cp->delay = cp->maxdelay;
			return;
		}
		cp->seekp = (long)0;
		cp->bootfp->seqnum = cp->seqnum;
		cp->currfp = cp->bootfp;
		stat(cp->bootfp->filename, &statbuf);
		cp->bootfp->size = (long)statbuf.st_size;
	}

	if (debugLevel >= MSG_INFO_2) {
		sprintf(debugmsg, "reading file %s, seeking to %ld\n",
				cp->currfp->filename, cp->seekp);
		senddebug(MSG_INFO_2);
	}

	fseek(cp->fstr, cp->seekp, SEEK_SET);
	ncount = fread(&outFILE[29], sizeof (char),
	    (cp->framesz)-PROTOCOL_OVERHEAD, cp->fstr);
	if (ncount > 0) {
		if (debugLevel >= MSG_ALWAYS) {
			sprintf(debugmsg, "%d bytes read from file\n", ncount);
			senddebug(MSG_ALWAYS);
		}

		/* sequence number */
		outFILE[8]  = (cp->seqnum & (long)0xff000000) >> 24;
		outFILE[9]  = (cp->seqnum & (long)0x00ff0000) >> 16;
		outFILE[10] = (cp->seqnum & (long)0x0000ff00) >> 8;
		outFILE[11] = (cp->seqnum & (long)0x000000ff);

		/* load address and flags */
		loadaddr = cp->currfp->loadaddr + cp->seekp;
		outFILE[16] = (loadaddr & (long)0xff000000) >> 24;
		outFILE[17] = (loadaddr & (long)0x00ff0000) >> 16;
		outFILE[18] = (loadaddr & (long)0x0000ff00) >> 8;
		outFILE[19] = (loadaddr & (long)0x000000ff);
		outFILE[24] = LOCATE_ENABLE;

		/* data header */
		outFILE[25] = ((ncount+4) & 0xff00) >> 8;
		outFILE[26] = ((ncount+4) & 0x00ff);

		/* program header */
		outFILE[0] = ((ncount + 0x19) & 0xff00) >> 8;
		outFILE[1] = ((ncount + 0x19) & 0x00ff);

		if (debugLevel >= MSG_ALWAYS) {
			sprintf(debugmsg, "%02X %02X: %d bytes, loading to "
			    "%02X %02X %02X %02X\n",
			    outFILE[10], outFILE[11],
			    ncount,
			    outFILE[16], outFILE[17],
			    outFILE[18], outFILE[19]);
			senddebug(MSG_ALWAYS);
		}

		/* send it out */
		if (dl_snd(fd, outFILE, ncount+29, addr, &priority) < 0)
			outblocked = 1;

		/* increment sequence number */
		cp->seqnum++;

		/* prepare for next seek */
		cp->seekp += (long)ncount;

		/* reset delay counter */
		cp->delay = cp->resetdflt;
	} /* ncount > 0 */

	/* see if we hit the end-of-file of the current file */
	if (debugLevel >= MSG_ALWAYS) {
		sprintf(debugmsg, "Checking for eof = %d\n", feof(cp->fstr));
		senddebug(MSG_ALWAYS);
	}

	if (cp->seekp >= cp->currfp->size) {
		if (debugLevel >= MSG_INFO_2) {
			sprintf(debugmsg,
			    "Current file reaches eof, closing\n");
			senddebug(MSG_INFO_2);
		}

		fclose(cp->fstr);
		if (cp->currfp->next) {
			cp->currfp = cp->currfp->next;
			if ((cp->fstr = fopen(cp->currfp->filename, "r"))
						== NULL) {
				if (debugLevel >= MSG_ERROR_1) {
					sprintf(debugmsg,
					    "Can't open bootfile %s\n",
					    cp->currfp->filename);
					senddebug(MSG_ERROR_1);
					sprintf(debugmsg, "Terminating "
					    "servicing this client\n");
					senddebug(MSG_ERROR_1);
				}
				cp->status = ST_FINISH;
				cp->timeo = time((time_t)0);
				cp->delay = cp->maxdelay;
				return;
			}
			cp->currfp->seqnum = cp->seqnum;
			cp->seekp = (long)0;
			stat(cp->currfp->filename, &statbuf);
			cp->currfp->size = (long)statbuf.st_size;

		} else {
			if (debugLevel >= MSG_INFO_2) {
				sprintf(debugmsg, "All files downloaded, "
				    "update state to ST_SEND_FINAL\n");
				senddebug(MSG_INFO_2);
			}
			cp->status = ST_SEND_FINAL;
		}
	}
}

void
sendFINAL(int fd, client_t *cp)
{
	struct		dl_address *addr;
	dl_priority_t	priority;

	if (cp->delay > 0) {
		if (debugLevel >= MSG_ALWAYS) {
			sprintf(debugmsg,
			    "Delay = %d, not allowed to send yet\n",
			    cp->delay);
			senddebug(MSG_ALWAYS);
		}
		cp->delay--;
		return;
	}

	addr = (struct dl_address *)dl_mkaddress(fd, cp->addr,
					0xFC, (unsigned char *)NULL, 0);
	priority.dl_min = 10;
	priority.dl_max = 2;

	if (debugLevel >= MSG_INFO_1) {
		sprintf(debugmsg, "sending down the last frame\n");
		senddebug(MSG_INFO_1);
	}

	/* sequence number */
	outFILE[8]  = (cp->seqnum & (long)0xff000000) >> 24;
	outFILE[9]  = (cp->seqnum & (long)0x00ff0000) >> 16;
	outFILE[10] = (cp->seqnum & (long)0x0000ff00) >> 8;
	outFILE[11] = (cp->seqnum & (long)0x000000ff);

	/* transfer address */
	outFILE[20] = (cp->xferaddr & (long)0xff000000) >> 24;
	outFILE[21] = (cp->xferaddr & (long)0x00ff0000) >> 16;
	outFILE[22] = (cp->xferaddr & (long)0x0000ff00) >> 8;
	outFILE[23] = (cp->xferaddr & (long)0x000000ff);

	/* flags */
	outFILE[24] = END_OF_FILE | XFER_ENABLE;

	/* data header */
	outFILE[25] = 0;
	outFILE[26] = 4;

	/* program header */
	outFILE[0] = 0;
	outFILE[1] = 0x19;

	if (debugLevel >= MSG_ALWAYS) {
		sprintf(debugmsg,
		    "%02X %02X: transfer to %02X %02X %02X %02X\n",
		    outFILE[10], outFILE[11],
		    outFILE[20], outFILE[21],
		    outFILE[22], outFILE[23]);
		senddebug(MSG_ALWAYS);
	}

	if (dl_snd(fd, outFILE, 29, addr, &priority) < 0)
		outblocked = 1;

	cp->fstr = NULL;
	cp->status = ST_FINISH;
	cp->timeo = time((time_t)0);
	cp->delay = cp->maxdelay;
	cp->currfp = cp->bootfp;
}
