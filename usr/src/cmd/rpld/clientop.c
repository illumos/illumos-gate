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

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "rpld.h"

extern client_t *clntp;
extern int	totclnt;
extern char	databuf[];
extern unsigned long delayGran;
extern unsigned long startDelay;
extern int	frameSize;
extern int	debugLevel;
extern int	maxClients;
extern char	debugmsg[];

/*
 * Add the new client between the current clntp and its next in the
 * circular linked list.
 */
void
clientadd(client_t *addp)
{
	client_t *cp;

	totclnt++;
	if (totclnt == 1 && clntp == NULL) {
		clntp = addp;
		clntp->next = clntp;
		clntp->prev = clntp;
		return;
	}

	cp = clntp->next;
	addp->next = cp;
	addp->prev = clntp;
	cp->prev = addp;
	clntp->next = addp;
}

/*
 * Remove the indicated client from the circular linked list.
 */
void
clientremove(client_t *rmp)
{
	client_t *cp;

	if (debugLevel >= MSG_INFO_1) {
		sprintf(debugmsg, "removing client %0X %0X %0X %0X %0X %0X\n",
			rmp->addr[0], rmp->addr[1], rmp->addr[2],
			rmp->addr[3], rmp->addr[4], rmp->addr[5]);
		senddebug(MSG_INFO_1);
	}

	totclnt--;
	if (totclnt == 0) {
		clntp = (client_t *)NULL;
		return;
	}

	cp = rmp->next;
	cp->prev = rmp->prev;
	cp = rmp->prev;
	cp->next = rmp->next;
}

client_t *
clientlookup(unsigned char addr[])
{
	int	i;
	int	found = 0;
	client_t *cp = clntp;

	if (debugLevel >= MSG_INFO_2) {
		sprintf(debugmsg,
		    "Entered clientlookup(), number of clients = %d\n",
		    totclnt);
		senddebug(MSG_INFO_2);
	}

	if (totclnt == 0) {
		if (debugLevel >= MSG_INFO_2) {
			sprintf(debugmsg, "No clients yet, returning\n");
			senddebug(MSG_INFO_2);
		}
		return (NULL);
	}

	if (debugLevel >= MSG_INFO_1) {
		sprintf(debugmsg,
		    "Looking for client %0X %0X %0X %0X %0X %0X\n",
		    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		senddebug(MSG_INFO_1);
	}

	for (i = 0; i < totclnt; i++) {
		if (cp->addr[0] == addr[0] && cp->addr[1] == addr[1] &&
		    cp->addr[2] == addr[2] && cp->addr[3] == addr[3] &&
		    cp->addr[4] == addr[4] && cp->addr[5] == addr[5]) {
			if (debugLevel >= MSG_INFO_1) {
				sprintf(debugmsg, "Client found\n");
				senddebug(MSG_INFO_1);
			}
			found = 1;
			break;
		}
		cp = cp->next;
	}
	if (found)
		return (cp);
	else
		return (NULL);
}


int
clientvalidate(void)
{
	struct ether_addr *addrp;
	client_t *cp;
	bootfile_t  *bp, *bp1;
	int	done = 0;
	int	i, j;
	int	bootparamslen;
	int	numfiles = -1;
	char	hostname[100];
	char	bootparams[1000];

	if (maxClients >= 0 && totclnt >= maxClients) {
		if (debugLevel >= MSG_WARN_2) {
			sprintf(debugmsg, "Already serving maximum number of "
			    "clients (= %d), request ignored\n", maxClients);
			senddebug(MSG_WARN_2);
		}
		return (-1);
	}

	/*
	 * Get the network address from the global data buffer and look
	 * it up in the ethers database.
	 */
	addrp = (struct ether_addr *)&databuf[32];
	if (ether_ntohost(hostname, addrp) != 0) {
		if (debugLevel >= MSG_WARN_1) {
			sprintf(debugmsg,
			    "ether_ntohost() failed, errno = %d\n", errno);
			senddebug(MSG_WARN_1);
		}
		return (-1);
	} else {
		if (debugLevel >= MSG_INFO_1) {
			sprintf(debugmsg, "host is %s\n", hostname);
			senddebug(MSG_INFO_1);
		}
	}

	/* See if we are already serving this client */
	if ((cp = clientlookup((unsigned char *)&databuf[32])) != NULL) {
		if (debugLevel >= MSG_INFO_2) {
			sprintf(debugmsg,
			    "Requesting client is already being serviced.\n");
			senddebug(MSG_INFO_2);
			sprintf(debugmsg, "Updating its record to "
			    "ST_FIND_RCVD and start over\n");
			senddebug(MSG_INFO_2);
		}

		/* start from the beginning */
		cp->status = ST_FIND_RCVD;
		fclose(cp->fstr);
		cp->currfp = cp->bootfp;
		cp->seekp = 0;
		cp->seqnum = 0;
		cp->maxdelay = startDelay;
		cp->timeo = 10*startDelay;
		return (0);
	}

	/*
	 * Now lookup the bootparams database and retrieve the whole
	 * client record in ASCII.
	 */
	if (bootparams_getbyname(hostname, bootparams,
	    sizeof (bootparams)) != 0) {
		if (debugLevel >= MSG_ERROR_1) {
			sprintf(debugmsg,
			    "Failed to retrieve bootparams for this client\n");
			senddebug(MSG_ERROR_1);
		}
		return (-1);
	}
	bootparamslen = strlen(bootparams);
	if (debugLevel >= MSG_ALWAYS) {
		sprintf(debugmsg, "Raw bootparams input\n");
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg, "%s\n", bootparams);
		senddebug(MSG_ALWAYS);
	}

	/* The TAB char will be a problem, so replace them with '\0' */
	for (i = 0; i < bootparamslen; i++) {
		if (bootparams[i] == TAB || bootparams[i] == ' ')
			bootparams[i] = '\0';
	}
	if (debugLevel >= MSG_ALWAYS) {
		sprintf(debugmsg, "After translation\n");
		senddebug(MSG_ALWAYS);
		sprintf(debugmsg, "%s\n", bootparams);
		senddebug(MSG_ALWAYS);
	}

	/*
	 * Try to allocate a client_t structure to serve this client.
	 */
	if ((cp = (client_t *)malloc(sizeof (client_t))) == NULL) {
		if (debugLevel >= MSG_WARN_1) {
			sprintf(debugmsg, "malloc() failed in adding a new "
			    "client_t structure\n");
			senddebug(MSG_WARN_1);
		}
		return (-1);
	}

	/* Fill this structure with config info */
	memcpy(cp->addr, addrp, 6);
	cp->status = ST_FIND_RCVD;
	cp->bootfp = (bootfile_t *)NULL;
	cp->fstr = NULL;
	cp->seekp = -1;
	cp->seqnum = 0;
	cp->framesz = frameSize;
	cp->maxdelay = startDelay;
	cp->timeo = 10*startDelay;
	cp->delay = cp->resetdflt = startDelay;

	/* Get the number of boot files for this client */
	for (i = 0; i < bootparamslen - 13; i++) {
		if (bootparams[i] == 'n' &&
		    bootparams[i+1] == 'u' && bootparams[i+2] == 'm' &&
		    bootparams[i+3] == 'b' && bootparams[i+4] == 'o' &&
		    bootparams[i+5] == 'o' && bootparams[i+6] == 't' &&
		    bootparams[i+7] == 'f' && bootparams[i+8] == 'i' &&
		    bootparams[i+9] == 'l' && bootparams[i+10] == 'e' &&
		    bootparams[i+11] == 's' && bootparams[i+12] == '=') {
			sscanf(&bootparams[i+13], "%d", &numfiles);
		}
	}
	if (numfiles < 0) {
		if (debugLevel >= MSG_ERROR_1) {
			sprintf(debugmsg,
			    "Must have at least 1 bootfile for this client\n");
			senddebug(MSG_ERROR_1);
		}
		free(cp);
		return (-1);
	}
	if (debugLevel >= MSG_INFO_2) {
		sprintf(debugmsg,
		    "There are %d bootfiles for this client\n", numfiles);
		senddebug(MSG_INFO_2);
	}

	/* Create the bootfile list and fill in the info from bootparams */
	for (j = 0; j < numfiles; j++) {
		if ((bp1 = (bootfile_t *)malloc(sizeof (bootfile_t))) == NULL) {
			if (debugLevel >= MSG_WARN_1) {
				sprintf(debugmsg, "Cound not malloc() "
				    "bootfile_t for bootfile %d\n", j);
				senddebug(MSG_WARN_1);
			}
			goto cleanup;
		}
		bp1->next = (bootfile_t *)NULL;
		bp1->seqnum = (long)-1;
		if (cp->bootfp == (bootfile_t *)NULL) {
			cp->bootfp = bp1;
		} else {
			bp->next = bp1;
		}
		bp = bp1;
	}
	bp = cp->bootfp;
	for (i = 0; i < bootparamslen - 9; i++) {
		if (bootparams[i] == 'b' &&
		    bootparams[i+1] == 'o' && bootparams[i+2] == 'o' &&
		    bootparams[i+3] == 't' && bootparams[i+4] == 'f' &&
		    bootparams[i+5] == 'i' && bootparams[i+6] == 'l' &&
		    bootparams[i+7] == 'e' && bootparams[i+8] == '=') {
			if (debugLevel >= MSG_ALWAYS) {
				sprintf(debugmsg, "found boot file");
				senddebug(MSG_ALWAYS);
			}
			(void) strlcpy(bp->filename,
				&bootparams[i+9], sizeof (bp->filename));
			for (j = strlen(bp->filename); j >= 0; j--)
				if (bp->filename[j] == ':')
					break;
			bp->filename[j] = '\0';

			if (access(bp->filename, R_OK) < 0) {
				if (debugLevel >= MSG_ERROR_1) {
					sprintf(debugmsg,
						"No access to bootfile (%s)\n",
						bp->filename);
					senddebug(MSG_ERROR_1);
				}
				goto cleanup;
			}

			sscanf(&(bp->filename[j+1]), "%lx",
					&(bp->loadaddr));
			if (debugLevel >= MSG_ALWAYS) {
				sprintf(debugmsg, " %s loading to %lx\n",
					bp->filename, bp->loadaddr);
				senddebug(MSG_ALWAYS);
			}

			bp = bp->next;
		}
	}

	/* Finally the transfer address */
	for (i = 0; i < bootparamslen - 9; i++) {
		if (bootparams[i] == 'b' &&
		    bootparams[i+1] == 'o' && bootparams[i+2] == 'o' &&
		    bootparams[i+3] == 't' && bootparams[i+4] == 'a' &&
		    bootparams[i+5] == 'd' && bootparams[i+6] == 'd' &&
		    bootparams[i+7] == 'r' && bootparams[i+8] == '=') {
			if (debugLevel >= MSG_ALWAYS) {
				sprintf(debugmsg, "found xfer addr");
				senddebug(MSG_ALWAYS);
			}
			sscanf(&bootparams[i+9], "%lx", &(cp->xferaddr));
			if (debugLevel >= MSG_ALWAYS) {
				sprintf(debugmsg, " at %lx\n", cp->xferaddr);
				senddebug(MSG_ALWAYS);
			}
		}
	}
	clientadd(cp);
	return (0);

cleanup:
	/* clean up any allocated structures and return */
	bp = cp->bootfp;
	while (bp) {
		bp1 = bp->next;
		free(bp);
		bp = bp1;
	}
	free(cp);
	return (-1);
}
