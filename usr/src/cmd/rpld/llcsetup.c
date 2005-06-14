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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/stropts.h>
#include <poll.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>

#include <sys/stream.h>
#include <sys/kstat.h>
#include <sys/llc1.h>

#include <dirent.h>

#include "rpld.h"
#include "dluser.h"

#define		BUFSIZE		10000

unsigned char   multAddr[6]  = {0x03, 0x00, 0x02, 0x00, 0x00, 0x00};
unsigned char   multAddr2[6] = {0xc0, 0x00, 0x40, 0x00, 0x00, 0x00};

static char *llcdev;

extern int	if_fd;
extern struct pollfd llc_fd;
extern char	ifName[];
extern int	debugLevel;
extern char	debugmsg[];
extern int	ifUnit;
extern int	ppanum;
extern int	need_llc;

struct ether_addr	myNodeAddr;
/*
 * Next lines makes enabmulti, and thus its fields, 32 bit aligned. This is
 * necessary on sparc. Space allocated must be rounded up to the next highest
 * number of words.
 */
uint32_t	enabmulti_aligned[(
			DL_ENABMULTI_REQ_SIZE		/* Basic size */
			+ 10				/* Address */
			+ sizeof (uint32_t) - 1)/	/* Round up */
			sizeof (uint32_t)];		/* Convert to 32 bit */
char	*enabmulti = (char *)enabmulti_aligned;
union	DL_primitives *enabp = (union DL_primitives *)enabmulti_aligned;

int
llcsetup(void)
{
struct strbuf	ctl;
char	resultbuf[MAXPRIMSZ];	/* Bigger than largest DLPI		*/
				/* struct size 				*/
union DL_primitives *dlp = (union DL_primitives *)resultbuf;
struct ll_snioc	snioc;
struct strioctl	strio;
int		flags = 0;
int		muxid;
char		myname[64];
struct ether_addr	eas;
DIR *dp;
struct dirent *de;
int 		use_llc1;
unsigned char	*multAddrp;
dl_info_t	if_info;


	/*
	 * Open a stream to the Ethernet driver.
	 */
	if (debugLevel >= MSG_INFO_2) {
		sprintf(debugmsg, "Opening %s\n", ifName);
		senddebug(MSG_INFO_2);
	}
	if ((if_fd = dl_open(ifName, O_RDWR, NULL)) < 0) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg, "Cannot open device %s\n", ifName);
			senddebug(MSG_FATAL);
		}
		return (-1);
	}

	if (dl_info(if_fd, &if_info) < 0) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg, "Cannot get info from device %s\n",
				ifName);
			senddebug(MSG_FATAL);
		}
		return (-1);
	}

	/*
	 * Attach the Ethernet stream to PPA specified by ifUnit.
	 */
	if (debugLevel >= MSG_INFO_2) {
		sprintf(debugmsg, "Sending DL_ATTACH_REQ to %s for PPA %d\n",
			ifName, ifUnit);
		senddebug(MSG_INFO_2);
	}
	if (dl_attach(if_fd, ifUnit) < 0) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg, "Failed in dl_attach of %s to %d\n",
				ifName, ifUnit);
			senddebug(MSG_FATAL);
		}
		return (-1);
	}

	/*
	 * Get the node address
	 */
	if (dlpi_get_phys(if_fd, &myNodeAddr) == 0) {
		if (debugLevel >= MSG_INFO_1) {
			sprintf(debugmsg, "My node address: %s ",
				ether_ntoa(&myNodeAddr));
			senddebug(MSG_INFO_1);
			sprintf(debugmsg, "\n");
			senddebug(MSG_INFO_1);
		}
	} else {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg, "Cannot get my own node address\n");
			senddebug(MSG_FATAL);
		}
		return (-1);
	}

	/*
	 * Bind the Ethernet stream to SAP 0xfc.
	 */
	if (debugLevel >= MSG_INFO_2) {
		sprintf(debugmsg, "Sending DL_BIND_REQ to ethernet driver\n");
		senddebug(MSG_INFO_2);
	}
	if (dl_bind(if_fd, 0xFC, 0, 0) < 0) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg, "Failed in dl_bind to %s\n", ifName);
			senddebug(MSG_FATAL);
		}
		return (-1);
	}

	if (debugLevel >= MSG_INFO_1) {
		if (need_llc)
			sprintf(debugmsg, "Need to link LLC under %s\n",
			    ifName);
		else
			sprintf(debugmsg, "No need to link LLC under %s\n",
			    ifName);
		senddebug(MSG_INFO_1);
	}

	/*
	 * Token ring (IEEE 802.5) has the multicast address bytes
	 * bit-reversed (but not byte-reserved)
	 */
	if (if_info.mac_type == DLTYPE_IEEE8025)
		multAddrp = multAddr2;
	else
		multAddrp = multAddr;

	if (need_llc) {
		/*
		 * Open a stream to the LLC driver.
		 * At this point it is certain that an llc device is needed
		 * So we try only llc1.
		 */

		llcdev = "/dev/llc1";
		if (debugLevel >= MSG_INFO_2) {
			sprintf(debugmsg, "Opening %s for SAP FC\n",
				llcdev);
			senddebug(MSG_INFO_2);
		}

		if ((llc_fd.fd = dl_open(llcdev, O_RDWR, NULL)) < 0) {
			/*
			 * llc1 doesnt work barf and quit.
			 */
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg,
					"Failed to open device %s\n",
					llcdev);
				senddebug(MSG_FATAL);
			}
			return (-1);
		}

		/*
		 * I_LINK ifName underneath /dev/llc
		 */
		if (debugLevel >= MSG_INFO_2) {
			sprintf(debugmsg, "Linking %s underneath %s FC case\n",
			    ifName, llcdev);
			senddebug(MSG_INFO_2);
		}
		if ((muxid = ioctl(llc_fd.fd, I_LINK, if_fd)) < 0) {
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg,
					"Failed to I_LINK %s under %s\n",
					ifName, llcdev);
				senddebug(MSG_FATAL);
			}
			return (-1);
		}

		/*
		 * Set the PPA of the Ethernet driver to ppanum.
		 * (This is the PPA that LLC clients need to specify when they
		 * attach to LLC.)
		 */
		if (debugLevel >= MSG_INFO_2) {
			sprintf(debugmsg, "setting PPA to %d\n", ppanum);
			senddebug(MSG_INFO_2);
		}
		snioc.lli_type = LI_SPPA;
		snioc.lli_ppa = ppanum;
		snioc.lli_index = muxid;
		strio.ic_cmd = L_SETPPA;
		strio.ic_timout = -1;			/* Infinite timeout */
		strio.ic_len = sizeof (snioc);
		strio.ic_dp = (char *)&snioc;
		if (ioctl(llc_fd.fd, I_STR, (char *)&strio) < 0) {
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg,
				    "Failed to set PPA %d to device %s\n",
				    ppanum, llcdev);
				senddebug(MSG_FATAL);
			}
			return (-1);
		}

		/*
		 * Attach the LLC stream to PPA ppanum.
		 */
		if (debugLevel >= MSG_INFO_2) {
			sprintf(debugmsg,
			    "Sending DL_ATTACH_REQ to %s FC\n", llcdev);
			senddebug(MSG_INFO_2);
		}
		if (dl_attach(llc_fd.fd, ppanum) < 0) {
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg,
				    "Failed to attach to device %s\n",
				    llcdev);
				senddebug(MSG_FATAL);
			}
			return (-1);
		}

		/*
		 * Bind the LLC stream to SAP 0xfc.
		 */
		if (debugLevel >= MSG_INFO_2) {
			sprintf(debugmsg,
			    "Sending DL_BIND_REQ to %s FC\n", llcdev);
			senddebug(MSG_INFO_2);
		}
		if (dl_bind(llc_fd.fd, 0xFC, DL_AUTO_TEST | DL_AUTO_XID, 0)
		    < 0) {
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg,
				    "Failed to bind to device %s\n",
				    llcdev);
				senddebug(MSG_FATAL);
			}
			return (-1);
		}
	} else {
		/* All subsequent I/O done using llc_fd.fd */
		llc_fd.fd = if_fd;
	}

	/*
	 * Set the RPL multicast address
	 */
	if (debugLevel >= MSG_INFO_2) {
		sprintf(debugmsg, "setting RPL multicast address\n");
		senddebug(MSG_INFO_2);
	}
	enabp->enabmulti_req.dl_primitive = DL_ENABMULTI_REQ;
	enabp->enabmulti_req.dl_addr_length = 6;
	enabp->enabmulti_req.dl_addr_offset = DL_ENABMULTI_REQ_SIZE;
	memcpy(&enabmulti[DL_ENABMULTI_REQ_SIZE], multAddrp, 6);
	ctl.len = DL_ENABMULTI_REQ_SIZE + 6;

	ctl.buf = enabmulti;
	if (putmsg(llc_fd.fd, &ctl, NULL, 0) < 0) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg,
			"Failed to enable RPL required multicast address\n");
			senddebug(MSG_FATAL);
		}
		return (-1);
	}

	/*
	 * Read the acknowledgement message (will be DL_OK_ACK if
	 * it was successful).
	 */
	ctl.maxlen = MAXPRIMSZ;
	ctl.buf = resultbuf;
	if (getmsg(llc_fd.fd, &ctl, NULL, &flags) < 0) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg,
	"Failed in getmsg() to receive ack for multicast enable operation\n");
			senddebug(MSG_FATAL);
		}
		return (-1);
	}

	if (dlp->dl_primitive != DL_OK_ACK) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg, "dl_errno %d unix_errno %d\n",
				dlp->error_ack.dl_errno,
				dlp->error_ack.dl_unix_errno);
			senddebug(MSG_FATAL);
		}
		return (-1);
	}

	return (0);
}

int
dlpi_get_phys(int fd, uchar_t  *eaddr)
{
	union DL_primitives	*dlp;
	char			*buf;
	struct strbuf 		ctl;
	int			flags;
	int			tmp;

	/* Allocate required buffers */
	if ((buf = (char *)memalign(BUFSIZE, sizeof (uint32_t))) == NULL) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg, "malloc() failed\n");
			senddebug(MSG_FATAL);
		}
		return (-1);
	}

	/* Issue DL_PHYS_ADDR_REQ */
	dlp = (union DL_primitives *)buf;

	dlp->physaddr_req.dl_primitive = DL_PHYS_ADDR_REQ;
	dlp->physaddr_req.dl_addr_type = DL_CURR_PHYS_ADDR;
	ctl.buf = (char *)dlp;
	ctl.len = DL_PHYS_ADDR_REQ_SIZE;
	if (putmsg(fd, &ctl, NULL, 0) < 0) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg,
			    "Failed in putmsg() for DL_PHYS_ADDR_REQ\n");
			senddebug(MSG_FATAL);
		}
		(void) free(buf);
		return (-1);
	}
	/* read reply */
	ctl.buf = (char *)dlp;
	ctl.len = 0;
	ctl.maxlen = BUFSIZE;
	flags = 0;
	if ((tmp = getmsg(fd, &ctl, NULL, &flags)) < 0) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg,
			    "Failed in getmsg() for DL_PHYS_ADDR_REQ\n");
			senddebug(MSG_FATAL);
		}
		(void) free(buf);
		return (-1);
	}
	if (debugLevel >= MSG_ALWAYS) {
		sprintf(debugmsg,
		    "phys_addr_ack: ret[%d] ctl.len[%d] flags[%d]\n",
		    tmp, ctl.len, flags);
		senddebug(MSG_ALWAYS);
	}
	/* Validate DL_PHYS_ADDR_ACK reply */
	if (ctl.len < sizeof (ulong_t)) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg,
		"phys_addr failed:  short reply to phys_addr request\n");
			senddebug(MSG_FATAL);
		}
		(void) free(buf);
		return (-1);
	}

	if (dlp->dl_primitive == DL_ERROR_ACK) {
		/*
		 * Do not print errors for DL_UNSUPPORTED and DL_NOTSUPPORTED
		 */
		if (dlp->error_ack.dl_errno != DL_UNSUPPORTED &&
		    dlp->error_ack.dl_errno != DL_NOTSUPPORTED) {
			if (debugLevel >= MSG_FATAL) {
				sprintf(debugmsg,
				"phys_addr failed: dl_errno %d unix_errno %d\n",
				    dlp->error_ack.dl_errno,
				    dlp->error_ack.dl_unix_errno);
				senddebug(MSG_FATAL);
			}
		}
		(void) free(buf);
		return (-1);
	}
	if (dlp->dl_primitive != DL_PHYS_ADDR_ACK) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg,
		"phys_addr failed:  unrecognizable dl_primitive %d received\n",
			    dlp->dl_primitive);
			senddebug(MSG_FATAL);
		}
		(void) free(buf);
		return (-1);
	}
	if (ctl.len < DL_PHYS_ADDR_ACK_SIZE) {
		if (debugLevel >= MSG_FATAL) {
			sprintf(debugmsg,
		"phys_addr failed: short phys_addr acknowledgement received\n");
			senddebug(MSG_FATAL);
		}
		(void) free(buf);
		return (-1);
	}
	/* Check length of address. */
	if (dlp->physaddr_ack.dl_addr_length != ETHERADDRL)
		return (-1);
	/*
	 * copy ethernet address
	 */
	memcpy((char *)eaddr, (char *)(buf + dlp->physaddr_ack.dl_addr_offset),
	    ETHERADDRL);
	(void) free(buf);
	return (0);
}
