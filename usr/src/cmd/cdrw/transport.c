/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/scsi/impl/uscsi.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libintl.h>

#include "transport.h"
#include "main.h"
#include "util.h"
#include "mmc.h"

char rqbuf[RQBUFLEN];
uchar_t	uscsi_status, rqstatus, rqresid;
static struct	uscsi_cmd uscmd;
static char	ucdb[16];
static uint_t	total_retries;

struct uscsi_cmd *
get_uscsi_cmd(void)
{
	(void) memset(&uscmd, 0, sizeof (uscmd));
	(void) memset(ucdb, 0, 16);
	uscmd.uscsi_cdb = ucdb;
	return (&uscmd);
}

int
uscsi(int fd, struct uscsi_cmd *scmd)
{
	int ret, global_rqsense;
	int retries, max_retries;

	/* set up for request sense extensions */
	if (!(scmd->uscsi_flags & USCSI_RQENABLE)) {
		scmd->uscsi_flags |= USCSI_RQENABLE;
		scmd->uscsi_rqlen = RQBUFLEN;
		scmd->uscsi_rqbuf = rqbuf;
		global_rqsense = 1;
	} else {
		global_rqsense = 0;
	}

	/*
	 * Some DVD drives may have a delay for writing or sync cache, and
	 * read media info (done after syncing cache). This can take a
	 * significant number of time. Such as the Pioneer A0X which will
	 * generate TOC after the cache is full in the middle of writing.
	 */

	if ((device_type != CD_RW) && ((scmd->uscsi_cdb[0] == WRITE_10_CMD) ||
	    (scmd->uscsi_cdb[0] == READ_INFO_CMD) || (scmd->uscsi_cdb[0] ==
	    SYNC_CACHE_CMD) || (scmd->uscsi_cdb[0] == CLOSE_TRACK_CMD))) {

		max_retries = 500;
	} else {
		/*
		 * Pioneer A08/A09 retries approx 30 times.
		 */
		max_retries = 40;
	}

	/*
	 * The device may be busy or slow and fail with a not ready status.
	 * we'll allow a limited number of retries to give the drive time
	 * to recover.
	 */
	for (retries = 0; retries < max_retries; retries++) {

		scmd->uscsi_status = 0;

		if (global_rqsense)
			(void) memset(rqbuf, 0, RQBUFLEN);

		if (debug && verbose) {
			int i;

			(void) printf("cmd:[");
			for (i = 0; i < scmd->uscsi_cdblen; i++)
				(void) printf("0x%02x ",
				    (uchar_t)scmd->uscsi_cdb[i]);
			(void) printf("]\n");
		}

		/*
		 * We need to have root privledges in order to use
		 * uscsi commands on the device.
		 */

		raise_priv();
		ret = ioctl(fd, USCSICMD, scmd);
		lower_priv();

		/* maintain consistency in case of sgen */
		if ((ret == 0) && (scmd->uscsi_status == 2)) {
			ret = -1;
			errno = EIO;
		}

		/* if error and extended request sense, retrieve errors */
		if (global_rqsense && (ret < 0) && (scmd->uscsi_status == 2)) {
			/*
			 * The drive is not ready to recieve commands but
			 * may be in the process of becoming ready.
			 * sleep for a short time then retry command.
			 * SENSE/ASC = 2/4 : not ready
			 * ASCQ = 0  Not Reportable.
			 * ASCQ = 1  Becoming ready.
			 * ASCQ = 4  FORMAT in progress.
			 * ASCQ = 7  Operation in progress.
			 * ASCQ = 8  Long write in progress.
			 */
			if ((SENSE_KEY(rqbuf) == 2) && (ASC(rqbuf) == 4) &&
			    ((ASCQ(rqbuf) == 0) || (ASCQ(rqbuf) == 1) ||
			    (ASCQ(rqbuf) == 4)) || (ASCQ(rqbuf) == 7)) {
				total_retries++;
				(void) sleep(3);
				continue;
			}

			/*
			 * we do not print this out under normal circumstances
			 * since we have BUFE enabled and do not want to alarm
			 * users with uneccessary messages.
			 */
			if (debug) {
				if ((SENSE_KEY(rqbuf) == 5) && (ASC(rqbuf) ==
				    0x21) && (ASCQ(rqbuf) == 2)) {
					(void) printf(gettext(
			"Buffer underrun occurred! trying to recover...\n"));
				}
			}

			/*
			 * long write operation in progress, ms_delay is
			 * used for some fast drives with a short drive
			 * buffer. Such as Pioneer DVD-RW drives. They will
			 * begin to generate TOC when the buffer is initially
			 * full, then resume operation a few minutes later
			 * with the buffer emptying quickly.
			 */
			if ((SENSE_KEY(rqbuf) == 2) && (ASC(rqbuf) == 4) &&
			    (ASCQ(rqbuf) == 8)) {
				total_retries++;
				/*
				 * In Simulation write mode, we use the
				 * READ_INFO_CMD to check if all the previous
				 * writes completed. Sleeping 500 ms will not
				 * be sufficient in all cases for DVDs.
				 */
				if ((device_type != CD_RW) &&
				    ((scmd->uscsi_cdb[0] == CLOSE_TRACK_CMD) ||
				    ((scmd->uscsi_cdb[0] == READ_INFO_CMD) &&
				    simulation)))
					(void) sleep(3);
				else
					ms_delay(500);
				continue;
			}
			/*
			 * Device is not ready to transmit or a device reset
			 * has occurred. wait for a short period of time then
			 * retry the command.
			 */
			if ((SENSE_KEY(rqbuf) == 6) && ((ASC(rqbuf) == 0x28) ||
			    (ASC(rqbuf) == 0x29))) {
				(void) sleep(3);
				total_retries++;
				continue;
			}

			if ((SENSE_KEY(rqbuf) == 5) &&
			    (device_type == DVD_PLUS ||
			    device_type == DVD_PLUS_W)) {
				if (scmd->uscsi_cdb[0] == MODE_SELECT_10_CMD &&
				    ASC(rqbuf) == 0x26) {
					ret = 1;
					break;
				}

				if (scmd->uscsi_cdb[0] == REZERO_UNIT_CMD &&
				    ASC(rqbuf) == 0x20) {
					ret = 1;
					break;
				}

			}
			/*
			 * Blank Sense, we don't know what the error is or if
			 * the command succeeded, Hope for the best. Some
			 * drives return blank sense periodically and will
			 * fail if this is removed.
			 */
			if ((SENSE_KEY(rqbuf) == 0) && (ASC(rqbuf) == 0) &&
			    (ASCQ(rqbuf) == 0)) {
				ret = 0;
				break;
			}

			if (debug) {
				(void) printf("cmd: 0x%02x ret:%i status:%02x "
				    " sense: %02x ASC: %02x ASCQ:%02x\n",
				    (uchar_t)scmd->uscsi_cdb[0], ret,
				    scmd->uscsi_status,
				    (uchar_t)SENSE_KEY(rqbuf),
				    (uchar_t)ASC(rqbuf), (uchar_t)ASCQ(rqbuf));
			}
		}

		/* no errors we'll return */
		break;
	}

	/* store the error status for later debug printing */
	if ((ret < 0) && (global_rqsense)) {
		uscsi_status = scmd->uscsi_status;
		rqstatus = scmd->uscsi_rqstatus;
		rqresid = scmd->uscsi_rqresid;

	}

	if (debug && retries) {
		(void) printf("total retries: %d\n", total_retries);
	}

	return (ret);
}
