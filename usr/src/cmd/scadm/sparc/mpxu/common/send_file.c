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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * send_file.c: to support firmware download (get fw S-records from the
 * user-specified file and send S-records string down to the service processor
 */

#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "librsc.h"
#include "adm.h"


int
ADM_Send_file(FILE  *FilePtr)
{
	static char		ADM_Line[ADM_LINE_SIZE];
	static bp_msg_t		Message;
	static struct timespec	Timeout;
	int			LinesWritten;
	int			Status;
	int			BootRetry;
	int			LastRecord;
	long			FileLength = 0L;
	long			FilePos;


	/*
	 * Determine the length of the file
	 */
	if (fseek(FilePtr, 0L, SEEK_END) == 0) {
		FileLength = ftell(FilePtr);
		rewind(FilePtr);
	}

	LinesWritten = 0;
	LastRecord   = 0;
	while ((fgets(ADM_Line, ADM_LINE_SIZE, FilePtr) != NULL) &&
	    (LastRecord == 0)) {
		if ((ADM_Line[0] == 'S') &&
		    ((ADM_Line[1] == '7') || (ADM_Line[1] == '8') ||
		    (ADM_Line[1] == '9'))) {
			LastRecord = 1;
		}

		BootRetry = ADM_BOOT_RETRY;
		while (BootRetry > 0) {
			if ((Status =
			    rsc_raw_write(ADM_Line, strlen(ADM_Line))) != 0) {
				return (Status);
			}

			/*
			 * Initialize Timeout each time just to be robust.
			 * Since this operation is not time critical, this is
			 * not a concern.
			 */
			Timeout.tv_nsec = 0;
			Timeout.tv_sec  = ADM_BOOT_LOAD_TIMEOUT;
			/* If we timeout, decrement BootRetry and try again */
			if ((Status = ADM_Boot_recv(&Message, &Timeout)) != 0) {
				/* We got a timeout */
				BootRetry = BootRetry - 1;
				continue;

			} else {

				/* we got a message back, see what it is */
				if ((Message.cmd  == BP_RSC_BOOTOK) &&
				    (Message.dat1 == 0) &&
				    (Message.dat2 == 0)) {

					LastRecord = 1;
					break;
				}

				if ((Message.cmd  != BP_RSC_BOOTACK) ||
				    (Message.dat1 != BP_DAT1_SRECORD_ACK)) {

					if (Message.dat1 ==
					    BP_DAT1_SRECORD_NAK) {
						continue;
					}
					ADM_Display_download_error(
					    (int)Message.cmd,
					    (int)Message.dat1);
					exit(-1);
				}

				/*
				 * We got a valid acknowledge, break out of
				 * loop and start to download next s-record
				 */
				break;
			}
		}

		/* See if we ever got a response */
		if (BootRetry <= 0) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: SC failed to respond during "
			    "download"));
			exit(-1);
		}

		LinesWritten++;
		if ((LinesWritten % 100) == 0) {
			(void) printf(".");
			(void) fflush(stdout);
		}
		if ((LinesWritten % 4000) == 0) {
			if (FileLength) {
				/* Show % progress */
				FilePos = ftell(FilePtr);
				(void) printf(" (%ld%%)",
				    (FilePos * 100) / FileLength);
			}
			(void) printf("\n");
			(void) fflush(stdout);
		}
	}
	if ((FileLength) && ((LinesWritten % 4000) != 0)) {
		/* Show final % progress (should normally be 100%) */
		FilePos = ftell(FilePtr);
		(void) printf(" (%ld%%)",
		    (FilePos * 100) / FileLength);
	}
	(void) printf("\n");

	return (0);
}


void
ADM_Display_download_error(int cmd, int dat1)
{
	if (cmd == BP_RSC_BOOTFAIL) {
		if (dat1 == BP_DAT1_REJECTED) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: download rejected"));

		} else if (dat1 == BP_DAT1_RANGE_ERR) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: download failed, "
			    "SC reported range error"));

		} else if (dat1 == BP_DAT1_VERIFY_ERR) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: download failed, "
			    "SC reported verify error"));

		} else if (dat1 == BP_DAT1_ERASE_ERR) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: download failed, "
			    "SC reported erase error"));

		} else if (dat1 == BP_DAT1_INT_WP_ERR) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: download failed, "
			    "SC reported int_wp error"));

		} else if (dat1 == BP_DAT1_WP_ERR) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: download failed, "
			    "SC reported wp error"));

		} else if (dat1 == BP_DAT1_VPP_ERR) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: download failed, "
			    "SC reported vpp error"));
		} else {
			(void) fprintf(stderr, "%s 0x%08x\n",
			    gettext("scadm: SC returned fatal error"), dat1);
		}
	} else if (cmd == BP_RSC_BOOTACK) {
		if (dat1 == BP_DAT1_SRECORD_ACK) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: download failed"));
		} else {
			(void) fprintf(stderr, "%s 0x%08x\n",
			    gettext("scadm: SC returned fatal error"), dat1);
		}
	} else {
		(void) fprintf(stderr, "%s 0x%08x:0x%08x\n",
		    gettext("scadm: SC returned unknown error"), cmd, dat1);
	}
}
