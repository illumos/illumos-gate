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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * download.c: support to the scadm download option (download service
 * processor firmware)
 */

#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>  /* required by rsc.h */

#include "adm.h"
#include "librsc.h"
#include "smq.h"


extern smq_t		ADM_bpMsgQueue;
extern smq_msg_t	ADM_bpMsgBuffer[ADM_BP_BUFF_SIZE];

static void usage();


void
ADM_Process_download(int argc, char *argv[])
{
	int			BootRetry;
	uint8_t			DownloadLocation;
	static bp_msg_t		Message;
	static struct timespec	Timeout;
	char			*Filename;
	FILE			*FilePtr;
	timestruc_t		Delay;
	int			i, err;
	int retry;
	int bootOpt;

	if ((argc != 3) && (argc != 4)) {
		usage();
		exit(-1);
	}

	if (argc == 4) {
		if (strcasecmp(argv[2], "boot") != 0) {
			usage();
			exit(-1);
		}
		Filename = argv[3];
		DownloadLocation = BP_DAT2_FLASH_BOOT;
		bootOpt = 1;
	} else { /* no [boot] option */

		Filename = argv[2];
		DownloadLocation = BP_DAT2_FLASH_MAIN;
		bootOpt = 0;
	}

	if ((FilePtr = fopen(Filename, "r")) == NULL) {
		(void) fprintf(stderr, "\n%s - \"%s\"\n\n",
		    gettext("scadm: file could not be opened"), Filename);
		exit(-1);
	}


	/* Verify file is s-record */
	if (ADM_Valid_srecord(FilePtr) != 0) {
		(void) fprintf(stderr, "\n%s - \"%s\"\n\n",
		    gettext("scadm: file not a valid s-record"), Filename);
		exit(-1);
	}

	/*
	 * Don't call rscp_start() because SC may still be in the
	 * boot monitor.  The boot monitor will not respond to
	 * rscp_start()
	 */

	/*
	 * Initialize Message Queue used between ADM_Callback and
	 * ADM_Boot_recv(). ADM_Callback is called from seperate thread.
	 */
	if (smq_init(&ADM_bpMsgQueue, ADM_bpMsgBuffer,
	    ADM_BP_BUFF_SIZE) != 0) {

		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: ERROR, unable to setup message queue"));
		exit(-1);
	}

	/* Initialize callback for Boot Monitor RX */
	if (rscp_register_bpmsg_cb(ADM_Callback) != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: ERROR, callback init failed"));
		exit(-1);
	}

	BootRetry = ADM_BOOT_RETRY;
	while (BootRetry > 0) {

		/*
		 * Initialize Message each time because this structure is reused
		 * during receive.  Since this operation is not time critical,
		 * this is not a concern
		 */
		Message.cmd  = BP_OBP_BOOTINIT;
		Message.dat1 = 0;
		Message.dat2 = DownloadLocation;
		rscp_send_bpmsg(&Message);

		/*
		 * Initialize Timeout each time just to be robust. Since this
		 * operation is not time critical, this is not a concern.
		 */
		Timeout.tv_nsec = 0;
		Timeout.tv_sec = ADM_BOOT_INIT_TIMEOUT;

		/* If we timeout, decrement BootRetry and try again */
		if (ADM_Boot_recv(&Message, &Timeout) != 0) {

			/* We got a timeout */
			BootRetry = BootRetry - 1;
			continue;
		} else {

			/* we got a message back, see what it is */
			if ((Message.cmd  != BP_RSC_BOOTACK) ||
			    (Message.dat1 != BP_DAT1_BOOTINIT_ACK)) {

				ADM_Display_download_error(Message.cmd,
				    Message.dat1);
				exit(-1);
			}

			/*
			 * We got a valid acknowledge, break out of loop and
			 * start to download s-record
			 */
			break;
		}
	}

	/* See if we ever got a response */
	if (BootRetry <= 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: SC did not respond during boot "
		    "initialization"));
		exit(-1);
	}

	/* Download s-record */
	if (ADM_Send_file(FilePtr) != 0) {
		(void) fprintf(stderr, "\n%s - \"%s\"\n\n",
		    gettext("scadm: Error downloading file"), Filename);
		exit(-1);
	}

	/* wait a second for BootMonitor to catch up */
	Delay.tv_nsec = 0;
	Delay.tv_sec  = 1;
	(void) nanosleep(&Delay, NULL);

	/* Send Reset boot protocol message to reboot SC */
	Message.cmd  = BP_OBP_RESET;
	Message.dat1 = 0;
	Message.dat2 = 0;
	rscp_send_bpmsg(&Message);

	/* Cleanup */
	rscp_unregister_bpmsg_cb(ADM_Callback);
	(void) smq_destroy(&ADM_bpMsgQueue);
	(void) fclose(FilePtr);

	(void) printf("%s\n\n", gettext("Download completed successfully"));

	(void) printf("%s\n\n", gettext("Please wait for verification"));

	/*
	 * scadm cannot tell if the SC successfully verified the
	 * download or not, but instead attempts to send a
	 * status message (up to 60 times) and assumes proper
	 * operation when sucessfully sent.
	 *
	 * When the boot option is used, the SC may hang after
	 * resetting itself (after it sucessfully downloads and
	 * verifies the boot file).  To work around this, scadm
	 * will (1) do a hard reset and pause for 10 seconds
	 * (2) retry the sending of status messages.
	 */

	retry = 0;
	do {
		if (retry == 1) {
			/* reset the SC before retrying */
			if (rsc_nmi() != 0) {
				(void) fprintf(stderr, "\n%s\n\n",
				    gettext(
				    "scadm: Unable to reset SC hardware"));
				exit(-1);
			}
			/* delay while SC resets */
			Delay.tv_nsec = 0;
			Delay.tv_sec  = ADM_BOOT_LOAD_TIMEOUT;
			(void) nanosleep(&Delay, NULL);
		}

		for (i = 0; i < 60; i++) {
			rscp_msg_t msg;
			msg.type = DP_RSC_STATUS;
			msg.len = 0;
			msg.data = NULL;

			(void) printf("%s", gettext("."));
			(void) fflush(stdout);

			err = rscp_send(&msg);
			if (err == 0)
				break;
		}
		if (err == 0)
			break;
		retry++;
	} while (bootOpt && (retry < 2));
	if (err == 0)
		(void) printf("\n%s\n\n", gettext("Complete"));
	else
		(void) printf("\n%s\n\n", gettext("Error during verification"));
}


static void
usage()
{
	(void) fprintf(stderr, "\n%s\n\n",
	    gettext("USAGE: scadm download [boot] <file>"));
}
