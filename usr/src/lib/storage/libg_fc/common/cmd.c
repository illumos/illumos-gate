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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*LINTLIBRARY*/

/*
 *  This module is part of the photon Command Line
 *  Interface program.
 *
 */

/*
 * I18N message number ranges
 *  This file: 9500 - 9999
 *  Shared common messages: 1 - 1999
 */

/*	Includes	*/
#include	<stdlib.h>
#include	<stdio.h>
#include	<sys/types.h>
#include	<unistd.h>
#include	<errno.h>
#include	<string.h>
#include	<sys/scsi/scsi.h>
#include	<nl_types.h>
#include	<sys/time.h>
#include	<l_common.h>
#include	<stgcom.h>
#include	<l_error.h>
#include	<g_state.h>


/*	Defines		*/
#define	MAXLEN		1000


/*	Global variables	*/
extern	nl_catd l_catd;


/*	External functions	*/
extern	int	rand_r(unsigned int *);


static int
wait_random_time(void)
{
time_t		timeval;
struct tm	*tmbuf = NULL;
struct timeval	tval;
unsigned int	seed;
int		random;
pid_t		pid;


	/*
	 * Get the system time and use "system seconds"
	 * as 'seed' to generate a random number. Then,
	 * wait between 1/10 - 1/2 seconds before retry.
	 * Get the current process id and ex-or it with
	 * the seed so that the random number is always
	 * different even in case of multiple processes
	 * generate a random number at the same time.
	 */
	if ((timeval = time(NULL)) == -1) {
		return (errno);
	}
	if ((tmbuf = localtime(&timeval)) == NULL) {
		return (L_LOCALTIME_ERROR);
	}

	pid = getpid();

	/* get a random number. */
	seed = (unsigned int) tmbuf->tm_sec;
	seed ^= pid;
	random = rand_r(&seed);


	random = ((random % 500) + 100) * MILLISEC;
	tval.tv_sec = random / MICROSEC;
	tval.tv_usec = random % MICROSEC;

	if (select(0, NULL, NULL, NULL, &tval) == -1) {
		return (L_SELECT_ERROR);
	}
	return (0);
}



/*
 * Execute a command and determine the result.
 */
int
cmd(int file, struct uscsi_cmd *command, int flag)
{
struct scsi_extended_sense	*rqbuf;
int				status, i, retry_cnt = 0, err;
char				errorMsg[MAXLEN];

	/*
	 * Set function flags for driver.
	 *
	 * Set Automatic request sense enable
	 *
	 */
	command->uscsi_flags = USCSI_RQENABLE;
	command->uscsi_flags |= flag;

	/* intialize error message array */
	errorMsg[0] = '\0';

	/* print command for debug */
	if (getenv("_LUX_S_DEBUG") != NULL) {
		if ((command->uscsi_cdb == NULL) ||
			(flag & USCSI_RESET) ||
			(flag & USCSI_RESET_ALL)) {
			if (flag & USCSI_RESET) {
				(void) printf("  Issuing a SCSI Reset.\n");
			}
			if (flag & USCSI_RESET_ALL) {
				(void) printf("  Issuing a SCSI Reset All.\n");
			}

		} else {
			(void) printf("  Issuing the following "
				"SCSI command: %s\n",
			g_scsi_find_command_name(command->uscsi_cdb[0]));
			(void) printf("	fd=0x%x cdb=", file);
			for (i = 0; i < (int)command->uscsi_cdblen; i++) {
				(void) printf("%x ", *(command->uscsi_cdb + i));
			}
			(void) printf("\n\tlen=0x%x bufaddr=0x%x buflen=0x%x"
				" flags=0x%x\n",
			command->uscsi_cdblen,
			command->uscsi_bufaddr,
			command->uscsi_buflen, command->uscsi_flags);

			if ((command->uscsi_buflen > 0) &&
				((flag & USCSI_READ) == 0)) {
				(void) g_dump("  Buffer data: ",
				(uchar_t *)command->uscsi_bufaddr,
				MIN(command->uscsi_buflen, 512), HEX_ASCII);
			}
		}
		fflush(stdout);
	}


	/*
	 * Default command timeout in case command left it 0
	 */
	if (command->uscsi_timeout == 0) {
		command->uscsi_timeout = 60;
	}
	/*	Issue command - finally */

retry:
	status = ioctl(file, USCSICMD, command);
	if (status == 0 && command->uscsi_status == 0) {
		if (getenv("_LUX_S_DEBUG") != NULL) {
			if ((command->uscsi_buflen > 0) &&
				(flag & USCSI_READ)) {
				(void) g_dump("\tData read:",
				(uchar_t *)command->uscsi_bufaddr,
				MIN(command->uscsi_buflen, 512), HEX_ASCII);
			}
		}
		return (status);
	}
	if ((status != 0) && (command->uscsi_status == 0)) {
		if ((getenv("_LUX_S_DEBUG") != NULL) ||
			(getenv("_LUX_ER_DEBUG") != NULL)) {
			(void) printf("Unexpected USCSICMD ioctl error: %s\n",
				strerror(errno));
		}
		return (status);
	}

	/*
	 * Just a SCSI error, create error message
	 * Retry once for Unit Attention,
	 * Not Ready, and Aborted Command
	 */
	if ((command->uscsi_rqbuf != NULL) &&
	    (((char)command->uscsi_rqlen - (char)command->uscsi_rqresid) > 0)) {

		rqbuf = (struct scsi_extended_sense *)command->uscsi_rqbuf;

		switch (rqbuf->es_key) {
		case KEY_NOT_READY:
			if (retry_cnt++ < 1) {
				ER_DPRINTF("Note: Device Not Ready."
						" Retrying...\n");

				if ((err = wait_random_time()) == 0) {
					goto retry;
				} else {
					return (err);
				}
			}
			break;

		case KEY_UNIT_ATTENTION:
			if (retry_cnt++ < 1) {
				ER_DPRINTF("  cmd():"
				" UNIT_ATTENTION: Retrying...\n");

				goto retry;
			}
			break;

		case KEY_ABORTED_COMMAND:
			if (retry_cnt++ < 1) {
				ER_DPRINTF("Note: Command is aborted."
				" Retrying...\n");

				goto retry;
			}
			break;
		}
		if ((getenv("_LUX_S_DEBUG") != NULL) ||
			(getenv("_LUX_ER_DEBUG") != NULL)) {
			g_scsi_printerr(command,
			(struct scsi_extended_sense *)command->uscsi_rqbuf,
			(command->uscsi_rqlen - command->uscsi_rqresid),
				errorMsg, strerror(errno));
		}

	} else {

		/*
		 * Retry 5 times in case of BUSY, and only
		 * once for Reservation-conflict, Command
		 * Termination and Queue Full. Wait for
		 * random amount of time (between 1/10 - 1/2 secs.)
		 * between each retry. This random wait is to avoid
		 * the multiple threads being executed at the same time
		 * and also the constraint in Photon IB, where the
		 * command queue has a depth of one command.
		 */
		switch ((uchar_t)command->uscsi_status & STATUS_MASK) {
		case STATUS_BUSY:
			if (retry_cnt++ < 5) {
				if ((err = wait_random_time()) == 0) {
					R_DPRINTF("  cmd(): No. of retries %d."
					" STATUS_BUSY: Retrying...\n",
					retry_cnt);
					goto retry;

				} else {
					return (err);
				}
			}
			break;

		case STATUS_RESERVATION_CONFLICT:
			if (retry_cnt++ < 1) {
				if ((err = wait_random_time()) == 0) {
					R_DPRINTF("  cmd():"
					" RESERVATION_CONFLICT:"
					" Retrying...\n");
					goto retry;

				} else {
					return (err);
				}
			}
			break;

		case STATUS_TERMINATED:
			if (retry_cnt++ < 1) {
				R_DPRINTF("Note: Command Terminated."
					" Retrying...\n");

				if ((err = wait_random_time()) == 0) {
					goto retry;
				} else {
					return (err);
				}
			}
			break;

		case STATUS_QFULL:
			if (retry_cnt++ < 1) {
				R_DPRINTF("Note: Command Queue is full."
				" Retrying...\n");

				if ((err = wait_random_time()) == 0) {
					goto retry;
				} else {
					return (err);
				}
			}
			break;
		}

	}
	if (((getenv("_LUX_S_DEBUG") != NULL) ||
		(getenv("_LUX_ER_DEBUG") != NULL)) &&
		(errorMsg[0] != '\0')) {
		(void) fprintf(stdout, "  %s\n", errorMsg);
	}
	return (L_SCSI_ERROR | command->uscsi_status);
}
