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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */



#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<sys/param.h>
#include	<sys/types.h>
#include	<fcntl.h>
#include	<sys/stat.h>
#include	<string.h>
#include	<strings.h>
#include	<ctype.h>
#include	<errno.h>
#include	<assert.h>
#include	<sys/scsi/impl/uscsi.h>
#include	<sys/scsi/generic/commands.h>
#include	<sys/scsi/impl/commands.h>
#include	<sys/scsi/generic/sense.h>
#include	<sys/scsi/generic/mode.h>
#include	<sys/scsi/generic/status.h>
#include	<sys/scsi/generic/inquiry.h>
#include	<sys/scsi/adapters/scsi_vhci.h>
#include	<sys/byteorder.h>
#include	"common.h"
#include	"errorcodes.h"

#define	MAX_MODE_SENSE_LEN		0xffff
#define	MAXLEN		1000

#define	RETRY_PATHLIST	1
#define	BYTES_PER_LINE	16
#define	SCMD_UNKNOWN	0xff

#define	SCSI_VHCI	"/devices/scsi_vhci/"
#define	SLASH		"/"
#define	DEV_PREFIX	"/devices/"
#define	DEV_PREFIX_STRLEN	strlen(DEV_PREFIX)
#define	DEVICES_DIR	"/devices"

extern	char	*dtype[]; /* from adm.c */
extern	int	rand_r(unsigned int *);

static int cleanup_dotdot_path(char *path);
static int wait_random_time(void);
static char *scsi_find_command_name(int cmd);
static void scsi_printerr(struct uscsi_cmd *ucmd,
	    struct scsi_extended_sense *rq, int rqlen,
	    char msg_string[], char *err_string);
static void string_dump(char *hdr, uchar_t *src, int nbytes, int format,
	    char msg_string[]);
static int issue_uscsi_cmd(int file, struct uscsi_cmd *command, int flag);


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
		return (-1); /* L_LOCALTIME_ERROR */
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
		return (-1); /* L_SELECT_ERROR */
	}
	return (0);
}

/*
 *		Special string dump for error message
 */
static	void
string_dump(char *hdr, uchar_t *src, int nbytes, int format, char msg_string[])
{
	int i;
	int n;
	char	*p;
	char	s[256];

	assert(format == HEX_ONLY || format == HEX_ASCII);

	(void) strcpy(s, hdr);
	for (p = s; *p; p++) {
		*p = ' ';
	}

	p = hdr;
	while (nbytes > 0) {
		(void) sprintf(&msg_string[strlen(msg_string)], "%s", p);
		p = s;
		n = MIN(nbytes, BYTES_PER_LINE);
		for (i = 0; i < n; i++) {
			(void) sprintf(&msg_string[strlen(msg_string)],
			    "%02x ", src[i] & 0xff);
		}
		if (format == HEX_ASCII) {
			for (i = BYTES_PER_LINE-n; i > 0; i--) {
				(void) sprintf(&msg_string[strlen(msg_string)],
				    "   ");
			}
			(void) sprintf(&msg_string[strlen(msg_string)],
			    "    ");
			for (i = 0; i < n; i++) {
				(void) sprintf(&msg_string[strlen(msg_string)],
				    "%c", isprint(src[i]) ? src[i] : '.');
			}
		}
		(void) sprintf(&msg_string[strlen(msg_string)], "\n");
		nbytes -= n;
		src += n;
	}
}
/*
 * Return a pointer to a string telling us the name of the command.
 */
static char *
scsi_find_command_name(int cmd)
{
	/*
	 * Names of commands.  Must have SCMD_UNKNOWN at end of list.
	 */
	struct scsi_command_name {
		int command;
		char	*name;
	} scsi_command_names[29];

	register struct scsi_command_name *c;

	scsi_command_names[0].command = SCMD_TEST_UNIT_READY;
	scsi_command_names[0].name = MSGSTR(61, "Test Unit Ready");

	scsi_command_names[1].command = SCMD_FORMAT;
	scsi_command_names[1].name = MSGSTR(110, "Format");

	scsi_command_names[2].command = SCMD_REASSIGN_BLOCK;
	scsi_command_names[2].name = MSGSTR(77, "Reassign Block");

	scsi_command_names[3].command = SCMD_READ;
	scsi_command_names[3].name = MSGSTR(27, "Read");

	scsi_command_names[4].command = SCMD_WRITE;
	scsi_command_names[4].name = MSGSTR(54, "Write");

	scsi_command_names[5].command = SCMD_READ_G1;
	scsi_command_names[5].name = MSGSTR(79, "Read(10 Byte)");

	scsi_command_names[6].command = SCMD_WRITE_G1;
	scsi_command_names[6].name = MSGSTR(51, "Write(10 Byte)");

	scsi_command_names[7].command = SCMD_MODE_SELECT;
	scsi_command_names[7].name = MSGSTR(97, "Mode Select");

	scsi_command_names[8].command = SCMD_MODE_SENSE;
	scsi_command_names[8].name = MSGSTR(95, "Mode Sense");

	scsi_command_names[9].command = SCMD_REASSIGN_BLOCK;
	scsi_command_names[9].name = MSGSTR(77, "Reassign Block");

	scsi_command_names[10].command = SCMD_REQUEST_SENSE;
	scsi_command_names[10].name = MSGSTR(74, "Request Sense");

	scsi_command_names[11].command = SCMD_READ_DEFECT_LIST;
	scsi_command_names[11].name = MSGSTR(80, "Read Defect List");

	scsi_command_names[12].command = SCMD_INQUIRY;
	scsi_command_names[12].name = MSGSTR(102, "Inquiry");

	scsi_command_names[13].command = SCMD_WRITE_BUFFER;
	scsi_command_names[13].name = MSGSTR(53, "Write Buffer");

	scsi_command_names[14].command = SCMD_READ_BUFFER;
	scsi_command_names[14].name = MSGSTR(82, "Read Buffer");

	scsi_command_names[15].command = SCMD_START_STOP;
	scsi_command_names[15].name = MSGSTR(67, "Start/Stop");

	scsi_command_names[16].command = SCMD_RESERVE;
	scsi_command_names[16].name = MSGSTR(72, "Reserve");

	scsi_command_names[17].command = SCMD_RELEASE;
	scsi_command_names[17].name = MSGSTR(75, "Release");

	scsi_command_names[18].command = SCMD_MODE_SENSE_G1;
	scsi_command_names[18].name = MSGSTR(94, "Mode Sense(10 Byte)");

	scsi_command_names[19].command = SCMD_MODE_SELECT_G1;
	scsi_command_names[19].name = MSGSTR(96, "Mode Select(10 Byte)");

	scsi_command_names[20].command = SCMD_READ_CAPACITY;
	scsi_command_names[20].name = MSGSTR(81, "Read Capacity");

	scsi_command_names[21].command = SCMD_SYNC_CACHE;
	scsi_command_names[21].name = MSGSTR(64, "Synchronize Cache");

	scsi_command_names[22].command = SCMD_READ_DEFECT_LIST;
	scsi_command_names[22].name = MSGSTR(80, "Read Defect List");

	scsi_command_names[23].command = SCMD_GDIAG;
	scsi_command_names[23].name = MSGSTR(108, "Get Diagnostic");

	scsi_command_names[24].command = SCMD_SDIAG;
	scsi_command_names[24].name = MSGSTR(69, "Set Diagnostic");

	scsi_command_names[25].command = SCMD_PERS_RESERV_IN;
	scsi_command_names[25].name = MSGSTR(10500, "Persistent Reserve In");

	scsi_command_names[26].command = SCMD_PERS_RESERV_OUT;
	scsi_command_names[26].name = MSGSTR(10501, "Persistent Reserve out");

	scsi_command_names[27].command = SCMD_LOG_SENSE;
	scsi_command_names[27].name = MSGSTR(10502, "Log Sense");

	scsi_command_names[28].command = SCMD_UNKNOWN;
	scsi_command_names[28].name = MSGSTR(25, "Unknown");


	for (c = scsi_command_names; c->command != SCMD_UNKNOWN; c++)
		if (c->command == cmd)
			break;
	return (c->name);
}


/*
 *	Function to create error message containing
 *	scsi request sense information
 */

static void
scsi_printerr(struct uscsi_cmd *ucmd, struct scsi_extended_sense *rq,
    int rqlen, char msg_string[], char *err_string)
{
	int		blkno;

	switch (rq->es_key) {
	case KEY_NO_SENSE:
		(void) sprintf(msg_string, MSGSTR(91, "No sense error"));
		break;
	case KEY_RECOVERABLE_ERROR:
		(void) sprintf(msg_string, MSGSTR(76, "Recoverable error"));
		break;
	case KEY_NOT_READY:
		(void) sprintf(msg_string,
		    MSGSTR(10503,
		    "Device Not ready. Error: Random Retry Failed: %s\n."),
		    err_string);
		break;
	case KEY_MEDIUM_ERROR:
		(void) sprintf(msg_string, MSGSTR(99, "Medium error"));
		break;
	case KEY_HARDWARE_ERROR:
		(void) sprintf(msg_string, MSGSTR(106, "Hardware error"));
		break;
	case KEY_ILLEGAL_REQUEST:
		(void) sprintf(msg_string, MSGSTR(103, "Illegal request"));
		break;
	case KEY_UNIT_ATTENTION:
		(void) sprintf(msg_string,
		    MSGSTR(10504,
		    "Unit attention."
		    "Error: Random Retry Failed.\n"));
		break;
	case KEY_WRITE_PROTECT:
		(void) sprintf(msg_string, MSGSTR(52, "Write protect error"));
		break;
	case KEY_BLANK_CHECK:
		(void) sprintf(msg_string, MSGSTR(131, "Blank check error"));
		break;
	case KEY_VENDOR_UNIQUE:
		(void) sprintf(msg_string, MSGSTR(58, "Vendor unique error"));
		break;
	case KEY_COPY_ABORTED:
		(void) sprintf(msg_string, MSGSTR(123, "Copy aborted error"));
		break;
	case KEY_ABORTED_COMMAND:
		(void) sprintf(msg_string,
		    MSGSTR(10505,
		    "Aborted command. Error: Random Retry Failed.\n"));
		break;
	case KEY_EQUAL:
		(void) sprintf(msg_string, MSGSTR(117, "Equal error"));
		break;
	case KEY_VOLUME_OVERFLOW:
		(void) sprintf(msg_string, MSGSTR(57, "Volume overflow"));
		break;
	case KEY_MISCOMPARE:
		(void) sprintf(msg_string, MSGSTR(98, "Miscompare error"));
		break;
	case KEY_RESERVED:
		(void) sprintf(msg_string, MSGSTR(10506,
		    "Reserved value found"));
		break;
	default:
		(void) sprintf(msg_string, MSGSTR(59, "Unknown error"));
		break;
	}

	(void) sprintf(&msg_string[strlen(msg_string)],
	    MSGSTR(10507, " during: %s"),
	    scsi_find_command_name(ucmd->uscsi_cdb[0]));

	if (rq->es_valid) {
		blkno = (rq->es_info_1 << 24) | (rq->es_info_2 << 16) |
		    (rq->es_info_3 << 8) | rq->es_info_4;
		(void) sprintf(&msg_string[strlen(msg_string)],
		    MSGSTR(49, ": block %d (0x%x)"), blkno, blkno);
	}

	(void) sprintf(&msg_string[strlen(msg_string)], "\n");

	if (rq->es_add_len >= 6) {
		(void) sprintf(&msg_string[strlen(msg_string)],
		    MSGSTR(132, "  Additional sense: 0x%x   "
		    "ASC Qualifier: 0x%x\n"),
		    rq->es_add_code, rq->es_qual_code);
		/*
		 * rq->es_add_info[ADD_SENSE_CODE],
		 * rq->es_add_info[ADD_SENSE_QUAL_CODE]);
		 */
	}
	if (rq->es_key == KEY_ILLEGAL_REQUEST) {
		string_dump(MSGSTR(47, " cmd:   "), (uchar_t *)ucmd,
		    sizeof (struct uscsi_cmd), HEX_ONLY, msg_string);
		string_dump(MSGSTR(48, " cdb:   "),
		    (uchar_t *)ucmd->uscsi_cdb,
		    ucmd->uscsi_cdblen, HEX_ONLY, msg_string);
	}
	string_dump(MSGSTR(43, " sense:  "),
	    (uchar_t *)rq, 8 + rq->es_add_len, HEX_ONLY, msg_string);
	rqlen = rqlen;	/* not used */
}


/*
 * Execute a command and determine the result.
 */
static int
issue_uscsi_cmd(int file, struct uscsi_cmd *command, int flag)
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
			    scsi_find_command_name(command->uscsi_cdb[0]));
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
				(void) dump_hex_data("  Buffer data: ",
				    (uchar_t *)command->uscsi_bufaddr,
				    MIN(command->uscsi_buflen, 512), HEX_ASCII);
			}
		}
		(void) fflush(stdout);
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
				(void) dump_hex_data("\tData read:",
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
			scsi_printerr(command,
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

/*
 *		MODE SENSE USCSI command
 *
 *
 *		pc = page control field
 *		page_code = Pages to return
 */
int
scsi_mode_sense_cmd(int fd, uchar_t *buf_ptr, int buf_len, uchar_t pc,
    uchar_t page_code)
{
	struct uscsi_cmd	ucmd;
	/* 10 byte Mode Select cmd */
	union scsi_cdb	cdb =  {SCMD_MODE_SENSE_G1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	struct	scsi_extended_sense	sense;
	int		status;
	static	int	uscsi_count;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (-1); /* L_INVALID_ARG */
	}

	(void) memset(buf_ptr, 0, buf_len);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	/* Just for me  - a sanity check */
	if ((page_code > MODEPAGE_ALLPAGES) || (pc > 3) ||
	    (buf_len > MAX_MODE_SENSE_LEN)) {
		return (-1); /* L_ILLEGAL_MODE_SENSE_PAGE */
	}
	cdb.g1_addr3 = (pc << 6) + page_code;
	cdb.g1_count1 = buf_len>>8;
	cdb.g1_count0 = buf_len & 0xff;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 120;

	status = issue_uscsi_cmd(fd, &ucmd, USCSI_READ);
	/* Bytes actually transfered */
	if (status == 0) {
		uscsi_count = buf_len - ucmd.uscsi_resid;
		S_DPRINTF("  Number of bytes read on "
		"Mode Sense 0x%x\n", uscsi_count);
		if (getenv("_LUX_D_DEBUG") != NULL) {
			(void) dump_hex_data("  Mode Sense data: ", buf_ptr,
			    uscsi_count, HEX_ASCII);
		}
	}
	return (status);
}

int
scsi_release(char *path)
{
	struct uscsi_cmd	ucmd;
	union scsi_cdb		cdb = {SCMD_RELEASE, 0, 0, 0, 0, 0};
	struct	scsi_extended_sense	sense;
	int	fd, status;

	P_DPRINTF("  scsi_release: Release: Path %s\n", path);
	if ((fd = open(path, O_NDELAY | O_RDONLY)) == -1)
		return (1);

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = NULL;
	ucmd.uscsi_buflen = 0;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;
	status = (issue_uscsi_cmd(fd, &ucmd, 0));

	(void) close(fd);
	return (status);
}

int
scsi_reserve(char *path)
{
	struct uscsi_cmd	ucmd;
	union scsi_cdb	cdb = {SCMD_RESERVE, 0, 0, 0, 0, 0};
	struct	scsi_extended_sense	sense;
	int	fd, status;

	P_DPRINTF("  scsi_reserve: Reserve: Path %s\n", path);
	if ((fd = open(path, O_NDELAY | O_RDONLY)) == -1)
		return (1);

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = NULL;
	ucmd.uscsi_buflen = 0;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;
	status = (issue_uscsi_cmd(fd, &ucmd, 0));

	(void) close(fd);
	return (status);
}

/*
 * Print out fabric dev dtype
 */
void
print_fabric_dtype_prop(uchar_t *hba_port_wwn, uchar_t *port_wwn,
    uchar_t dtype_prop)
{
	if ((dtype_prop & DTYPE_MASK) < 0x10) {
		(void) fprintf(stdout, " 0x%-2x (%s)\n",
		    (dtype_prop & DTYPE_MASK),
		    dtype[(dtype_prop & DTYPE_MASK)]);
	} else if ((dtype_prop & DTYPE_MASK) < 0x1f) {
		(void) fprintf(stdout,
		    MSGSTR(2096, " 0x%-2x (Reserved)\n"),
		    (dtype_prop & DTYPE_MASK));
	} else {
		/* Check to see if this is the HBA */
		if (wwnConversion(hba_port_wwn) != wwnConversion(port_wwn)) {
			(void) fprintf(stdout, MSGSTR(2097,
			    " 0x%-2x (Unknown Type)\n"),
			    (dtype_prop & DTYPE_MASK));
		} else {
			/* MATCH */
			(void) fprintf(stdout, MSGSTR(2241,
			    " 0x%-2x (Unknown Type,Host Bus Adapter)\n"),
			    (dtype_prop & DTYPE_MASK));
		}
	}
}


void
print_inq_data(char *arg_path, char *path, L_inquiry inq, uchar_t *serial,
    size_t serial_len)
{
	char	**p;
	uchar_t	*v_parm;
	int	scsi_3, length;
	char	byte_number[MAXNAMELEN];
	static	char *scsi_inquiry_labels_2[21];
	static	char *scsi_inquiry_labels_3[22];
#define	MAX_ANSI_VERSION	6
	static	char	*ansi_version[MAX_ANSI_VERSION];
	/*
	 * Intialize scsi_inquiry_labels_2 with i18n strings
	 */
	scsi_inquiry_labels_2[0] = MSGSTR(138, "Vendor:                     ");
	scsi_inquiry_labels_2[1] = MSGSTR(149, "Product:                    ");
	scsi_inquiry_labels_2[2] = MSGSTR(139, "Revision:                   ");
	scsi_inquiry_labels_2[3] = MSGSTR(143, "Firmware Revision           ");
	scsi_inquiry_labels_2[4] = MSGSTR(144, "Serial Number               ");
	scsi_inquiry_labels_2[5] = MSGSTR(140, "Device type:                ");
	scsi_inquiry_labels_2[6] = MSGSTR(145, "Removable media:            ");
	scsi_inquiry_labels_2[7] = MSGSTR(146, "ISO version:                ");
	scsi_inquiry_labels_2[8] = MSGSTR(147, "ECMA version:               ");
	scsi_inquiry_labels_2[9] = MSGSTR(148, "ANSI version:               ");
	scsi_inquiry_labels_2[10] =
	    MSGSTR(2168, "Async event notification:   ");
	scsi_inquiry_labels_2[11] =
	    MSGSTR(2169, "Terminate i/o process msg:  ");
	scsi_inquiry_labels_2[12] = MSGSTR(150, "Response data format:       ");
	scsi_inquiry_labels_2[13] = MSGSTR(151, "Additional length:          ");
	scsi_inquiry_labels_2[14] = MSGSTR(152, "Relative addressing:        ");
	scsi_inquiry_labels_2[15] =
	    MSGSTR(2170, "32 bit transfers:           ");
	scsi_inquiry_labels_2[16] =
	    MSGSTR(2171, "16 bit transfers:           ");
	scsi_inquiry_labels_2[17] =
	    MSGSTR(2172, "Synchronous transfers:      ");
	scsi_inquiry_labels_2[18] = MSGSTR(153, "Linked commands:            ");
	scsi_inquiry_labels_2[19] = MSGSTR(154, "Command queueing:           ");
	scsi_inquiry_labels_2[20] =
	    MSGSTR(2173, "Soft reset option:          ");

	/*
	 * Intialize scsi_inquiry_labels_3 with i18n strings
	 */
	scsi_inquiry_labels_3[0] = MSGSTR(138, "Vendor:                     ");
	scsi_inquiry_labels_3[1] = MSGSTR(149, "Product:                    ");
	scsi_inquiry_labels_3[2] = MSGSTR(139, "Revision:                   ");
	scsi_inquiry_labels_3[3] = MSGSTR(143, "Firmware Revision           ");
	scsi_inquiry_labels_3[4] = MSGSTR(144, "Serial Number               ");
	scsi_inquiry_labels_3[5] = MSGSTR(140, "Device type:                ");
	scsi_inquiry_labels_3[6] = MSGSTR(145, "Removable media:            ");
	scsi_inquiry_labels_3[7] = MSGSTR(2174, "Medium Changer Element:     ");
	scsi_inquiry_labels_3[8] = MSGSTR(146, "ISO version:                ");
	scsi_inquiry_labels_3[9] = MSGSTR(147, "ECMA version:               ");
	scsi_inquiry_labels_3[10] = MSGSTR(148, "ANSI version:               ");
	scsi_inquiry_labels_3[11] =
	    MSGSTR(2175, "Async event reporting:      ");
	scsi_inquiry_labels_3[12] =
	    MSGSTR(2176, "Terminate task:             ");
	scsi_inquiry_labels_3[13] =
	    MSGSTR(2177, "Normal ACA Supported:       ");
	scsi_inquiry_labels_3[14] = MSGSTR(150, "Response data format:       ");
	scsi_inquiry_labels_3[15] = MSGSTR(151, "Additional length:          ");
	scsi_inquiry_labels_3[16] =
	    MSGSTR(2178, "Cmd received on port:       ");
	scsi_inquiry_labels_3[17] =
	    MSGSTR(2179, "SIP Bits:                   ");
	scsi_inquiry_labels_3[18] = MSGSTR(152, "Relative addressing:        ");
	scsi_inquiry_labels_3[19] = MSGSTR(153, "Linked commands:            ");
	scsi_inquiry_labels_3[20] =
	    MSGSTR(2180, "Transfer Disable:           ");
	scsi_inquiry_labels_3[21] = MSGSTR(154, "Command queueing:           ");

	/*
	 * Intialize scsi_inquiry_labels_3 with i18n strings
	 */
	ansi_version[0] = MSGSTR(2181,
	    " (Device might or might not comply to an ANSI version)");
	ansi_version[1] = MSGSTR(2182,
	    " (This code is reserved for historical uses)");
	ansi_version[2] = MSGSTR(2183,
	    " (Device complies to ANSI X3.131-1994 (SCSI-2))");
	ansi_version[3] = MSGSTR(2184,
	    " (Device complies to ANSI INCITS 301-1997 (SPC))");
	ansi_version[4] = MSGSTR(2226,
	    " (Device complies to ANSI INCITS 351-2001 (SPC-2))");
	ansi_version[5] = MSGSTR(2227,
	    " (Device complies to ANSI INCITS 408-2005 (SPC-3))");

	/* print inquiry information */

	(void) fprintf(stdout, MSGSTR(2185, "\nINQUIRY:\n"));
		/*
		 * arg_path is the path sent to luxadm by the user.  if arg_path
		 * is a /devices path, then we do not need to print out physical
		 * path info
		 */
	if (strcmp(arg_path, path) != 0 &&
	    strstr(arg_path, "/devices/") == NULL) {
		(void) fprintf(stdout, "  ");
		(void) fprintf(stdout,
		    MSGSTR(5, "Physical Path:"));
		(void) fprintf(stdout, "\n  %s\n", path);
	}
	if (inq.inq_ansi < 3) {
		p = scsi_inquiry_labels_2;
		scsi_3 = 0;
	} else {
		p = scsi_inquiry_labels_3;
		scsi_3 = 1;
	}
	if (inq.inq_len < 11) {
		p += 1;
	} else {
		/* */
		(void) fprintf(stdout, "%s", *p++);
		print_chars(inq.inq_vid, sizeof (inq.inq_vid), 0);
		(void) fprintf(stdout, "\n");
	}
	if (inq.inq_len < 27) {
		p += 1;
	} else {
		(void) fprintf(stdout, "%s", *p++);
		print_chars(inq.inq_pid, sizeof (inq.inq_pid), 0);
		(void) fprintf(stdout, "\n");
	}
	if (inq.inq_len < 31) {
		p += 1;
	} else {
		(void) fprintf(stdout, "%s", *p++);
		print_chars(inq.inq_revision, sizeof (inq.inq_revision), 0);
		(void) fprintf(stdout, "\n");
	}
	if (inq.inq_len < 39) {
		p += 2;
	} else {
		/*
		 * If Pluto then print
		 * firmware rev & serial #.
		 */
		if (strstr((char *)inq.inq_pid, "SSA") != 0) {
			(void) fprintf(stdout, "%s", *p++);
			print_chars(inq.inq_firmware_rev,
			    sizeof (inq.inq_firmware_rev), 0);
			(void) fprintf(stdout, "\n");
			(void) fprintf(stdout, "%s", *p++);
			print_chars(serial, serial_len, 0);
			(void) fprintf(stdout, "\n");
		} else if ((inq.inq_dtype & DTYPE_MASK) != DTYPE_ESI) {
			p++;
			(void) fprintf(stdout, "%s", *p++);
			print_chars(serial, serial_len, 0);
			(void) fprintf(stdout, "\n");
		} else {
			/* if we miss both the above if's */
			p += 2;
		}
	}

	(void) fprintf(stdout, "%s0x%x (", *p++, (inq.inq_dtype & DTYPE_MASK));
	if ((inq.inq_dtype & DTYPE_MASK) < 0x10) {
		(void) fprintf(stdout, "%s", dtype[inq.inq_dtype & DTYPE_MASK]);
	} else if ((inq.inq_dtype & DTYPE_MASK) < 0x1f) {
		(void) fprintf(stdout, MSGSTR(71, "Reserved"));
	} else {
		(void) fprintf(stdout, MSGSTR(2186, "Unknown device"));
	}
	(void) fprintf(stdout, ")\n");

	(void) fprintf(stdout, "%s", *p++);
	if (inq.inq_rmb != 0) {
		(void) fprintf(stdout, MSGSTR(40, "yes"));
	} else {
		(void) fprintf(stdout, MSGSTR(45, "no"));
	}
	(void) fprintf(stdout, "\n");

	if (scsi_3) {
		(void) fprintf(stdout, "%s", *p++);
		if (inq.inq_mchngr != 0) {
			(void) fprintf(stdout, MSGSTR(40, "yes"));
		} else {
			(void) fprintf(stdout, MSGSTR(45, "no"));
		}
		(void) fprintf(stdout, "\n");
	}
	(void) fprintf(stdout, "%s%d\n", *p++, inq.inq_iso);
	(void) fprintf(stdout, "%s%d\n", *p++, inq.inq_ecma);

	(void) fprintf(stdout, "%s%d", *p++, inq.inq_ansi);
	if (inq.inq_ansi < MAX_ANSI_VERSION) {
		(void) fprintf(stdout, "%s", ansi_version[inq.inq_ansi]);
	} else
		(void) fprintf(stdout, " (%s)", MSGSTR(71, "Reserved"));

	(void) fprintf(stdout, "\n");

	if (inq.inq_aenc) {
		(void) fprintf(stdout, "%s", *p++);
		(void) fprintf(stdout, MSGSTR(40, "yes"));
		(void) fprintf(stdout, "\n");
	} else {
		p++;
	}
	if (scsi_3) {
		(void) fprintf(stdout, "%s", *p++);
		if (inq.inq_normaca != 0) {
			(void) fprintf(stdout, MSGSTR(40, "yes"));
		} else {
			(void) fprintf(stdout, MSGSTR(45, "no"));
		}
		(void) fprintf(stdout, "\n");
	}
	if (inq.inq_trmiop) {
		(void) fprintf(stdout, "%s", *p++);
		(void) fprintf(stdout, MSGSTR(40, "yes"));
		(void) fprintf(stdout, "\n");
	} else {
		p++;
	}
	(void) fprintf(stdout, "%s%d\n", *p++, inq.inq_rdf);
	(void) fprintf(stdout, "%s0x%x\n", *p++, inq.inq_len);
	if (scsi_3) {
		if (inq.inq_dual_p) {
			if (inq.inq_port != 0) {
				(void) fprintf(stdout, MSGSTR(2187,
				    "%sa\n"), *p++);
			} else {
				(void) fprintf(stdout, MSGSTR(2188,
				    "%sb\n"), *p++);
			}
		} else {
			p++;
		}
	}
	if (scsi_3) {
		if (inq.inq_SIP_1 || inq.ui.inq_3.inq_SIP_2 ||
		    inq.ui.inq_3.inq_SIP_3) {
			(void) fprintf(stdout, "%s%d, %d, %d\n", *p,
			    inq.inq_SIP_1, inq.ui.inq_3.inq_SIP_2,
			    inq.ui.inq_3.inq_SIP_3);
		}
		p++;

	}

	if (inq.ui.inq_2.inq_2_reladdr) {
		(void) fprintf(stdout, "%s", *p);
		(void) fprintf(stdout, MSGSTR(40, "yes"));
		(void) fprintf(stdout, "\n");
	}
	p++;

	if (!scsi_3) {
		if (inq.ui.inq_2.inq_wbus32) {
			(void) fprintf(stdout, "%s", *p);
			(void) fprintf(stdout, MSGSTR(40, "yes"));
			(void) fprintf(stdout, "\n");
		}
		p++;

		if (inq.ui.inq_2.inq_wbus16) {
			(void) fprintf(stdout, "%s", *p);
			(void) fprintf(stdout, MSGSTR(40, "yes"));
			(void) fprintf(stdout, "\n");
		}
		p++;

		if (inq.ui.inq_2.inq_sync) {
			(void) fprintf(stdout, "%s", *p);
			(void) fprintf(stdout, MSGSTR(40, "yes"));
			(void) fprintf(stdout, "\n");
		}
		p++;

	}
	if (inq.ui.inq_2.inq_linked) {
		(void) fprintf(stdout, "%s", *p);
		(void) fprintf(stdout, MSGSTR(40, "yes"));
		(void) fprintf(stdout, "\n");
	}
	p++;

	if (scsi_3) {
		(void) fprintf(stdout, "%s", *p++);
		if (inq.ui.inq_3.inq_trandis != 0) {
			(void) fprintf(stdout, MSGSTR(40, "yes"));
		} else {
			(void) fprintf(stdout, MSGSTR(45, "no"));
		}
		(void) fprintf(stdout, "\n");
	}

	if (inq.ui.inq_2.inq_cmdque) {
		(void) fprintf(stdout, "%s", *p);
		(void) fprintf(stdout, MSGSTR(40, "yes"));
		(void) fprintf(stdout, "\n");
	}
	p++;

	if (!scsi_3) {
		if (inq.ui.inq_2.inq_sftre) {
			(void) fprintf(stdout, "%s", *p);
			(void) fprintf(stdout, MSGSTR(40, "yes"));
			(void) fprintf(stdout, "\n");
		}
		p++;

	}

	/*
	 * Now print the vendor-specific data.
	 */
	v_parm = inq.inq_ven_specific_1;
	if (inq.inq_len >= 32) {
		length = inq.inq_len - 31;
		if (strstr((char *)inq.inq_pid, "SSA") != 0) {
			(void) fprintf(stdout, MSGSTR(2189,
			    "Number of Ports, Targets:   %d,%d\n"),
			    inq.inq_ssa_ports, inq.inq_ssa_tgts);
			v_parm += 20;
			length -= 20;
		} else if ((strstr((char *)inq.inq_pid, "SUN") != 0) ||
		    (strncmp((char *)inq.inq_vid, "SUN     ",
		    sizeof (inq.inq_vid)) == 0)) {
			v_parm += 16;
			length -= 16;
		}
		/*
		 * Do hex Dump of rest of the data.
		 */
		if (length > 0) {
			(void) fprintf(stdout,
			    MSGSTR(2190,
			"              VENDOR-SPECIFIC PARAMETERS\n"));
			(void) fprintf(stdout,
			    MSGSTR(2191,
			    "Byte#                  Hex Value            "
			    "                 ASCII\n"));
			(void) sprintf(byte_number,
			    "%d    ", inq.inq_len - length + 5);
			dump_hex_data(byte_number, v_parm,
			    MIN(length, inq.inq_res3 - v_parm), HEX_ASCII);
		}
		/*
		 * Skip reserved bytes 56-95.
		 */
		length -= (inq.inq_box_name - v_parm);
		if (length > 0) {
			(void) sprintf(byte_number, "%d    ",
			    inq.inq_len - length + 5);
			dump_hex_data(byte_number, inq.inq_box_name,
			    MIN(length, sizeof (inq.inq_box_name) +
			    sizeof (inq.inq_avu)), HEX_ASCII);
		}
	}
	if (getenv("_LUX_D_DEBUG") != NULL) {
		dump_hex_data("\nComplete Inquiry: ",
		    (uchar_t *)&inq,
		    MIN(inq.inq_len + 5, sizeof (inq)), HEX_ASCII);
	}
}

/*
 * Internal routine to clean up ../'s in paths.
 * returns 0 if no "../" are left.
 *
 * Wouldn't it be nice if there was a standard system library
 * routine to do this...?
 */
static int
cleanup_dotdot_path(char *path)
{
	char holder[MAXPATHLEN];
	char *dotdot;
	char *previous_slash;

	/* Find the first "/../" in the string */
	dotdot = strstr(path, "/../");
	if (dotdot == NULL) {
		return (0);
	}


	/*
	 * If the [0] character is '/' and "../" immediatly
	 * follows it, then we can strip the ../
	 *
	 *	/../../foo/bar == /foo/bar
	 *
	 */
	if (dotdot == path) {
		strcpy(holder, &path[3]); /* strip "/.." */
		strcpy(path, holder);
		return (1);
	}

	/*
	 * Now look for the LAST "/" before the "/../"
	 * as this is the parent dir we can get rid of.
	 * We do this by temporarily truncating the string
	 * at the '/' just before "../" using the dotdot pointer.
	 */
	*dotdot = '\0';
	previous_slash = strrchr(path, '/');
	if (previous_slash == NULL) {
		/*
		 * hmm, somethings wrong.  path looks something
		 * like "foo/../bar/" so we can't really deal with it.
		 */
		return (0);
	}
	/*
	 * Now truncate the path just after the previous '/'
	 * and slam everything after the "../" back on
	 */
	*(previous_slash+1) = '\0';
	(void) strcat(path, dotdot+4);
	return (1); /* We may have more "../"s */
}

/*
 * Follow symbolic links from the logical device name to
 * the /devfs physical device name.  To be complete, we
 * handle the case of multiple links.  This function
 * either returns NULL (no links, or some other error),
 * or the physical device name, alloc'ed on the heap.
 *
 * NOTE: If the path is relative, it will be forced into
 * an absolute path by pre-pending the pwd to it.
 */
char *
get_slash_devices_from_osDevName(char *osDevName, int flag)
{
	struct stat	stbuf;
	char		source[MAXPATHLEN];
	char		scratch[MAXPATHLEN];
	char		pwd[MAXPATHLEN];
	char		*tmp, *phys_path;
	int		cnt;
	boolean_t	is_lstat_failed = B_TRUE;

	/* return NULL if path is NULL */
	if (osDevName == NULL) {
		return (NULL);
	}

	strcpy(source, osDevName);
	for (;;) {

		/*
		 * First make sure the path is absolute.  If not, make it.
		 * If it's already an absolute path, we have no need
		 * to determine the cwd, so the program should still
		 * function within security-by-obscurity directories.
		 */
		if (source[0] != '/') {
			tmp = getcwd(pwd, MAXPATHLEN);
			if (tmp == NULL) {
				return (NULL);
			}
			/*
			 * Handle special case of "./foo/bar"
			 */
			if (source[0] == '.' && source[1] == '/') {
				strcpy(scratch, source+2);
			} else { /* no "./" so just take everything */
				strcpy(scratch, source);
			}
			strcpy(source, pwd);
			(void) strcat(source, "/");
			(void) strcat(source, scratch);
		}

		/*
		 * Clean up any "../"s that are in the path
		 */
		while (cleanup_dotdot_path(source))
			;

		/*
		 * source is now an absolute path to the link we're
		 * concerned with
		 */
		if (flag == NOT_IGNORE_DANGLING_LINK) {
			/*
			 * In order not to ingore dangling links, check
			 * the lstat. If lstat succeeds, return the path
			 * from readlink.
			 * Note: osDevName input with /devices path from
			 * a dangling /dev link doesn't pass lstat so
			 * NULL is returned.
			 */
			if (stat(source, &stbuf) == -1) {
				if (!is_lstat_failed &&
				    strstr(source, "/devices")) {
					/*
					 * lstat succeeded previously and source
					 * contains "/devices" then it is
					 * dangling node.
					 */
					phys_path = (char *)calloc(1,
					    strlen(source) + 1);
					if (phys_path != NULL) {
						(void) strncpy(phys_path,
						    source, strlen(source) + 1);
					}
					return (phys_path);
				} else if (is_lstat_failed) {
					/* check lstat result. */
					if (lstat(source, &stbuf) == -1) {
						return (NULL);
					} else {
						/* and continue */
						is_lstat_failed = B_FALSE;
					}
				} else {
					/*
					 * With algorithm that resolves a link
					 * and then issues readlink(), should
					 * not be reached here.
					 */
					return (NULL);
				}
			} else {
				if (lstat(source, &stbuf) == -1) {
					/*
					 * when stat succeeds it is not
					 * a dangling node so it is not
					 * a special case.
					 */
					return (NULL);
				}
			}
		} else if (flag == STANDARD_DEVNAME_HANDLING) {
			/*
			 * See if there's a real file out there.  If not,
			 * we have a dangling link and we ignore it.
			 */
			if (stat(source, &stbuf) == -1) {
				return (NULL);
			}
			if (lstat(source, &stbuf) == -1) {
				return (NULL);
			}
		} else {
			/* invalid flag */
			return (NULL);
		}

		/*
		 * If the file is not a link, we're done one
		 * way or the other.  If there were links,
		 * return the full pathname of the resulting
		 * file.
		 *
		 * Note:  All of our temp's are on the stack,
		 * so we have to copy the final result to the heap.
		 */
		if (!S_ISLNK(stbuf.st_mode)) {
			phys_path = (char *)calloc(1, strlen(source) + 1);
			if (phys_path != NULL) {
				(void) strncpy(phys_path, source,
				    strlen(source) + 1);
			}
			return (phys_path);
		}
		cnt = readlink(source, scratch, sizeof (scratch));
		if (cnt < 0) {
			return (NULL);
		}
		/*
		 * scratch is on the heap, and for some reason readlink
		 * doesn't always terminate things properly so we have
		 * to make certain we're properly terminated
		 */
		scratch[cnt] = '\0';

		/*
		 * Now check to see if the link is relative.  If so,
		 * then we have to append it to the directory
		 * which the source was in. (This is non trivial)
		 */
		if (scratch[0] != '/') {
			tmp = strrchr(source, '/');
			if (tmp == NULL) { /* Whoa!  Something's hosed! */
				O_DPRINTF("Internal error... corrupt path.\n");
				return (NULL);
			}
			/* Now strip off just the directory path */
			*(tmp+1) = '\0'; /* Keeping the last '/' */
			/* and append the new link */
			(void) strcat(source, scratch);
			/*
			 * Note:  At this point, source should have "../"s
			 * but we'll clean it up in the next pass through
			 * the loop.
			 */
		} else {
			/* It's an absolute link so no worries */
			strcpy(source, scratch);
		}
	}
	/* Never reach here */
}

/*
 * Input - Space for client_path, phci_path and paddr fields of ioc structure
 * need to be allocated by the caller of this routine.
 */
int
get_scsi_vhci_pathinfo(char *dev_path, sv_iocdata_t *ioc, int *path_count)
{
	char	*physical_path, *physical_path_s;
	int	retval;
	int	fd;
	int	initial_path_count;
	int	current_path_count;
	int	i;
	char	*delimiter;
	int	malloc_error = 0;
	int	prop_buf_size;
	int	pathlist_retry_count = 0;

	if (strncmp(dev_path, SCSI_VHCI, strlen(SCSI_VHCI)) != 0) {
		if ((physical_path = get_slash_devices_from_osDevName(
		    dev_path, STANDARD_DEVNAME_HANDLING)) == NULL) {
			return (L_INVALID_PATH);
		}
		if (strncmp(physical_path, SCSI_VHCI,
		    strlen(SCSI_VHCI)) != 0) {
			free(physical_path);
			return (L_INVALID_PATH);
		}
	} else {
		if ((physical_path = calloc(1, MAXPATHLEN)) == NULL) {
			return (L_MALLOC_FAILED);
		}
		(void) strcpy(physical_path, dev_path);
	}
	physical_path_s = physical_path;

	/* move beyond "/devices" prefix */
	physical_path += DEV_PREFIX_STRLEN-1;
	/* remove  :c,raw suffix */
	delimiter = strrchr(physical_path, ':');
	/* if we didn't find the ':' fine, else truncate */
	if (delimiter != NULL) {
		*delimiter = '\0';
	}

	/*
	 * We'll call ioctl SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO
	 * at least twice.  The first time will get the path count
	 * and the size of the ioctl propoerty buffer.  The second
	 * time will get the path_info for each path.
	 *
	 * It's possible that additional paths are added while this
	 * code is running.  If the path count increases between the
	 * 2 ioctl's above, then we'll retry (and assume all is well).
	 */
	(void) strcpy(ioc->client, physical_path);
	ioc->buf_elem = 1;
	ioc->ret_elem = (uint_t *)&(initial_path_count);
	ioc->ret_buf = NULL;

	/* free physical path */
	free(physical_path_s);

	/* 0 buf_size asks driver to return actual size needed */
	/* open the ioctl file descriptor */
	if ((fd = open("/devices/scsi_vhci:devctl", O_RDWR)) < 0) {
		return (L_OPEN_PATH_FAIL);
	}

	retval = ioctl(fd, SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO, ioc);
	if (retval != 0) {
		close(fd);
		return (L_SCSI_VHCI_ERROR);
	}
	prop_buf_size = SV_PROP_MAX_BUF_SIZE;


	while (pathlist_retry_count <= RETRY_PATHLIST) {
		ioc->buf_elem = initial_path_count;
		/* Make driver put actual # paths in variable */
		ioc->ret_elem = (uint_t *)&(current_path_count);

		/*
		 * Allocate space for array of path_info structures.
		 * Allocate enough space for # paths from get_pathcount
		 */
		ioc->ret_buf = (sv_path_info_t *)
		    calloc(initial_path_count, sizeof (sv_path_info_t));
		if (ioc->ret_buf == NULL) {
			close(fd);
			return (L_MALLOC_FAILED);
		}

		/*
		 * Allocate space for path properties returned by driver
		 */
		malloc_error = 0;
		for (i = 0; i < initial_path_count; i++) {
			ioc->ret_buf[i].ret_prop.buf_size = prop_buf_size;
			if ((ioc->ret_buf[i].ret_prop.buf =
			    (caddr_t)malloc(prop_buf_size)) == NULL) {
				malloc_error = 1;
				break;
			}
			if ((ioc->ret_buf[i].ret_prop.ret_buf_size =
			    (uint_t *)malloc(sizeof (uint_t))) == NULL) {
				malloc_error = 1;
				break;
			}
		}
		if (malloc_error == 1) {
			for (i = 0; i < initial_path_count; i++) {
				free(ioc->ret_buf[i].ret_prop.buf);
				free(ioc->ret_buf[i].ret_prop.ret_buf_size);
			}
			free(ioc->ret_buf);
			close(fd);
			return (L_MALLOC_FAILED);
		}

		retval = ioctl(fd, SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO, ioc);
		if (retval != 0) {
			for (i = 0; i < initial_path_count; i++) {
				free(ioc->ret_buf[i].ret_prop.buf);
				free(ioc->ret_buf[i].ret_prop.ret_buf_size);
			}
			free(ioc->ret_buf);
			close(fd);
			return (L_SCSI_VHCI_ERROR);
		}
		if (initial_path_count < current_path_count) {
			/* then a new path was added */
			pathlist_retry_count++;
			initial_path_count = current_path_count;
		} else {
			break;
		}
	}
	/* we are done with ioctl's, lose the fd */
	close(fd);

	/*
	 * Compare the length num elements from the ioctl response
	 *   and the caller's request - use smaller value.
	 *
	 * pathlist_p->path_count now has count returned from ioctl.
	 * ioc.buf_elem has the value the caller provided.
	 */
	if (initial_path_count < current_path_count) {
		/* More paths exist than we allocated space for */
		*path_count = initial_path_count;
	} else {
		*path_count = current_path_count;
	}

	return (0);
}

int
get_mode_page(char *path, uchar_t **pg_buf)
{
	struct mode_header_g1	*mode_header_ptr;
	int		status, size, fd;

	/* open controller */
	if ((fd = open(path, O_NDELAY | O_RDWR)) == -1)
		return (-1); /* L_OPEN_PATH_FAIL */

	/*
	 * Read the first part of the page to get the page size
	 */
	size = 20;
	if ((*pg_buf = (uchar_t *)calloc(1, size)) == NULL) {
		(void) close(fd);
		return (L_MALLOC_FAILED);
	}
	/* read page */
	if (status = scsi_mode_sense_cmd(fd, *pg_buf, size,
	    0, MODEPAGE_ALLPAGES)) {
		(void) close(fd);
		(void) free(*pg_buf);
		return (status);
	}
	/* Now get the size for all pages */
	mode_header_ptr = (struct mode_header_g1 *)(void *)*pg_buf;
	size = ntohs(mode_header_ptr->length) +
	    sizeof (mode_header_ptr->length);
	(void) free(*pg_buf);
	if ((*pg_buf = (uchar_t *)calloc(1, size)) == NULL) {
		(void) close(fd);
		return (L_MALLOC_FAILED);
	}
	/* read all pages */
	if (status = scsi_mode_sense_cmd(fd, *pg_buf, size,
	    0, MODEPAGE_ALLPAGES)) {
		(void) close(fd);
		(void) free(*pg_buf);
		return (status);
	}
	(void) close(fd);
	return (0);
}

/*
 * Dump a structure in hexadecimal.
 */
void
dump_hex_data(char *hdr, uchar_t *src, int nbytes, int format)
{
	int i;
	int n;
	char	*p;
	char	s[256];

	assert(format == HEX_ONLY || format == HEX_ASCII);

	(void) strcpy(s, hdr);
	for (p = s; *p; p++) {
		*p = ' ';
	}

	p = hdr;
	while (nbytes > 0) {
		(void) fprintf(stdout, "%s", p);
		p = s;
		n = MIN(nbytes, BYTES_PER_LINE);
		for (i = 0; i < n; i++) {
			(void) fprintf(stdout, "%02x ", src[i] & 0xff);
		}
		if (format == HEX_ASCII) {
			for (i = BYTES_PER_LINE-n; i > 0; i--) {
				(void) fprintf(stdout, "   ");
			}
			(void) fprintf(stdout, "    ");
			for (i = 0; i < n; i++) {
				(void) fprintf(stdout, "%c",
				    isprint(src[i]) ? src[i] : '.');
			}
		}
		(void) fprintf(stdout, "\n");
		nbytes -= n;
		src += n;
	}
}
