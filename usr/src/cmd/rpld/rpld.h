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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>

#define VERYLONGTIME			(long)9999999

#define COMMENT_CHAR			'#'
#define CR				0x0d
#define LF				0x0a
#define TAB				0x09

#define DEST_CONSOLE			0
#define DEST_SYSLOGD			1
#define DEST_LOGFILE			2

#define RPLD_PATH			"/opt/home/alanka/netboot/rpld/rpld"
#define REMOVETIMEOUT			2

/* Default values to start with */
#define DFT_CONFIGFILE			"/etc/rpld.conf"
#define DFT_DEBUGLEVEL			0
#define DFT_DEBUGDEST			DEST_CONSOLE
#define DFT_MAXCLIENTS			-1
#define DFT_LOGFILE			"/var/spool/rpld.log"
#define DFT_STARTDELAY			20
#define	DFT_DELAYGRAN			(long)2
#define DFT_BACKGROUND			0
#define DFT_FRAMESIZE			1400
#define DFT_IFNAME			(char *)NULL

/* RPL command codes */
#define RPL_FIND_FR			0x0001
#define RPL_FOUND_FR			0x0002
#define RPL_SEND_FILE_REQ_FR		0x0010
#define RPL_FILE_DATA_RES_FR		0x0020
#define RPL_LOAD_ERR_RES_FR		0x0040
#define RPL_PROGRAM_ALERT_FR		0x0030

#ifdef sparc
#define RPL_LISTEN_SAP			0x3F
#else
#define RPL_LISTEN_SAP			0xFC
#endif

/* Commands in the RPL protocol */
#define	CMD_FIND		0x01
#define CMD_FOUND		0x02
#define CMD_SEND_FILE		0x10
#define CMD_FILE_DATA		0x20
#define CMD_PROGRAM_ALERT	0x30
#define CMD_LOAD_ERROR		0x40

/* Various bit flags for FILE.DATA.RESPONSE frames */
#define END_OF_FILE		0x80
#define XFER_ENABLE		0x40
#define LOCATE_ENABLE		0x20
#define ACK_REQUEST		0x10

/* Possible states */
#define	ST_FIND_RCVD		-2
#define ST_FOUND_SENT		-1
#define ST_DATA_XFER		0
#define ST_SEND_FINAL		1
#define ST_FINISH		2

/* Different levels of debug messages */
#define MSG_NONE		0
#define MSG_FATAL		1
#define MSG_ERROR_1		2
#define MSG_ERROR_2		3
#define MSG_WARN_1		4
#define MSG_WARN_2		5
#define MSG_WARN_3		6
#define MSG_INFO_1		7
#define MSG_INFO_2		8
#define MSG_ALWAYS		9

/* data structures to keep track of clients being served  */
struct bootfile_s {
	struct bootfile_s	*next;		/* link to next file */
	char		filename[256];	/* the file to be downloaded */
	long		size;		/* file size, for eof comparison */
	long		loadaddr;	/* address to start loading */
	long		seqnum;		/* start seq num for this file */
};
typedef struct bootfile_s bootfile_t;

struct client_s {
	struct client_s *next;		/* forward link */
	struct client_s *prev;		/* backward link */
	unsigned char	addr[6];	/* physical network hardware addr */
	int		status;		/* status of service */
	bootfile_t	*bootfp;	/* head of boot file list to download */
	bootfile_t	*currfp;	/* current boot file downloading */
	FILE		*fstr;		/* file Stream for current file to */
					/* download */
	long		seekp;		/* fseek for current file */
	long		seqnum;		/* sequence number for next frame */
	long		xferaddr;	/* final transfer addr to execute */
	int		framesz;	/* max frame size to use */
	time_t		timeo;		/* timeout for successful download */
	long		maxdelay;	/* max delay ever encountered */
	long		delay;		/* delay needed between out frames */
	long		resetdflt;	/* reset value when delay expires */
};
typedef struct client_s client_t;

