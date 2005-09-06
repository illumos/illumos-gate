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

#include <stropts.h>
#include <syslog.h>
#include "rpld.h"

extern char    configFile[];
extern int	debugLevel;
extern int	debugDest;
extern int	maxClients;
extern int	backGround;
extern char	logFile[];
extern unsigned long    delayGran;
extern unsigned long	startDelay;
extern int	frameSize;
extern char	ifName[];
extern int	ifUnit;
extern char	debugmsg[];
extern FILE    *log_str;


/*
 * This is the routine to send the debug messages to the specified
 * location.
 */
void
senddebug(int pri)
{
	int	logpri;

	switch (debugDest) {
	case DEST_CONSOLE:
		printf("%s", debugmsg);
		break;
	case DEST_SYSLOGD:
		switch (pri) {
		case MSG_FATAL:
			logpri = LOG_ERR;
			break;
		case MSG_ERROR_1:
		case MSG_ERROR_2:
			logpri = LOG_WARNING;
			break;
		case MSG_WARN_1:
		case MSG_WARN_2:
		case MSG_WARN_3:
			logpri = LOG_NOTICE;
			break;
		case MSG_INFO_1:
		case MSG_INFO_2:
			logpri = LOG_INFO;
			break;
		case MSG_ALWAYS:
			logpri = LOG_DEBUG;
			break;
		}
		logpri |= (LOG_DAEMON | LOG_PID | LOG_CONS);
		syslog(logpri, "%s", debugmsg);
		break;
	case DEST_LOGFILE:
		if (log_str == NULL) {
			log_str = fopen(logFile, "a+");
			if (log_str == NULL) {
				printf("Cannot open log file %s\n", logFile);
				printf("Server aborted\n");
				exit(0);
			}
			setbuf(log_str, (char *)NULL);
		}
		fprintf(log_str, "%s", debugmsg);
		break;
	}
}

void
dumpctl(struct strbuf *ctl)
{
	int	i, j, k, n;

	if (debugLevel >= MSG_ALWAYS) {
		sprintf(debugmsg, "\nControl part of RPL packet = %d bytes:\n",
				ctl->len);
		senddebug(MSG_ALWAYS);
	}
	k = ctl->len / 10;
	for (i = 0; i <= k; i++) {
		if (debugLevel >= MSG_ALWAYS) {
			sprintf(debugmsg, "%4d\t", i*10);
			senddebug(MSG_ALWAYS);
		}
		n = (i+1)*10;
		if (n > ctl->len)
			n = ctl->len;
		for (j = i*10; j < n; j++) {
			if (debugLevel >= MSG_ALWAYS) {
				sprintf(debugmsg, "%02X ",
					(char)(ctl->buf[j] & 0x000000FF));
				senddebug(MSG_ALWAYS);
			}
		}
		if (debugLevel >= MSG_ALWAYS) {
			sprintf(debugmsg, "\n");
			senddebug(MSG_ALWAYS);
		}
	}
}

void
dumpdata(struct strbuf *data)
{
	int	i, j, k, n;

	if (debugLevel >= MSG_ALWAYS) {
		sprintf(debugmsg, "\nData part of RPL packet = %d bytes:\n",
					data->len);
		senddebug(MSG_ALWAYS);
	}
	k = data->len / 10;
	for (i = 0; i <= k; i++) {
		if (debugLevel >= MSG_ALWAYS) {
			sprintf(debugmsg, "%4d\t", i*10);
			senddebug(MSG_ALWAYS);
		}
		n = (i+1)*10;
		if (n > data->len)
			n = data->len;
		for (j = i*10; j < n; j++) {
			if (debugLevel >= MSG_ALWAYS) {
				sprintf(debugmsg, "%02X ",
					(char)(data->buf[j] & 0x000000FF));
				senddebug(MSG_ALWAYS);
			}
		}
		if (debugLevel >= MSG_ALWAYS) {
			sprintf(debugmsg, "\n");
			senddebug(MSG_ALWAYS);
		}
	}
}

void
dumpparams(void)
{
	char	dbDest[20];

	sprintf(debugmsg, "ConfigFile = %s\n", configFile);
	senddebug(MSG_ALWAYS);
	sprintf(debugmsg, "DebugLevel = %d\n", debugLevel);
	senddebug(MSG_ALWAYS);
	switch (debugDest) {
	case DEST_CONSOLE:
		(void) strlcpy(dbDest, "console", sizeof (dbDest));
		break;
	case DEST_SYSLOGD:
		(void) strlcpy(dbDest, "syslogd", sizeof (dbDest));
		break;
	case DEST_LOGFILE:
		(void) strlcpy(dbDest, "logfile", sizeof (dbDest));
		break;
	}
	sprintf(debugmsg, "DebugDest  = %s\n", dbDest);
	senddebug(MSG_ALWAYS);
	sprintf(debugmsg, "MaxClients = %d", maxClients);
	if (maxClients == -1)
		strcat(debugmsg, " (unlimited)\n");
	else
		strcat(debugmsg, "\n");
	senddebug(MSG_ALWAYS);

	if (backGround) {
		(void) strlcpy(dbDest, "TRUE", sizeof (dbDest));
	} else {
		(void) strlcpy(dbDest, "FALSE", sizeof (dbDest));
	}
	sprintf(debugmsg, "BackGround = %s\n", dbDest);
	senddebug(MSG_ALWAYS);
	sprintf(debugmsg, "LogFile    = %s\n", logFile);
	senddebug(MSG_ALWAYS);
	sprintf(debugmsg, "StartDelay = %ld\n", startDelay);
	senddebug(MSG_ALWAYS);
	sprintf(debugmsg, "DelayGran  = %ld\n", delayGran);
	senddebug(MSG_ALWAYS);
	sprintf(debugmsg, "FrameSize  = %d\n", frameSize);
	senddebug(MSG_ALWAYS);
	sprintf(debugmsg, "Interface  = %s%d\n", ifName, ifUnit);
	senddebug(MSG_ALWAYS);
}
