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
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Embedded Fcode Interpreter
 *
 * Process cmd line args and invoke Fcode engine.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stropts.h>
#include <ctype.h>

#include <fcode/engine.h>
#include <fcode/log.h>
#include <fcode/debug.h>

#include <fcdriver/fcdriver.h>

#define	MSG_ERRLOG_DEFAULT	(MSG_FATAL|MSG_ERROR|MSG_WARN|MSG_INFO|\
				    MSG_DEBUG|MSG_FC_DEBUG)
#define	MSG_SYSLOG_DEFAULT	(MSG_FATAL|MSG_ERROR|MSG_WARN)
#define	DEBUG_FC_LIST		(DEBUG_COMMA|DEBUG_EXEC_TRACE|\
				    DEBUG_EXEC_DUMP_RS|DEBUG_EXEC_DUMP_RS|\
				    DEBUG_EXEC_SHOW_VITALS|DEBUG_TRACING|\
				    DEBUG_BYTELOAD_DS|DEBUG_BYTELOAD_RS|\
				    DEBUG_BYTELOAD_TOKENS|DEBUG_SHOW_RS|\
				    DEBUG_SHOW_STACK)

common_data_t common;

void *fc_env;

void
usage(char *argv[])
{
	log_message(MSG_ERROR, "Usage: %s <flags>\n", argv[0]);
	log_message(MSG_ERROR,
	    "    -D                        fcode_debug = true\n");
	log_message(MSG_ERROR,
	    "    -d <level>                set debug level\n");
	log_message(MSG_ERROR,
	    "    -f <file>                 interpret fcode/source <file>\n");
	log_message(MSG_ERROR,
	    "    -i                        go 'interactive'\n");
	log_message(MSG_ERROR,
	    "    -s <string>               interpret <string> as forth\n");
	log_message(MSG_ERROR,
	    "    -a                        FCODE image has a.out header\n");
	log_message(MSG_ERROR,
	    "    -e [<msglvl>:]<errorlog>  Set error log file\n");
	log_message(MSG_ERROR,
	    "    -l <msglvl>               Set syslog message level\n");
	log_message(MSG_ERROR,
	    "    -k                        Toggle OBP page kludge\n");
}

fcode_env_t *env;

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind, opterr, optopt;
	int c, aout = 0;
	char *fcode_file = NULL;
	char *forthstr = NULL;
	int debug = 0;
	int syslog_flags = MSG_SYSLOG_DEFAULT;
	int lflag = 0;
	int error_log_flags;
	char *errlog = NULL;
	extern void run_one_efdaemon_request(fcode_env_t *);

	common.Progname = argv[0];
	common.search_path = getenv("FC_SEARCH_PATH");
	common.fcode_fd = -1;
	env = fc_env  = clone_environment(NULL, &common);

	while ((c = getopt(argc, argv, "ad:e:f:l:iDs:k")) != EOF) {
		switch (c) {
		case 'a':
			aout = 1;
			break;

		case 'd':
			debug = debug_flags_to_mask(optarg);
			set_interpreter_debug_level(debug);
			if (debug)
				env->fcode_debug = 1;
			break;

		case 'e':
			if ((errlog = strchr(optarg, ':')) != NULL) {
				*errlog++ = '\0';
				error_log_flags = parse_msg_flags(optarg);
			} else {
				errlog = optarg;
				error_log_flags = MSG_ERRLOG_DEFAULT;
			}
			open_error_log(errlog, error_log_flags);
			break;

		case 'l':
			syslog_flags = parse_msg_flags(optarg);
			lflag++;
			break;

		case 'D':
			env->fcode_debug = 1;
			break;

		case 'f':
			fcode_file = optarg;
			break;

		case 'i':
			forthstr = "interact";
			env->fcode_debug = 1;
			break;

		case 's':
			forthstr = optarg;
			break;

		case '?':
			usage(argv);
			exit(1);
		}
	}

	if (forthstr) {
		run_fcode(env, (uchar_t *)forthstr, strlen(forthstr));
	} else if (fcode_file) {
		run_fcode_from_file(env, fcode_file, aout);
	} else {
		if ((debug & DEBUG_FC_LIST) != 0 &&
		    ((error_log_flags | syslog_flags) & MSG_FC_DEBUG) == 0) {
			log_message(MSG_WARN, "Warning, verbose debug flag(s)"
			    " on, but syslog/errlog not enabled for verbose"
			    " debug\n");
			if (errlog)
				error_log_flags |= MSG_FC_DEBUG;
			else
				syslog_flags |= MSG_FC_DEBUG;
		}
		if ((debug & ~DEBUG_FC_LIST) != 0 &&
		    ((error_log_flags | syslog_flags) & MSG_DEBUG) == 0) {
			log_message(MSG_WARN, "Warning, debug flag(s) on, but"
			    " syslog/errlog not enabled for debug\n");
			if (errlog)
				error_log_flags |= MSG_DEBUG;
			else
				syslog_flags |= MSG_DEBUG;
		}

		if (errlog == NULL || lflag) {
			if (syslog_flags & MSG_FC_DEBUG)
				log_message(MSG_WARN, "Warning, verbose debug"
				    " not recommended for syslog\n");
			open_syslog_log("interpreter", syslog_flags);
		}
		run_one_efdaemon_request(env);
	}

	return (0);
}
