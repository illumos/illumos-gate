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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include "inc.h"
#include "conv.h"

/*
 * Forward declarations
 */
static void setup(int, char **, Cmd_info *);
static void setcom(Cmd_info *, Cmd_func);
static void usage(void);
static void sigexit(int sig);
static int notfound(Cmd_info *);
static void check_swap();

const char *
_ar_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}


void
establish_sighandler(void (*handler)())
{
	static const int signum[] = {SIGHUP, SIGINT, SIGQUIT, 0};
	int i;

	if (handler == SIG_IGN) {
		/* Ignore all the specified signals */
		for (i = 0; signum[i]; i++)
			(void) signal(signum[i], SIG_IGN);

	} else {
		/*
		 * Set any signal that doesn't default to being ignored
		 * to our signal handler.
		 */
		for (i = 0; signum[i]; i++)
			if (signal(signum[i], SIG_IGN) != SIG_IGN)
				(void) signal(signum[i], handler);
	}
}

int
main(int argc, char **argv, char *envp[])
{
	int fd;
	Cmd_info *cmd_info;
	int ret;
	char *new = NULL;

#ifndef	XPG4
	/*
	 * Check for a binary that better fits this architecture.
	 */
	(void) conv_check_native(argv, envp);
#endif

	/*
	 * Establish locale.
	 */
	(void) setlocale(LC_ALL, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));

	/* Allow a graceful exit up until we start to write an archive */
	establish_sighandler(sigexit);

	/*
	 * Initialize cmd_info
	 */
	cmd_info = (Cmd_info *)calloc(1, sizeof (Cmd_info));
	if (cmd_info == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_MALLOC), strerror(err));
		exit(1);
	}

	if (argc < 2)
		usage();

	/*
	 * Option handling.
	 */
	if (argv[1][0] != '-') {
		new = (char *)malloc(strlen(argv[1]) + 2);
		if (new == NULL) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_MALLOC),
			    strerror(err));
			exit(1);
		}
		(void) strcpy(new, MSG_ORIG(MSG_STR_HYPHEN));
		(void) strcat(new, argv[1]);
		argv[1] = new;
	}
	setup(argc, argv, cmd_info);

	/*
	 * Check SWAP
	 */
	if (cmd_info->opt_flgs & z_FLAG)
		check_swap();

	if (cmd_info->comfun == NULL) {
		if ((cmd_info->opt_flgs & (d_FLAG | r_FLAG | q_FLAG |
		    t_FLAG | p_FLAG | m_FLAG | x_FLAG)) == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_01));
			exit(1);
		}
	}

	cmd_info->modified = (cmd_info->opt_flgs & s_FLAG);
	fd = getaf(cmd_info);

	if ((fd == -1) &&
	    (cmd_info->opt_flgs &
	    (d_FLAG | m_FLAG | p_FLAG | t_FLAG | x_FLAG)) ||
	    ((cmd_info->opt_flgs & r_FLAG) &&
	    (cmd_info->opt_flgs & (a_FLAG | b_FLAG)))) {
		(void) fprintf(stderr, MSG_INTL(MSG_NOT_FOUND_AR),
		    cmd_info->arnam);
		exit(1);
	}

	(*cmd_info->comfun)(cmd_info);
	if (cmd_info->modified) {
		writefile(cmd_info);
	} else
		(void) close(fd);

	ret = notfound(cmd_info);

	/*
	 * Check SWAP
	 */
	if (cmd_info->opt_flgs & z_FLAG)
		check_swap();

	free(new);
	free(cmd_info);
	return (ret);

}

/*
 * Option handing function.
 *	Using getopt(), following xcu4 convention.
 */
static void
setup(int argc, char *argv[], Cmd_info *cmd_info)
{
	int Vflag = 0;
	int c;
	int usage_err = 0;

	while ((c = getopt(argc, argv, MSG_ORIG(MSG_STR_OPTIONS))) != -1) {
		switch (c) {
		case 'a': /* position after named archive member file */
			cmd_info->opt_flgs |= a_FLAG;
			cmd_info->ponam = trim(optarg);
			break;
		case 'b': /* position before named archive member file */
		case 'i': /* position before named archive member: same as b */
			cmd_info->opt_flgs |= b_FLAG;
			cmd_info->ponam = trim(optarg);
			break;
		case 'c': /* supress messages */
			cmd_info->opt_flgs |= c_FLAG;
			break;
		case 'd':
			/*
			 * key operation:
			 * delete files from the archive
			 */
			setcom(cmd_info, dcmd);
			cmd_info->opt_flgs |= d_FLAG;
			break;
		case 'l': /* ignored */
			break;
		case 'm':
			/*
			 * key operation:
			 * move files to end of the archive
			 * or as indicated by position flag
			 */
			setcom(cmd_info, mcmd);
			cmd_info->opt_flgs |= m_FLAG;
			break;
		case 'p':
			/*
			 * key operation:
			 * print files in the archive
			 */
			setcom(cmd_info, pcmd);
			cmd_info->opt_flgs |= p_FLAG;
			break;
		case 'q':
			/*
			 * key operation:
			 * quickly append files to end of the archive
			 */
			setcom(cmd_info, qcmd);
			cmd_info->opt_flgs |= q_FLAG;
			break;
		case 'r':
			/*
			 * key operation:
			 * replace or add files to the archive
			 */
			setcom(cmd_info, rcmd);
			cmd_info->opt_flgs |= r_FLAG;
			break;
		case 's': /* force symbol table regeneration */
			cmd_info->opt_flgs |= s_FLAG;
			break;
		case 'S': /* Build SYM64 symbol table */
			cmd_info->opt_flgs |= S_FLAG;
			break;
		case 't':
			/*
			 * key operation:
			 * print table of contents
			 */
			setcom(cmd_info, tcmd);
			cmd_info->opt_flgs |= t_FLAG;
			break;
		case 'u': /* update: change archive dependent on file dates */
			cmd_info->opt_flgs |= u_FLAG;
			break;
		case 'v': /* verbose */
			cmd_info->opt_flgs |= v_FLAG;
			break;
		case 'x':
			/*
			 * key operation:
			 * extract files from the archive
			 */
			setcom(cmd_info, xcmd);
			cmd_info->opt_flgs |= x_FLAG;
			break;
		case 'z':
			cmd_info->opt_flgs |= z_FLAG;
			break;
		case 'V':
			/*
			 * print version information.
			 * adjust command line access accounting
			 */
			if (Vflag == 0) {
				(void) fprintf(stderr,
				    MSG_ORIG(MSG_FMT_VERSION),
				    (const char *)SGU_PKG,
				    (const char *)SGU_REL);
				Vflag++;
			}
			break;
		case 'C':
			cmd_info->opt_flgs |= C_FLAG;
			break;
		case 'M':
			/*
			 * -M was an original undocumented AT&T feature that
			 * would force the use of mmap() instead of read()
			 * for pulling file data into the process before
			 * writing it to the archive. Ignored.
			 */
			break;
		case 'T':
			cmd_info->opt_flgs |= T_FLAG;
			break;
		case ':':
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_02), optopt);
			usage_err++;
			break;
		case '?':
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_03), optopt);
			usage_err++;
			break;
		}
	}

	if (usage_err || argc - optind < 1)
		usage();

	cmd_info->arnam = argv[optind];
	cmd_info->namv = &argv[optind+1];
	cmd_info->namc = argc - optind - 1;
}


/*
 * Set the function to be called to do the key operation.
 * Check that only one key is indicated.
 */
static void
setcom(Cmd_info *cmd_info, Cmd_func *fun)
{
	if (cmd_info->comfun != 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_USAGE_04));
		exit(1);
	}
	cmd_info->comfun = fun;
}

static void
usage(void)
{
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE));
	exit(1);
}

/*ARGSUSED0*/
static void
sigexit(int sig)
{
	exit(100);
}

/* tells the user which of the listed files were not found in the archive */

static int
notfound(Cmd_info *cmd_info)
{
	int i, n;

	n = 0;
	for (i = 0; i < cmd_info->namc; i++)
		if (cmd_info->namv[i]) {
			(void) fprintf(stderr, MSG_INTL(MSG_NOT_FOUND_FILE),
			    cmd_info->namv[i]);
			n++;
		}
	return (n);
}

/*
 * Debugging info
 */
static void
check_swap(void)
{
	(void) system(MSG_ORIG(MSG_CMD_SWAP));
}
