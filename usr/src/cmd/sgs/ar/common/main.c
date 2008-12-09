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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "inc.h"
#include "extern.h"

static char *arnam;

/*
 * Function prototypes
 */
static void setup(int, char **, Cmd_info *);
static void setcom(Cmd_info *, int (*)());
static void usage(void);
static void sigexit(int sig);
static int notfound(Cmd_info *);
static void check_swap();

#define	OPTSTR	":a:b:i:vucsrdxtplmqVCTzM"

int
main(int argc, char **argv)
{
	int i;
	int fd;
	Cmd_info *cmd_info;
	int ret;
	char *new = NULL;
	char *data = NULL;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	for (i = 0; signum[i]; i++)
		if (signal(signum[i], SIG_IGN) != SIG_IGN)
			(void) signal(signum[i], sigexit);
	/*
	 * Initialize cmd_info
	 */
	cmd_info = (Cmd_info *)calloc(1, sizeof (Cmd_info));
	if (cmd_info == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, (char *)0);
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
			error_message(MALLOC_ERROR, PLAIN_ERROR, (char *)0);
			exit(1);
		}
		(void) strcpy(new, "-");
		(void) strcat(new, argv[1]);
		argv[1] = new;
	}
	setup(argc, argv, cmd_info);

	/*
	 * Check SWAP
	 */
	if (opt_FLAG((cmd_info), z_FLAG))
		check_swap();

	if (cmd_info->comfun == 0) {
		if (!(opt_FLAG((cmd_info), d_FLAG) ||
		    opt_FLAG(cmd_info, r_FLAG) ||
		    opt_FLAG(cmd_info, q_FLAG) || opt_FLAG(cmd_info, t_FLAG) ||
		    opt_FLAG(cmd_info, p_FLAG) || opt_FLAG(cmd_info, m_FLAG) ||
		    opt_FLAG(cmd_info, x_FLAG))) {
			error_message(USAGE_01_ERROR, PLAIN_ERROR, (char *)0);
			exit(1);
		}
	}

	cmd_info->modified = opt_FLAG(cmd_info, s_FLAG);
	fd = getaf(cmd_info);

	if ((fd == -1) &&
	    (opt_FLAG(cmd_info, d_FLAG) || opt_FLAG(cmd_info, t_FLAG) ||
	    opt_FLAG(cmd_info, p_FLAG) || opt_FLAG(cmd_info, m_FLAG) ||
	    opt_FLAG(cmd_info, x_FLAG) ||
	    (opt_FLAG(cmd_info, r_FLAG) && (opt_FLAG(cmd_info, a_FLAG) ||
	    opt_FLAG(cmd_info, b_FLAG))))) {
		error_message(NOT_FOUND_01_ERROR,
		    PLAIN_ERROR, (char *)0, arnam);
		exit(1);
	}

	(*cmd_info->comfun)(cmd_info);
	if (cmd_info->modified) {
		data = writefile(cmd_info);
	} else
		(void) close(fd);

	ret = notfound(cmd_info);

	/*
	 * Check SWAP
	 */
	if (opt_FLAG((cmd_info), z_FLAG))
		check_swap();

	free(data);
	free(new);
	free(cmd_info);
	return (ret);

}

/*
 * Option hadning function.
 *	Using getopt(), following xcu4 convention.
 */
static void
setup(int argc, char *argv[], Cmd_info *cmd_info)
{
	int Vflag = 0;
	int c;
	int usage_err = 0;

	while ((c = getopt(argc, argv, OPTSTR)) != -1) {
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
		case 'l': /* temporary directory */
			cmd_info->opt_flgs |= l_FLAG;
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
				(void) fprintf(stderr, "ar: %s %s\n",
				    (const char *)SGU_PKG,
				    (const char *)SGU_REL);
					Vflag++;
			}
			break;
		case 'C':
			cmd_info->OPT_flgs |= C_FLAG;
			break;
		case 'M':
			cmd_info->OPT_flgs |= M_FLAG;
			break;
		case 'T':
			cmd_info->OPT_flgs |= T_FLAG;
			break;
		case ':':
			error_message(USAGE_02_ERROR,
			    PLAIN_ERROR, (char *)0, optopt);
			usage_err++;
			break;
		case '?':
			error_message(USAGE_03_ERROR,
			    PLAIN_ERROR, (char *)0, optopt);
			usage_err++;
			break;
		}
	}

	if (usage_err || argc - optind < 1)
		usage();

	cmd_info->arnam = arnam = argv[optind];
	cmd_info->namv = &argv[optind+1];
	cmd_info->namc = argc - optind - 1;
}


/*
 * Set the function to be called to do the key operation.
 * Check that only one key is indicated.
 */
static void
setcom(Cmd_info *cmd_info, int (*fun)())
{
	if (cmd_info->comfun != 0) {
		error_message(USAGE_04_ERROR, PLAIN_ERROR, (char *)0);
		exit(1);
	}
	cmd_info->comfun = fun;
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
"usage: ar -d[-vV] archive file ...\n"
"       ar -m[-abivV] [posname] archive file ...\n"
"       ar -p[-vV][-s] archive [file ...]\n"
"       ar -q[-cuvV] [-abi] [posname] [file ...]\n"
"       ar -r[-cuvV] [-abi] [posname] [file ...]\n"
"       ar -t[-vV][-s] archive [file ...]\n"
"       ar -x[-vV][-sCT] archive [file ...]\n"));
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
			error_message(NOT_FOUND_03_ERROR,
			    PLAIN_ERROR, (char *)0, cmd_info->namv[i]);
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
	(void) system("/usr/sbin/swap -s");
}
