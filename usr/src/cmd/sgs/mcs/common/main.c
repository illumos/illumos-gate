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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 *
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "stdlib.h"
#include "conv.h"
#include "mcs.h"
#include "extern.h"
#define	OPTUNIT	100

static size_t optcnt = 0;
static size_t optbufsz = OPTUNIT;

/*
 * Function prototypes.
 */
static void usage(int);
static void sigexit(int);
static int setup_sectname(char *, int);
static void queue(int, char *);

int
main(int argc, char ** argv, char ** envp)
{
	const char	*opt;
	char		*str;
	int		error_count = 0, num_sect = 0, errflag = 0;
	int		c, i, my_prog;
	Cmd_Info	*cmd_info;

	/*
	 * Check for a binary that better fits this architecture.
	 */
	(void) conv_check_native(argv, envp);

	/*
	 * mcs(1) and strip() are hard linked together, determine which command
	 * was invoked.
	 */
	prog = argv[0];
	if ((str = strrchr(prog, '/')) != NULL)
		str++;
	else
		str = prog;

	if (strcmp(str, "mcs") == 0) {
		my_prog = MCS;
		opt = "a:cdn:pVz?";
	} else if (strcmp(str, "strip") == 0) {
		my_prog = STRIP;
		opt = "lxV?";
	} else
		exit(FAILURE);

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	for (i = 0; signum[i]; i++)
		if (signal(signum[i], SIG_IGN) != SIG_IGN)
			(void) signal(signum[i], sigexit);

	if ((Action =
	    malloc(optbufsz * sizeof (struct action))) == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, (char *)0, prog);
		exit(FAILURE);
	}

	/*
	 * Allocate command info structure
	 */
	cmd_info = (Cmd_Info *) calloc(1, sizeof (Cmd_Info));
	if (cmd_info == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, (char *)0, prog);
		exit(FAILURE);
	}
	if (my_prog == STRIP)
		cmd_info->flags |= I_AM_STRIP;

	while ((c = getopt(argc, argv, (char *)opt)) != EOF) {
		switch (c) {
		case 'a':
			optcnt++;
			queue(ACT_APPEND, optarg);
			cmd_info->flags |= (MIGHT_CHG | aFLAG);
			cmd_info->str_size += strlen(optarg) + 1;
			break;
		case 'c':
			optcnt++;
			queue(ACT_COMPRESS, NULL);
			cmd_info->flags |= (MIGHT_CHG | cFLAG);
			break;
		case 'd':
			optcnt++;
			if (CHK_OPT(cmd_info, dFLAG) == 0)
				queue(ACT_DELETE, NULL);
			cmd_info->flags |= (MIGHT_CHG | dFLAG);
			break;
		case 'z':
			optcnt++;
			queue(ACT_ZAP, NULL);
			cmd_info->flags |= (MIGHT_CHG | zFLAG);
			break;
		case 'n':
			(void) setup_sectname(optarg, my_prog);
			num_sect++;
			break;
		case 'l':
			optcnt++;
			cmd_info->flags |= lFLAG;
			break;
		case 'p':
			optcnt++;
			queue(ACT_PRINT, NULL);
			cmd_info->flags |= pFLAG;
			break;
		case 'x':
			optcnt++;
			cmd_info->flags |= xFLAG;
			break;
		case 'V':
			cmd_info->flags |= VFLAG;
			(void) fprintf(stderr, "%s: %s %s\n", prog,
			    (const char *)SGU_PKG, (const char *)SGU_REL);
			break;
		case '?':
			errflag++;
			break;
		default:
			break;
		}
	}

	if (errflag) {
		usage(my_prog);
		exit(FAILURE);
	}

	/*
	 * strip command may not take any options.
	 */
	if (my_prog != STRIP) {
		if (argc == optind &&
		    (CHK_OPT(cmd_info, MIGHT_CHG) || CHK_OPT(cmd_info, pFLAG) ||
		    argc == 1))
			usage(my_prog);
		else if (!CHK_OPT(cmd_info, MIGHT_CHG) &&
		    !CHK_OPT(cmd_info, pFLAG) && !CHK_OPT(cmd_info, VFLAG))
			usage(my_prog);
	}

	/*
	 * This version only allows multiple section names
	 * only for -d option.
	 */
	if ((num_sect >= 2) && (CHK_OPT(cmd_info, pFLAG) ||
	    CHK_OPT(cmd_info, aFLAG) ||
	    CHK_OPT(cmd_info, cFLAG))) {
		error_message(USAGE_ERROR, PLAIN_ERROR, (char *)0,  prog);
		exit(FAILURE);
	}

	/*
	 * If no -n was specified,
	 * set the default, ".comment".
	 * This is for mcs only.
	 */
	if (num_sect == 0 && my_prog == MCS) {
		(void) setup_sectname(".comment", MCS);
	}

	/*
	 * If I am strip command, then add needed
	 * section names.
	 */
	if (my_prog == STRIP) {
		(void) setup_sectname(".line", MCS);
		if (CHK_OPT(cmd_info, lFLAG) == 0) {
			(void) setup_sectname(".debug", STRIP);
			(void) setup_sectname(".stab", STRIP);
		}
		if (CHK_OPT(cmd_info, dFLAG) == 0) {
			queue(ACT_DELETE, NULL);
			cmd_info->flags |= MIGHT_CHG;
			cmd_info->flags |= dFLAG;
		}
	}

	(void) elf_version(EV_NONE);
	if (elf_version(EV_CURRENT) == EV_NONE) {
		error_message(ELFVER_ERROR, LIBelf_ERROR, elf_errmsg(-1), prog);
		exit(FAILURE);
	}

	if (CHK_OPT(cmd_info, pFLAG) || CHK_OPT(cmd_info, MIGHT_CHG)) {
		for (; optind < argc; optind++) {
			error_count = error_count +
			    (each_file(argv[optind], cmd_info));
		}
	}

	mcs_exit(error_count);
	/*NOTREACHED*/
	return (0);
}

/*
 * Supplementary functions
 */
static void
queue(int activity, char *string)
{
	if (optcnt > optbufsz) {
		optbufsz = optbufsz * 2;
		if ((Action = realloc((struct action *)Action,
		    optbufsz * sizeof (struct action))) == NULL) {
		    error_message(MALLOC_ERROR, PLAIN_ERROR, (char *)0, prog);
		    mcs_exit(FAILURE);
		}
	}
	Action[actmax].a_action = activity;
	Action[actmax].a_cnt = 0;
	Action[actmax].a_string = string;
	actmax++;
}

/*
 * Reset a temporary file descriptor for reuse.
 * If the file requires unlinking, that is done first.
 */
void
free_tempfile(Tmp_File *temp_file)
{
	if ((temp_file->tmp_name != NULL) && (temp_file->tmp_unlink))
		(void) unlink(temp_file->tmp_name);
	(void) memset(temp_file, 0, sizeof (*temp_file));
}

/*ARGSUSED0*/
static void
sigexit(int i)
{
	free_tempfile(&artmpfile);
	free_tempfile(&elftmpfile);
	exit(100);
}

static void
usage(int me)
{
	if (me == MCS)
		(void) fprintf(stderr, gettext(
		"usage: %s [-cdpVz] [-a string] [-n name] file ...\n"), prog);
	else
		(void) fprintf(stderr, gettext(
		"usage: %s [-lVx] file ...\n"), prog);
	mcs_exit(FAILURE);
}

void
mcs_exit(int val)
{
	free_tempfile(&artmpfile);
	free_tempfile(&elftmpfile);
	exit(val);
}

/*
 * Insert the section name 'name' into the
 * section list.
 */
static int
setup_sectname(char *name, int whoami)
{
	S_Name *new;

	/*
	 * Check if the name is already specified or not.
	 */
	if ((whoami == MCS) && (sectcmp(name) == 0))
		return (0);

	/*
	 * Allocate one
	 */
	if ((new = malloc(sizeof (S_Name))) == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, (char *)0, prog);
		exit(FAILURE);
	}
	new->name = strdup(name);
	if (new->name == NULL) {
		error_message(USAGE_ERROR, PLAIN_ERROR, (char *)0, prog);
		exit(FAILURE);
	}
	if (whoami == STRIP)
		new->flags = SNAME_FLG_STRNCMP;
	new->next = NULL;

	/*
	 * Put this one in the list
	 */
	new->next = sect_head;
	sect_head = new;

	return (0);
}

/*
 * Check if the 'name' exists in the section list.
 *
 * If found
 *	return 0;
 * else
 *	return 1
 */
int
sectcmp(char *name)
{
	/*
	 * Check if the name is already specified or not.
	 */
	if (sect_head != NULL) {
		S_Name *p1 = sect_head;
		while (p1 != NULL) {
			if (p1->flags & SNAME_FLG_STRNCMP) {
				if (strncmp(p1->name,
				    name, strlen(p1->name)) == 0)
					return (0);
			} else if (strcmp(p1->name, name) == 0) {
				return (0);	/* silently ignore */
			}
			p1 = p1->next;
		}
	}
	return (1);
}
