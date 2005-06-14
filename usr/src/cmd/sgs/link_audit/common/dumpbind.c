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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdlib.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/lwp.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<sys/mman.h>
#include	<synch.h>
#include	<errno.h>

#include	"bindings.h"

void
usage()
{
	(void) printf("usage: dumpbind [-pqsc] <bindings.data>\n");
	(void) printf("\t-p\tdisplay output in parsable format\n");
	(void) printf("\t-q\tquery all mutex_locks in data buffer\n");
	(void) printf("\t-c\tclear all mutex_locks in data buffer\n");
	(void) printf("\t-s\tset all mutex_locks in data buffer\n");
	(void) printf("\t-b\tprint bucket usage statistics\n");
}

/*
 * Returns 1 if lock held - 0 otherwise.
 */
static int
query_lock(lwp_mutex_t *lock) {
	if (_lwp_mutex_trylock(lock) == 0) {
		(void) _lwp_mutex_unlock(lock);
		return (0);
	} else
		return (1);
}

static void
query_buffer_locks(bindhead * bhp)
{
	int	i, bkt_locks_held = 0;

	(void) printf("bh_strlock: ");
	if (query_lock(&bhp->bh_strlock) == 1)
		(void) printf("lock held\n");
	else
		(void) printf("free\n");

	(void) printf("bh_lock: ");
	if (query_lock(&bhp->bh_lock) == 1)
		(void) printf("lock held\n");
	else
		(void) printf("free\n");

	(void) printf("Buckets: %d - locks held:\n", bhp->bh_bktcnt);
	for (i = 0; i < bhp->bh_bktcnt; i++) {
		if (query_lock(&bhp->bh_bkts[i].bb_lock) == 1) {
			bkt_locks_held++;
			(void) printf("\tbkt[%d]: lock held\n", i);
		}
	}
	if (bkt_locks_held == 0)
		(void) printf("\tnone.\n");
	else
		(void) printf("\t[%d bucket(s) locked]\n", bkt_locks_held);
}

static void
clear_buffer_locks(bindhead * bhp)
{
	int	i;

	if (query_lock(&bhp->bh_strlock) == 1) {
		(void) _lwp_mutex_unlock(&bhp->bh_strlock);
		(void) printf("bh_strlock: cleared\n");
	}
	if (query_lock(&bhp->bh_lock) == 1) {
		(void) _lwp_mutex_unlock(&bhp->bh_lock);
		(void) printf("bh_lock: cleared\n");
	}
	for (i = 0; i < bhp->bh_bktcnt; i++) {
		if (query_lock(&bhp->bh_bkts[i].bb_lock) == 1) {
			(void) _lwp_mutex_unlock(&bhp->bh_bkts[i].bb_lock);
			(void) printf("bkt[%d]: lock cleared\n", i);
		}
	}
}

static void
set_buffer_locks(bindhead * bhp)
{
	int	i;

	for (i = 0; i < bhp->bh_bktcnt; i++)
		(void) _lwp_mutex_lock(&bhp->bh_bkts[i].bb_lock);

	(void) _lwp_mutex_lock(&bhp->bh_strlock);
	(void) _lwp_mutex_lock(&bhp->bh_lock);
}

int
main(int argc, char **argv)
{
	int		fd;
	char		*fname, *format_string;
	bindhead	*bhp, *tmp_bhp;
	int		i, c;
	int		bflag = 0, pflag = 0, qflag = 0, cflag = 0, sflag = 0;
	ulong_t		symcount, callcount;

	while ((c = getopt(argc, argv, "bspcq")) != EOF)
		switch (c) {
		case 'b':
			bflag++;
			break;
		case 'p':
			pflag++;
			break;
		case 'q':
			qflag++;
			break;
		case 'c':
			cflag++;
			break;
		case 's':
			sflag++;
			break;
		case '?':
			usage();
			return (1);
		}

	if (optind == argc) {
		usage();
		return (1);
	}
	fname = argv[optind];
	if ((fd = open(fname, O_RDWR)) == -1) {
		(void) fprintf(stderr,
		    "dumpbindings: unable to open file: %s\n", fname);
		perror("open");
		return (1);
	}
	/* LINTED */
	if ((bhp = (bindhead *)mmap(0, sizeof (bindhead),
	    (PROT_READ | PROT_WRITE), MAP_SHARED, fd, 0)) == MAP_FAILED) {
		(void) fprintf(stderr, "dumpbind: mmap failed\n");
		perror("mmap");
		return (1);
	}

	if (qflag) {
		query_buffer_locks(bhp);
		return (0);
	}

	if (cflag) {
		clear_buffer_locks(bhp);
		return (0);
	}
	if (sflag) {
		set_buffer_locks(bhp);
		return (0);
	}

	/* LINTED */
	if ((tmp_bhp = (bindhead *)mmap(0, bhp->bh_size,
	    (PROT_READ | PROT_WRITE), MAP_SHARED, fd, 0)) == MAP_FAILED) {
		(void) fprintf(stderr, "dumpbind: remap: mmap failed\n");
		perror("mmap");
		return (1);
	}
	(void) close(fd);

	(void) munmap((void *)bhp, sizeof (bindhead));
	bhp = tmp_bhp;

	if (pflag)
		format_string = "%s|%s|%8d\n";
	else {
		if (!bflag)
		    (void) printf(
			"                           Bindings Summary Report\n\n"
			"Library                             Symbol"
			"                   Call Count\n"
			"----------------------------------------------"
			"--------------------------\n");
		format_string = "%-35s %-25s %5d\n";
	}

	symcount = 0;
	callcount = 0;
	for (i = 0; i < bhp->bh_bktcnt; i++) {
		int		ent_cnt = 0;
		binding_entry *	bep;
		unsigned int	bep_off = bhp->bh_bkts[i].bb_head;

		while (bep_off) {
			/* LINTED */
			bep = (binding_entry *)((char *)bhp + bep_off);
			if (!bflag) {
				/* LINTED */
				(void) printf(format_string,
				    (char *)bhp + bep->be_lib_name,
				    (char *)bhp + bep->be_sym_name,
				    bep->be_count);
				symcount++;
				callcount += bep->be_count;
			}
			bep_off = bep->be_next;
			ent_cnt++;
		}
		if (bflag)
			(void) printf("bkt[%d] - %d entries\n", i, ent_cnt);
	}

	if (!bflag && !pflag)
		(void) printf(
			"----------------------------------------------"
			"--------------------------\n"
			"Symbol Count: %lu    Call Count: %lu\n\n",
			symcount, callcount);

	return (0);
}
