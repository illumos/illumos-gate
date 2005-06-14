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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <link.h>
#include <sys/types.h>
#include <sys/regset.h>
#include <sys/frame.h>
#include <sys/procfs.h>
#include <fcntl.h>
#include <signal.h>
#include "env.h"
#include "hash.h"


typedef struct {
	float		d_time;
	int		d_count;
	const char	*d_symname;
} d_entry;

typedef struct list {
	d_entry		*l_dep;
	struct list	*l_next;
} List;


static Elist	    *bindto_list = 0;
static Elist	    *bindfrom_list = 0;

static int  initialized;
extern long long gethrvtime();

static const char *progname;
static long long starts[1000];
static long long accounted[1000];		/* time accounted for */
static int  counter = 0;

static float	total_time = 0.0;
static List	*list_head = 0;

static hash	*tbl;

static sigset_t		iset;

static void
list_insert(d_entry *dep)
{
	List *new_list;
	List *cur;
	List *prev;

	if ((new_list = malloc(sizeof (List))) == 0) {
		(void) printf("libperfcnt.so: malloc failed - "
			"can't print summary\n");
		exit(1);
	}
	new_list->l_dep = dep;

	if (list_head == 0) {
		list_head = new_list;
		new_list->l_next = 0;
		return;
	}
	for (cur = list_head, prev = 0;
	    (cur && (cur->l_dep->d_time < dep->d_time));
	    prev = cur, cur = cur->l_next)
		;
	/*
	 * insert at head of list
	 */
	if (prev == 0) {
		new_list->l_next = list_head;
		list_head = new_list;
		return;
	}
	prev->l_next = new_list;
	new_list->l_next = cur;
}

uint_t
la_version(uint_t version)
{
	int fd;
	char buffer[100];

	if (version > LAV_CURRENT)
		(void) fprintf(stderr, "perfcnt.so.1: unexpected version: %d\n",
			version);

	(void) sprintf(buffer, "/proc/%d", (int)getpid());
	if ((fd = open(buffer, O_RDWR)) >= 0) {
		long state = PR_MSACCT;
		if (ioctl(fd, PIOCSET, &state) == -1)
			perror("PIOCSET");
		(void) close(fd);
	}

	initialized++;
	tbl = make_hash(213);

	build_env_list(&bindto_list, (const char *)"PERFCNT_BINDTO");
	build_env_list(&bindto_list, (const char *)"PERFCNT_BINDFROM");

	/*
	 * Initalize iset to the full set of signals to be masked durring
	 * pltenter/pltexit
	 */
	(void) sigfillset(&iset);

	return (LAV_CURRENT);
}


/* ARGSUSED1 */
uint_t
la_objopen(Link_map *lmp, Lmid_t lmid, uintptr_t *cookie)
{
	static int	first = 1;
	uint_t	flags = 0;

	if (first) {
		progname = lmp->l_name;
		first = 0;
	}

	if (bindto_list == 0)
		flags = LA_FLG_BINDTO;
	else {
		if (check_list(bindto_list, lmp->l_name))
			flags = LA_FLG_BINDTO;
	}
	if (bindfrom_list == 0)
		flags |= LA_FLG_BINDFROM;
	else {
		if (check_list(bindfrom_list, lmp->l_name))
			flags |= LA_FLG_BINDFROM;
	}

	return (flags);
}

/* ARGSUSED1 */
#if	defined(__sparcv9)
uintptr_t
la_sparcv9_pltenter(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_sparcv9_regs *regset, uint_t *sb_flags,
	const char *sym_name)
#elif	defined(__sparc)
uintptr_t
la_sparcv8_pltenter(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_sparcv8_regs *regset, uint_t *sb_flags)
#elif	defined(__amd64)
uintptr_t
la_amd64_pltenter(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, La_amd64_regs *regset, uint_t *sb_flags,
	const char *sym_name)
#elif	defined(__i386)
uintptr_t
la_i86_pltenter(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcooke,
	uintptr_t *defcook, La_i86_regs *regset, uint_t *sb_flags)
#endif
{
	accounted[counter] = 0;
	starts[counter] = gethrvtime();
	counter++;
	return (symp->st_value);
}



/* ARGSUSED1 */
#if	defined(_LP64)
/* ARGSUSED */
uintptr_t
la_pltexit64(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, uintptr_t retval, const char *sym_name)
#else
uintptr_t
la_pltexit(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcookie,
	uintptr_t *defcookie, uintptr_t retval)
#endif
{
	d_entry		**dep;
	long long	time_used;
	sigset_t	oset;
#if	!defined(_LP64)
	const char	*sym_name = (const char *)symp->st_name;
#endif

	(void) sigprocmask(SIG_BLOCK, &iset, &oset);

	counter--;
	time_used = gethrvtime() - starts[counter];

	dep = (d_entry **)get_hash(tbl, (char *)sym_name);
	if (*dep == NULL) {
		char *ptr = malloc(sizeof (d_entry));
		/* LINTED */
		(*dep) = (d_entry *)ptr;
		(*dep)->d_count = 0;
		(*dep)->d_time = 0.0;
		(*dep)->d_symname = sym_name;
	}

	if (counter)
		accounted[counter - 1] += time_used;

	((*dep)->d_count)++;
	(*dep)->d_time += (double)((time_used - accounted[counter]) / 1.0e9);

	(void) sigprocmask(SIG_SETMASK, &oset, NULL);

	return (retval);
}

/* ARGSUSED1 */
static void
scanlist(d_entry *dep, void *food, char *name)
{
	total_time += dep->d_time;
	list_insert(dep);
}

#pragma fini(cleanup)
static void
cleanup()
{
	List	*cur;
	(void) operate_hash(tbl, scanlist, NULL);
	(void) printf("\n\nPerf Counts for: %s\n\n", progname);
	(void) printf("%20s\tc_count\t    tim\t\tavg. tim\ttot. %%\n",
		"SYMBOL");
	(void) printf("--------------------------------------------------"
		"-------------------\n");
	for (cur = list_head; cur; cur = cur->l_next) {
		d_entry		*dep = cur->l_dep;
		float		tim = dep->d_time * 1000000;

		(void) printf("%20s\t%d\t%8.2f\t%8.2f\t%2.2f%%\n",
			dep->d_symname, dep->d_count, tim, tim / dep->d_count,
			((dep->d_time / total_time) * 100.0));
	}
	(void) printf("--------------------------------------------------"
		"-------------------\n");
	(void) printf("\t\t\t\t\t\tTotal Time: %8.2f\n",
		total_time * 1000000);
}
