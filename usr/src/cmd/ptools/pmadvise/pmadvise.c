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

/*
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */

/*
 * pmadvise
 *
 * ptool wrapper for madvise(3C) to apply memory advice to running processes
 *
 * usage:	pmadvise -o option[,option] [-v] [-F] pid ...
 *  (Give "advice" about a process's memory)
 *  -o option[,option]: options are
 *      private=<advice>
 *      shared=<advice>
 *      heap=<advice>
 *      stack=<advice>
 *      <segaddr>[:<length>]=<advice>
 *     valid <advice> is one of:
 *      normal, random, sequential, willneed, dontneed,
 *      free, access_lwp, access_many, access_default
 *  -v: verbose output
 *  -F: force grabbing of the target process(es)
 *  -l: show unresolved dynamic linker map names
 *  pid: process id list
 *
 *
 * Advice passed to this tool are organized into various lists described here:
 *  rawadv_list: includes all specific advice from command line (specific
 *               advice being those given to a particular address range rather
 *               than a type like "heap" or "stack".  In contrast, these
 *               types are referred to as generic advice). Duplicates allowed.
 *               List ordered by addr, then by size (largest size first).
 *               Created once per run.
 *  merged_list: includes all specific advice from the rawadv_list as well as
 *               all generic advice.  This must be recreated for each process
 *               as the generic advice will apply to different regions for
 *               different processes. Duplicates allowed. List ordered by addr,
 *               then by size (largest size first). Created once per pid.
 *  chopped_list: used for verbose output only. This list parses the merged
 *                list such that it eliminates any overlap and combines the
 *                advice. Easiest to think of this visually: if you take all
 *                the advice in the merged list and lay them down on a memory
 *                range of the entire process (laying on top of each other when
 *                necessary), then flatten them into one layer, combining advice
 *                in the case of overlap, you get the chopped_list of advice.
 *                Duplicate entries not allowed (since there is no overlap by
 *                definition in this list).  List ordered by addr. Created once
 *                per pid.
 *
 *                Example:
 *                   merged_list:   |-----adv1----|---------adv3---------|
 *                                       |--adv2--|--adv4--|-----adv5----|
 *                                                  ||
 *                                                  \/
 *                   chopped_list:  |adv1|-adv1,2-|-adv3,4-|----adv3,5---|
 *
 *  maplist: list of memory mappings for a particular process. Used to create
 *           generic advice entries for merged_list and for pmap like verbose
 *           output. Created once per pid.
 *
 * Multiple lists are necessary because the actual advice applied given a set
 * of generic and specific advice changes from process to process, so for each
 * pid pmadvise is passed, it must create a new merged_list from which to apply
 * advice (and a new chopped_list if verbose output is requested).
 *
 * Pseudo-code:
 * I.	Input advice from command line
 * II.	Create [raw advice list] of specific advice
 * III.	Iterate through PIDs:
 *	A.	Create [map list]
 *	B.	Merge generic advice and [raw advice list] into [merged list]
 *	C.	Apply advice from [merged list]; upon error:
 *		i.	output madvise error message
 *		ii.	remove element from [merged list]
 *	D.	If verbose output:
 *		i.	Create [chopped list] from [merged list]
 *		ii.	Iterate through [map list]:
 *			a.	output advice as given by [merged list]
 *		iii.	Delete [chopped list]
 *	E.	Delete [merged list]
 *	F.	Delete [map list]
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <link.h>
#include <libelf.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <assert.h>
#include <libproc.h>
#include <libgen.h>
#include <signal.h>

#include "pmap_common.h"

#ifndef	TEXT_DOMAIN			/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* use this only if it wasn't */
#endif

#define	KILOBYTE	1024

/*
 * Round up the value to the nearest kilobyte
 */
#define	ROUNDUP_KB(x)	(((x) + (KILOBYTE - 1)) / KILOBYTE)

#define	NO_ADVICE		0

/*
 * The following definitions are used as the third argument in insert_addr()
 *   NODUPS = no duplicates are not allowed, thus if the addr being inserted
 *   already exists in the list, return without inserting again.
 *
 *   YESDUPS = yes duplicates are allowed, thus always insert the addr
 *   regardless of whether it already exists in the list or not.
 */
#define	NODUPS	1
#define	YESDUPS	0

/*
 * Advice that can be passed to madvise fit into three groups that each
 * contain 3 mutually exclusive options.  These groups are defined below:
 *   Group 1: normal, random, sequential
 *   Group 2: willneed, dontneed, free, purge
 *   Group 3: default, accesslwp, accessmany
 * Thus, advice that includes (at most) one from each group is valid.
 *
 * The following #define's are used as masks to determine which group(s) a
 * particular advice fall under.
 */

#define	GRP1_ADV	(1 << MADV_NORMAL | 1 << MADV_RANDOM | \
			1 << MADV_SEQUENTIAL)
#define	GRP2_ADV	(1 << MADV_WILLNEED | 1 << MADV_DONTNEED | \
			1 << MADV_FREE | 1 << MADV_PURGE)
#define	GRP3_ADV	(1 << MADV_ACCESS_DEFAULT | 1 << MADV_ACCESS_LWP | \
			1 << MADV_ACCESS_MANY)

static	int	create_maplist(void *, const prmap_t *, const char *);
static	int	pr_madvise(struct ps_prochandle *, caddr_t, size_t, int);

static	char	*mflags(uint_t);
static	char	*advtostr(int);

static	int	lflag = 0;

static	int	addr_width, size_width;
static	char	*progname;
static	struct ps_prochandle *Pr;

static	lwpstack_t *stacks;
static	uint_t	nstacks;

static char	*suboptstr[] = {
	"private",
	"shared",
	"heap",
	"stack",
	NULL
};


int	generic_adv[] = {NO_ADVICE, NO_ADVICE, NO_ADVICE, NO_ADVICE};
int	at_map = 0;

typedef struct saddr_struct {
	uintptr_t	addr;
	size_t		length;
	int		adv;
	struct saddr_struct	*next;
} saddr_t;
static int	apply_advice(saddr_t **);
static void	set_advice(int *, int);
static void	create_choplist(saddr_t **, saddr_t *);

/*
 * The segment address advice from the command line
 */
saddr_t	*rawadv_list = NULL;
/*
 * The rawadv_list + list entries for the generic advice (if any).
 * This must be recreated for each PID as the memory maps might be different.
 */
saddr_t *merged_list = NULL;
/*
 * The merged_list cut up so as to remove all overlap
 * e.g. if merged_list contained two entries:
 *
 * [0x38000:0x3e000) = adv1
 * [0x3a000:0x3c000) = adv2
 *
 * the chopped list will contain three entries:
 *
 * [0x38000:0x3a000) = adv1
 * [0x3a000:0x3c000) = adv1,adv2
 * [0x3c000:0x3e000) = adv1
 *
 */
saddr_t *chopped_list = NULL;

typedef struct mapnode_struct {
	prmap_t			*pmp;
	char			label[PATH_MAX];
	int			mtypes;
	struct mapnode_struct	*next;
} mapnode_t;

mapnode_t *maplist_head = NULL;
mapnode_t *maplist_tail = NULL;
static void	print_advice(saddr_t *, mapnode_t *);

int	opt_verbose;

static char	*advicestr[] = {
	"normal",
	"random",
	"sequential",
	"willneed",
	"dontneed",
	"free",
	"access_default",
	"access_lwp",
	"access_many"
};

/*
 * How many signals caught from terminal
 * We bail out as soon as possible when interrupt is set
 */
static int	interrupt = 0;

/*
 * Interrupt handler
 */
static void	intr(int);

/*
 * Iterative function passed to Plwp_iter to
 * get alt and main stacks for given lwp.
 */
static int
getstack(void *data, const lwpstatus_t *lsp)
{
	int *np = (int *)data;

	if (Plwp_alt_stack(Pr, lsp->pr_lwpid, &stacks[*np].lwps_stack) == 0) {
		stacks[*np].lwps_stack.ss_flags |= SS_ONSTACK;
		stacks[*np].lwps_lwpid = lsp->pr_lwpid;
		(*np)++;
	}

	if (Plwp_main_stack(Pr, lsp->pr_lwpid, &stacks[*np].lwps_stack) == 0) {
		stacks[*np].lwps_lwpid = lsp->pr_lwpid;
		(*np)++;
	}

	return (0);
}

/*
 * Prints usage and exits
 */
static void
usage()
{
	(void) fprintf(stderr,
	    gettext("usage:\t%s [-o option[,option]] [-Flv] pid ...\n"),
	    progname);
	(void) fprintf(stderr,
	    gettext("    (Give \"advice\" about a process's memory)\n"
	    "    -o option[,option]: options are\n"
	    "        private=<advice>\n"
	    "        shared=<advice>\n"
	    "        heap=<advice>\n"
	    "        stack=<advice>\n"
	    "        <segaddr>[:<length>]=<advice>\n"
	    "       valid <advice> is one of:\n"
	    "        normal, random, sequential, willneed, dontneed,\n"
	    "        free, access_lwp, access_many, access_default\n"
	    "    -v: verbose output\n"
	    "    -F: force grabbing of the target process(es)\n"
	    "    -l: show unresolved dynamic linker map names\n"
	    "    pid: process id list\n"));
	exit(2);
}

/*
 * Function to parse advice from options string
 */
static int
get_advice(char *optarg)
{
	/*
	 * Determine which advice is given, we use shifted values as
	 * multiple pieces of advice may apply for a particular region.
	 * (See comment above regarding GRP[1,2,3]_ADV definitions for
	 * breakdown of advice groups).
	 */
	if (strcmp(optarg, "access_default") == 0)
		return (1 << MADV_ACCESS_DEFAULT);
	else if (strcmp(optarg, "access_many") == 0)
		return (1 << MADV_ACCESS_MANY);
	else if (strcmp(optarg, "access_lwp") == 0)
		return (1 << MADV_ACCESS_LWP);
	else if (strcmp(optarg, "sequential") == 0)
		return (1 << MADV_SEQUENTIAL);
	else if (strcmp(optarg, "willneed") == 0)
		return (1 << MADV_WILLNEED);
	else if (strcmp(optarg, "dontneed") == 0)
		return (1 << MADV_DONTNEED);
	else if (strcmp(optarg, "random") == 0)
		return (1 << MADV_RANDOM);
	else if (strcmp(optarg, "normal") == 0)
		return (1 << MADV_NORMAL);
	else if (strcmp(optarg, "free") == 0)
		return (1 << MADV_FREE);
	else if (strcmp(optarg, "purge") == 0)
		return (1 << MADV_PURGE);
	else {
		(void) fprintf(stderr, gettext("%s: invalid advice: %s\n"),
		    progname, optarg);
		usage();
		return (-1);
	}
}

/*
 * Function to convert character size indicators into actual size
 * (i.e., 123M => sz = 123 * 1024 * 1024)
 */
static size_t
atosz(char *optarg, char **endptr)
{
	size_t	sz = 0;

	if (optarg == NULL || optarg[0] == '\0')
		return (0);

	sz = strtoll(optarg, endptr, 0);

	switch (**endptr) {
	case 'E':
	case 'e':
		sz *= KILOBYTE;
		/* FALLTHRU */
	case 'P':
	case 'p':
		sz *= KILOBYTE;
		/* FALLTHRU */
	case 'T':
	case 't':
		sz *= KILOBYTE;
		/* FALLTHRU */
	case 'G':
	case 'g':
		sz *= KILOBYTE;
		/* FALLTHRU */
	case 'M':
	case 'm':
		sz *= KILOBYTE;
		/* FALLTHRU */
	case 'K':
	case 'k':
		sz *= KILOBYTE;
		/* FALLTHRU */
	case 'B':
	case 'b':
		(*endptr)++;
		/* FALLTHRU */
	default:
		break;
	}
	return (sz);
}

/*
 * Inserts newaddr into list.  dups indicates whether we allow duplicate
 * addr entries in the list (valid values are NODUPS and YESDUPS).
 */
static void
insert_addr(saddr_t **list, saddr_t *newaddr, int dups)
{
	saddr_t *prev = *list;
	saddr_t *psaddr;

	if (*list == NULL) {
		newaddr->next = *list;
		*list = newaddr;
		return;
	}

	for (psaddr = (*list)->next; psaddr != NULL; psaddr = psaddr->next) {
		if ((dups == NODUPS) && (psaddr->addr == newaddr->addr)) {
			free(newaddr);
			return;
		}

		/*
		 * primary level of comparison is by address; smaller addr 1st
		 * secondary level of comparison is by length; bigger length 1st
		 */
		if ((psaddr->addr > newaddr->addr) ||
		    (psaddr->addr == newaddr->addr &&
		    psaddr->length < newaddr->length))
			break;

		prev = psaddr;
	}

	prev->next = newaddr;
	newaddr->next = psaddr;
}

/*
 * Deletes given element from list
 */
static void
delete_addr(saddr_t **list, saddr_t *delme)
{
	saddr_t	*prev = *list;

	if (delme == *list) {
		*list = delme->next;
		free(delme);
		return;
	}

	while (prev != NULL && prev->next != delme) {
		prev = prev->next;
	}

	if (prev) {
		prev->next = delme->next;
		free(delme);
	}
}

/*
 * Delete entire list
 */
static void
delete_list(saddr_t **list)
{
	saddr_t *psaddr = *list;

	while (psaddr != NULL) {
		saddr_t *temp = psaddr;

		psaddr = psaddr->next;
		free(temp);
	}
	*list = NULL;
}

static saddr_t *
parse_suboptions(char *value)
{
	char	*endptr;
	saddr_t *psaddr = malloc(sizeof (saddr_t));

	/*
	 * This must (better) be a segment addr
	 */
	psaddr->addr =
	    strtoull(value, &endptr, 16);

	/*
	 * Check to make sure strtoul worked correctly (a properly formatted
	 * string will terminate in a ':' (if size is given) or an '=' (if size
	 * is not specified). Also check to make sure a 0 addr wasn't returned
	 * indicating strtoll was unable to convert).
	 */
	if ((psaddr->addr == 0) || (*endptr != ':' && *endptr != '=')) {
		free(psaddr);
		(void) fprintf(stderr,
		    gettext("%s: invalid option %s\n"),
		    progname, value);
		usage();
	} else {
		/* init other fields */
		psaddr->length = 0;
		psaddr->adv = NO_ADVICE;
		psaddr->next = NULL;

		/* skip past address */
		value = endptr;

		/* check for length */
		if (*value == ':') {
			/* skip the ":" */
			value++;
			psaddr->length = atosz(value, &endptr);
		}

		if (*endptr != '=') {
			(void) fprintf(stderr,
			    gettext("%s: invalid option %s\n"),
			    progname, value);
			/*
			 * if improperly formatted, free mem, print usage, and
			 * exit Note: usage ends with a call to exit()
			 */
			free(psaddr);
			usage();
		}
		/* skip the "=" */
		value = endptr + 1;
		at_map |= (1 << AT_SEG);
		psaddr->adv =
		    get_advice(value);
	}

	return (psaddr);
}

/*
 * Create linked list of mappings for current process
 * In addition, add generic advice and raw advice
 * entries to merged_list.
 */
/* ARGSUSED */
static int
create_maplist(void *arg, const prmap_t *pmp, const char *object_name)
{
	const 		pstatus_t *Psp = Pstatus(Pr);
	mapnode_t *newmap = malloc(sizeof (mapnode_t));
	saddr_t	*newaddr;
	saddr_t	*psaddr;
	char	*lname = NULL;
	int	i;

	if (interrupt)
		return (0);

	newmap->pmp = malloc(sizeof (prmap_t));
	newmap->label[0] = '\0';
	newmap->mtypes = 0;
	newmap->next = NULL;
	(void) memcpy(newmap->pmp, pmp, sizeof (prmap_t));

	/*
	 * If the mapping is not anon or not part of the heap, make a name
	 * for it.  We don't want to report the heap as a.out's data.
	 */
	if (!(pmp->pr_mflags & MA_ANON) ||
	    (pmp->pr_vaddr + pmp->pr_size <= Psp->pr_brkbase ||
	    pmp->pr_vaddr >= Psp->pr_brkbase + Psp->pr_brksize)) {
		lname = make_name(Pr, lflag, pmp->pr_vaddr, pmp->pr_mapname,
		    newmap->label, sizeof (newmap->label));
		if (pmp->pr_mflags & MA_SHARED)
			newmap->mtypes |= 1 << AT_SHARED;
		else
			newmap->mtypes |= 1 << AT_PRIVM;
	}

	if (lname == NULL && (pmp->pr_mflags & MA_ANON)) {
		lname = anon_name(newmap->label, Psp, stacks, nstacks,
		    pmp->pr_vaddr, pmp->pr_size, pmp->pr_mflags, pmp->pr_shmid,
		    &newmap->mtypes);
	}

	/*
	 * Add raw advice that applies to this mapping to the merged_list
	 */
	psaddr = rawadv_list;
	/*
	 * Advance to point in rawadv_list that applies to this mapping
	 */
	while (psaddr && psaddr->addr < pmp->pr_vaddr)
		psaddr = psaddr->next;
	/*
	 * Copy over to merged_list, check to see if size needs to be filled in
	 */
	while (psaddr && psaddr->addr < (pmp->pr_vaddr + pmp->pr_size)) {
		newaddr = malloc(sizeof (saddr_t));
		(void) memcpy(newaddr, psaddr, sizeof (saddr_t));
		insert_addr(&merged_list, newaddr, YESDUPS);
		/*
		 * For raw advice that is given without size, try to default
		 * size to size of mapping (only allowed if raw adv addr is
		 * equal to beginning of mapping). Don't change the entry
		 * in rawadv_list, only in the merged_list as the mappings
		 * (and thus the default sizes) will be different for
		 * different processes.
		 */
		if ((pmp->pr_vaddr == psaddr->addr) && (psaddr->length == 0))
			newaddr->length = pmp->pr_size;
		psaddr = psaddr->next;
	}

	/*
	 * Put mapping into merged list with no advice, then
	 * check to see if any generic advice applies.
	 */
	newaddr = malloc(sizeof (saddr_t));
	newaddr->addr = pmp->pr_vaddr;
	newaddr->length = pmp->pr_size;
	newaddr->adv = NO_ADVICE;
	insert_addr(&merged_list, newaddr, YESDUPS);

	newmap->mtypes &= at_map;
	for (i = AT_STACK; i >= AT_PRIVM; i--) {
		if (newmap->mtypes & (1 << i)) {
			assert(generic_adv[i] != NO_ADVICE);
			newaddr->adv = generic_adv[i];
			break;
		}
	}

	/*
	 * Add to linked list of mappings
	 */
	if (maplist_tail == NULL) {
		maplist_head = maplist_tail = newmap;
	} else {
		maplist_tail->next = newmap;
		maplist_tail = newmap;
	}


	return (0);
}

/*
 * Traverse advice list and apply all applicable advice to each region
 */
static int
apply_advice(saddr_t **advicelist)
{
	saddr_t	*psaddr = *advicelist;
	saddr_t	*next;
	int	i;


	while (!interrupt && psaddr != NULL) {
		/*
		 * Save next pointer since element may be removed before
		 * we get a chance to advance psaddr.
		 */
		next = psaddr->next;

		/*
		 * Since mappings have been added to the merged list
		 * even if no generic advice was given for the map,
		 * check to make sure advice exists before bothering
		 * with the for loop.
		 */
		if (psaddr->adv != NO_ADVICE) {
			for (i = MADV_NORMAL; i <= MADV_PURGE; i++) {
				if ((psaddr->adv & (1 << i)) &&
				    (pr_madvise(Pr, (caddr_t)psaddr->addr,
				    psaddr->length, i) < 0)) {
					/*
					 * madvise(3C) call failed trying to
					 * apply advice output error and remove
					 * from advice list
					 */
					(void) fprintf(stderr,
					    gettext("Error applying "
					    "advice (%s) to memory range "
					    "[%lx, %lx):\n"),
					    advicestr[i], (ulong_t)psaddr->addr,
					    (ulong_t)psaddr->addr +
					    psaddr->length);
					perror("madvise");
					/*
					 * Clear this advice from the advice
					 * mask. If no more advice is given
					 * for this element, remove element
					 * from list.
					 */
					psaddr->adv &= ~(1 << i);
					if (psaddr->adv == 0) {
						delete_addr(advicelist, psaddr);
						break;
					}
				}
			}
		}
		psaddr = next;
	}
	return (0);
}

/*
 * Set advice but keep mutual exclusive property of advice groupings
 */
static void
set_advice(int *combined_adv, int new_adv) {
	/*
	 * Since advice falls in 3 groups of mutually exclusive options,
	 * clear previous value if new advice overwrites that group.
	 */

	/*
	 * If this is the first advice to be applied, clear invalid value (-1)
	 */
	if (*combined_adv == -1)
		*combined_adv = 0;

	if (new_adv & GRP1_ADV)
		*combined_adv &= ~GRP1_ADV;
	else if (new_adv & GRP2_ADV)
		*combined_adv &= ~GRP2_ADV;
	else
		*combined_adv &= ~GRP3_ADV;

	*combined_adv |= new_adv;
}

/*
 * Create chopped list from merged list for use with verbose output
 */
static void
create_choplist(saddr_t **choppedlist, saddr_t *mergedlist)
{
	saddr_t	*mlptr, *clptr;

	for (mlptr = mergedlist; mlptr != NULL; mlptr = mlptr->next) {
		clptr = malloc(sizeof (saddr_t));
		clptr->addr = mlptr->addr;
		clptr->length = 0;
		/*
		 * Initialize the adv to -1 as an indicator for invalid
		 * elements in the chopped list (created from gaps between
		 * memory maps).
		 */
		clptr->adv = -1;
		clptr->next = NULL;
		insert_addr(choppedlist, clptr, NODUPS);

		clptr = malloc(sizeof (saddr_t));
		clptr->addr = mlptr->addr + mlptr->length;
		clptr->length = 0;
		/*
		 * Again, initialize to -1 as an indicatorfor invalid elements
		 */
		clptr->adv = -1;
		clptr->next = NULL;
		insert_addr(choppedlist, clptr, NODUPS);
	}

	for (clptr = *choppedlist; clptr != NULL; clptr = clptr->next) {
		if (clptr->next) {
			clptr->length = clptr->next->addr - clptr->addr;
		} else {
			/*
			 * must be last element, now that we've calculated
			 * all segment lengths, we can remove this node
			 */
			delete_addr(choppedlist, clptr);
			break;
		}
	}

	for (mlptr = mergedlist; mlptr != NULL; mlptr = mlptr->next) {
		for (clptr = *choppedlist; clptr != NULL; clptr = clptr->next) {
			if (mlptr->addr <= clptr->addr &&
			    mlptr->addr + mlptr->length >=
			    clptr->addr + clptr->length)
				/*
				 * set_advice() will take care of conflicting
				 * advice by taking only the last advice
				 * applied for each of the 3 groups of advice.
				 */
				set_advice(&clptr->adv, mlptr->adv);
			if (mlptr->addr + mlptr->length <
			    clptr->addr)
				break;
		}
	}
}

/*
 * Print advice in pmap style for verbose output
 */
static void
print_advice(saddr_t *advlist, mapnode_t *maplist)
{
	saddr_t		*psaddr = advlist;
	mapnode_t	*pmapnode;
	char		*advice;

	pmapnode = maplist;

	while (psaddr) {
		/*
		 * Using indicator flag from create_choppedlist, we know
		 * which entries in the chopped_list are gaps and should
		 * not be printed.
		 */
		if (psaddr->adv == -1) {
			psaddr = psaddr->next;
			continue;
		}

		while (pmapnode && (pmapnode->pmp->pr_vaddr +
		    pmapnode->pmp->pr_size <= psaddr->addr))
			pmapnode = pmapnode->next;

		advice = advtostr(psaddr->adv);

		/*
		 * Print segment mapping and advice if there is any, or just a
		 * segment mapping.
		 */
		if (strlen(advice) > 0) {
			(void) printf("%.*lX %*uK %6s %s\t%s\n",
			    addr_width, (ulong_t)psaddr->addr, size_width - 1,
			    (int)ROUNDUP_KB(psaddr->length),
			    mflags(pmapnode->pmp->pr_mflags), pmapnode->label,
			    advice);
		} else {
			(void) printf("%.*lX %*uK %6s %s\n",
			    addr_width, (ulong_t)psaddr->addr, size_width - 1,
			    (int)ROUNDUP_KB(psaddr->length),
			    mflags(pmapnode->pmp->pr_mflags), pmapnode->label);
		}
		psaddr = psaddr->next;

	}
}

/*
 * Call madvise(3c) in the context of the target process
 */
static int
pr_madvise(struct ps_prochandle *Pr, caddr_t addr, size_t len, int advice)
{
	return (pr_memcntl(Pr, addr, len, MC_ADVISE,
	    (caddr_t)(uintptr_t)advice, 0, 0));
}

static char *
mflags(uint_t arg)
{
	static char code_buf[80];

	/*
	 * rwxsR
	 *
	 * r - segment is readable
	 * w - segment is writable
	 * x - segment is executable
	 * s - segment is shared
	 * R - segment is mapped MAP_NORESERVE
	 *
	 */
	(void) snprintf(code_buf, sizeof (code_buf), "%c%c%c%c%c ",
	    arg & MA_READ ? 'r' : '-',
	    arg & MA_WRITE ? 'w' : '-',
	    arg & MA_EXEC ? 'x' : '-',
	    arg & MA_SHARED ? 's' : '-',
	    arg & MA_NORESERVE ? 'R' : '-');

	return (code_buf);
}

/*
 * Convert advice to a string containing a commented list of applicable advice
 */
static char *
advtostr(int adv)
{
	static char buf[50];
	int i;

	*buf = '\0';

	if (adv != NO_ADVICE) {
		for (i = MADV_NORMAL; i <= MADV_PURGE; i++) {
			if (adv & (1 << i)) {
				/*
				 * check if it's the first advice entry
				 */
				if (*buf == '\0')
					(void) snprintf(buf, sizeof (buf) - 1,
					    "<= %s", advicestr[i]);
				else
					(void) snprintf(buf, sizeof (buf) - 1,
					    "%s,%s", buf, advicestr[i]);
			}
		}
	}

	return (buf);
}

/*
 * Handler for catching signals from terminal
 */
/* ARGSUSED */
static void
intr(int sig)
{
	interrupt++;
}

int
main(int argc, char **argv)
{
	int Fflag = 0;
	int rc = 0;
	int opt, subopt;
	int tmpadv;
	char	*options, *value;
	saddr_t	*psaddr;
	mapnode_t *pmapnode, *tempmapnode;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Get name of program for error messages
	 */
	progname = basename(argv[0]);

	/*
	 * Not much to do when only name of program given
	 */
	if (argc == 1)
		usage();

	/*
	 * Catch signals from terminal, so they can be handled asynchronously
	 * when we're ready instead of when we're not (;-)
	 */
	if (sigset(SIGHUP, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGHUP, intr);
	if (sigset(SIGINT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGINT, intr);
	if (sigset(SIGQUIT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGQUIT, intr);
	(void) sigset(SIGPIPE, intr);
	(void) sigset(SIGTERM, intr);

	/*
	 * Parse options, record generic advice if any and create
	 * rawadv_list from specific address advice.
	 */

	while ((opt = getopt(argc, argv, "Flo:v")) != EOF) {
		switch (opt) {
		case 'o':
			options = optarg;
			while (*options != '\0') {
				subopt = getsubopt(&options, suboptstr,
				    &value);
				switch (subopt) {
				case AT_PRIVM:
				case AT_HEAP:
				case AT_SHARED:
				case AT_STACK:
					at_map |= (1 << subopt);
					tmpadv = get_advice(value);
					set_advice(&generic_adv[subopt],
					    tmpadv);
					break;
				default:
					at_map |= (1 << AT_SEG);
					psaddr = parse_suboptions(value);
					if (psaddr == NULL) {
						usage();
					} else {
						insert_addr(&rawadv_list,
						    psaddr, YESDUPS);
					}
					break;
				}
			}
			break;
		case 'v':
			opt_verbose = 1;
			break;
		case 'F':		/* force grabbing (no O_EXCL) */
			Fflag = PGRAB_FORCE;
			break;
		case 'l':		/* show unresolved link map names */
			lflag = 1;
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc <= 0) {
		usage();
	}

	(void) proc_initstdio();

	/*
	 * Iterate through all pid arguments, create new merged_list, maplist,
	 * (and chopped_list if using verbose output) based on each process'
	 * memory map.
	 */

	while (!interrupt && argc-- > 0) {
		char *arg;
		int gcode;
		psinfo_t psinfo;

		(void) proc_flushstdio();

		if ((Pr = proc_arg_grab(arg = *argv++, PR_ARG_PIDS,
		    PGRAB_RETAIN | Fflag, &gcode)) == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: cannot examine %s: %s\n"),
			    progname, arg, Pgrab_error(gcode));
			rc++;
			continue;
		}


		addr_width =
		    (Pstatus(Pr)->pr_dmodel == PR_MODEL_LP64) ? 16 : 8;
		size_width =
		    (Pstatus(Pr)->pr_dmodel == PR_MODEL_LP64) ? 11 : 8;
		(void) memcpy(&psinfo, Ppsinfo(Pr), sizeof (psinfo_t));

		if (opt_verbose) {
			proc_unctrl_psinfo(&psinfo);
			(void) printf("%d:\t%.70s\n",
			    (int)psinfo.pr_pid, psinfo.pr_psargs);
		}

		/*
		 * Get mappings for a process unless it is a system process.
		 */
		if (!(Pstatus(Pr)->pr_flags & PR_ISSYS)) {
			nstacks = psinfo.pr_nlwp * 2;
			stacks = calloc(nstacks, sizeof (stacks[0]));
			if (stacks != NULL) {
				int n = 0;
				(void) Plwp_iter(Pr, getstack, &n);
				qsort(stacks, nstacks, sizeof (stacks[0]),
				    cmpstacks);
			}

			if (Pgetauxval(Pr, AT_BASE) != -1L &&
			    Prd_agent(Pr) == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: warning: "
				    "librtld_db failed to initialize; "
				    "shared library information will not "
				    "be available\n"),
				    progname);
			}

			/*
			 * Create linked list of mappings for current process
			 * In addition, add generic advice and raw advice
			 * entries to merged_list.
			 * e.g. if rawadv_list contains:
			 *   [0x38000,0x3a000) = adv1
			 *   [0x3a000,0x3c000) = adv2
			 * and there is generic advice:
			 *   heap = adv3
			 * where heap corresponds to 0x38000, then merged_list
			 * will contain:
			 *   ... (include all other mappings from process)
			 *   [0x38000,0x3c000) = adv3
			 *   [0x38000,0x3a000) = adv1
			 *   [0x3a000,0x3c000) = adv2
			 *   ... (include all other mappings from process)
			 */
			assert(merged_list == NULL);
			maplist_head = maplist_tail = NULL;
			rc += Pmapping_iter(Pr, (proc_map_f *)create_maplist,
			    NULL);

			/*
			 * Apply advice by iterating through merged list
			 */
			(void) apply_advice(&merged_list);

			if (opt_verbose) {
				assert(chopped_list == NULL);
				/*
				 * Create chopped_list from merged_list
				 */
				create_choplist(&chopped_list, merged_list);

				/*
				 * Iterate through maplist and output as
				 * given by chopped_list
				 */
				print_advice(chopped_list, maplist_head);
				delete_list(&chopped_list);
			}

			delete_list(&merged_list);

			/*
			 * Clear maplist
			 */
			pmapnode = maplist_head;
			while (pmapnode) {
				tempmapnode = pmapnode;
				pmapnode = pmapnode->next;
				free(tempmapnode);
			}

			if (stacks != NULL) {
				free(stacks);
				stacks = NULL;
			}
		}

		Prelease(Pr, 0);
	}

	(void) proc_finistdio();

	return (rc);
}
