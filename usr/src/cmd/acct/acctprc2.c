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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *	acctprc2 <ptmp1 >ptacct
 *	reads std. input (in ptmp.h/ascii format)
 *	hashes items with identical uid/name together, sums times
 *	sorts in uid/name order, writes tacct.h records to output
 */

#include <sys/types.h>
#include <sys/param.h>
#include "acctdef.h"
#include <stdio.h>
#include <string.h>
#include <search.h>
#include <stdlib.h>

struct	ptmp	pb;
struct	tacct	tb;

struct	utab	{
	uid_t	ut_uid;
	char	ut_name[NSZ];
	float	ut_cpu[2];	/* cpu time (mins) */
	float	ut_kcore[2];	/* kcore-mins */
	long	ut_pc;		/* # processes */
} * ub;

static	int usize;
void **root = NULL;

void output(void);
void enter(struct ptmp *);

int
main(int argc, char **argv)
{

	while (scanf("%ld\t%s\t%lu\t%lu\t%u",
		&pb.pt_uid,
		pb.pt_name,
		&pb.pt_cpu[0], &pb.pt_cpu[1],
		&pb.pt_mem) != EOF)
			enter(&pb);
	output();
	exit(0);
}

int node_compare(const void *node1, const void *node2)
{
	if (((const struct utab *)node1)->ut_uid > \
		((const struct utab *)node2)->ut_uid)
		return(1);
	else if (((const struct utab *)node1)->ut_uid < \
		((const struct utab *)node2)->ut_uid)
		return(-1);
	else	return(strcmp(((const struct utab *) node1)->ut_name,
			((const struct utab *) node2)->ut_name));
	
}

void
enter(struct ptmp *p)
{
	unsigned int i;
	double memk;
	struct utab **pt;
 
	/* clear end of short users' names */
	for(i = strlen(p->pt_name) + 1; i < NSZ; p->pt_name[i++] = '\0') ;

	if ((ub = (struct utab *)malloc(sizeof (struct utab))) == NULL) {
		fprintf(stderr, "acctprc2: malloc fail!\n");
		exit(2);
	}

	ub->ut_uid = p->pt_uid;
	CPYN(ub->ut_name, p->pt_name);
	ub->ut_cpu[0] = MINT(p->pt_cpu[0]);
	ub->ut_cpu[1] = MINT(p->pt_cpu[1]);
	memk = KCORE(pb.pt_mem);
	ub->ut_kcore[0] = memk * MINT(p->pt_cpu[0]);
	ub->ut_kcore[1] = memk * MINT(p->pt_cpu[1]);
	ub->ut_pc = 1;
 
	if (*(pt = (struct utab **)tsearch((void *)ub, (void **)&root,  \
		node_compare)) == NULL) {
		fprintf(stderr, "Not enough space available to build tree\n");
		exit(1);
	}
	
	if (*pt != ub) {
		(*pt)->ut_cpu[0] += MINT(p->pt_cpu[0]);
		(*pt)->ut_cpu[1] += MINT(p->pt_cpu[1]);
		(*pt)->ut_kcore[0] += memk * MINT(p->pt_cpu[0]);
		(*pt)->ut_kcore[1] += memk * MINT(p->pt_cpu[1]);
		(*pt)->ut_pc++;
		free(ub);
	}
}

void print_node(const void *node, VISIT order, int level) {
        if (order == postorder || order == leaf) {
                tb.ta_uid = (*(struct utab **)node)->ut_uid;
                CPYN(tb.ta_name, (*(struct utab **)node)->ut_name);
                tb.ta_cpu[0] = ((*(struct utab **)node)->ut_cpu[0]);
                tb.ta_cpu[1] = ((*(struct utab **)node)->ut_cpu[1]);
                tb.ta_kcore[0] = (*(struct utab **)node)->ut_kcore[0];
                tb.ta_kcore[1] = (*(struct utab **)node)->ut_kcore[1];
                tb.ta_pc = (*(struct utab **)node)->ut_pc;
                fwrite(&tb, sizeof(tb), 1, stdout);
        }
}

void
output(void)
{
                twalk((struct utab *)root, print_node);
}
