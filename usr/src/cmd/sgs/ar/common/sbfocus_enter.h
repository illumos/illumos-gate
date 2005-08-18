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

#ifndef _SBFOCUS_ENTER_H
#define	_SBFOCUS_ENTER_H

#include <stdio.h>
#include <sys/param.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

/*
 * Datastructure that holds persistent data that sbfocus_symbol & sbfocus_close
 * needs. Passing in a pointer to this struct makes them re-entrant.
 */
typedef struct Sbld_tag *Sbld, Sbld_rec;

struct Sbld_tag {
	FILE	*fd;
	int	failed;
};

/*
 * fragment of SunOS <machine/a.out.h>
 *         Format of a symbol table entry
 */
struct nlist {
	union {
		char *n_name;	/* for use when in-core */
		long n_strx;	/* index into file string table */
	} n_un;
	unsigned char  n_type;	/* type flag (N_TEXT...) */
	char	n_other;	/* unused */
	short	n_desc;	/* see <stab.h> */
	unsigned long  n_value;	/* value of symbol (or sdb offset) */
};

void sbfocus_symbol(Sbld data, char *name, char *type, char *symbol);
void sbfocus_close(Sbld data);

Sbld_rec   sb_data;
#endif	/* _SBFOCUS_ENTER_H */
