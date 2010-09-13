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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _IDMAP_ENGINE_H
#define	_IDMAP_ENGINE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Debug macros */
#define	DPTR(a) printf("%s::%d  %s = %p\n", __FILE__, __LINE__, #a, a);
#define	DSTRING(a) printf("%s::%d  %s = \"%s\"\n", __FILE__, __LINE__, #a, \
			a ? a : "(null)");
#define	DINT(a) printf("%s::%d  %s = %d\n", __FILE__, __LINE__, #a, a);
#define	DHEX(a) printf("%s::%d  %s = %X\n", __FILE__, __LINE__, #a, a);

#ifdef __cplusplus
extern "C" {
#endif

typedef char *flag_t;
#define	FLAG_SET (char *)1
#define	FLAG_ALPHABET_SIZE 255

#define	IDMAP_ENG_OK 0
#define	IDMAP_ENG_ERROR -1
#define	IDMAP_ENG_ERROR_SILENT -2

typedef struct cmd_pos {
	int linenum;		/* line number */
	char *line;		/* line content */
} cmd_pos_t;


typedef struct cmd_ops {
	const char *cmd;	/* the subcommand */
	const char *options;	/* getopt string for the subcommand params */
	int (*p_do_func)(flag_t *f,
	    int argc,
	    char **argv,
	    cmd_pos_t *pos); /* handle */
} cmd_ops_t;

extern int engine_init(int comc, cmd_ops_t *comv, int argc, char **argv,
    int *is_batch_mode);
extern int engine_fini();

extern int run_engine(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif	/* _IDMAP_ENGINE_H */
