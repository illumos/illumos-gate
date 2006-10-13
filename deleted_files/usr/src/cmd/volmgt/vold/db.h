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
 * Copyright (c) 1992 by Sun Microsystems, Inc.
 */

#ifndef	__DB_H
#define	__DB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct dbops {
	void	(*dop_lookup)(vvnode_t *);
	void	(*dop_root)();
	bool_t	(*dop_update)(obj_t *);
	bool_t	(*dop_add)(obj_t *);
	bool_t	(*dop_remove)(obj_t *);
	vol_t	*(*dop_findlabel)(char *, label *);
	bool_t	(*dop_testkey)(char *, char *, char *);
	char	*dop_name;
	int	dop_pad[10];
};

/*
 * Database working operations.
 */
void 	db_lookup(vvnode_t *);
void	db_root();
bool_t 	db_update(obj_t *);
bool_t 	db_add(obj_t *);
bool_t 	db_remove(obj_t *);
vol_t	*db_findlabel(char *, label *);
bool_t	db_testkey(char *, char *, char *);
int	db_configured_cnt(void);

/*
 * Database initialization operations.
 */
int	db_load(char *);		/* load a new database object */
void	db_new(struct dbops *);		/* link in a dbops structure */

#define	DB_SYM	"db_init"

#ifdef	__cplusplus
}
#endif

#endif /* __DB_H */
