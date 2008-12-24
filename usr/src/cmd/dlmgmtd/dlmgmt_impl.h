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
 * Functions to maintain a table of datalink configuration information.
 */

#ifndef	_DLMGMT_IMPL_H
#define	_DLMGMT_IMPL_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <door.h>
#include <libdllink.h>

/*
 * datalink attribute structure
 */
typedef struct dlmgmt_linkattr_s {
	struct dlmgmt_linkattr_s	*lp_next;
	struct dlmgmt_linkattr_s	*lp_prev;
	char				lp_name[MAXLINKATTRLEN];
	void				*lp_val;
	dladm_datatype_t		lp_type;
	uint_t				lp_sz;
} dlmgmt_linkattr_t;

/*
 * datalink structure
 */
typedef struct dlmgmt_link_s {
	dlmgmt_linkattr_t	*ll_head;
	char			ll_link[MAXLINKNAMELEN];
	datalink_class_t	ll_class;
	uint32_t		ll_media;
	datalink_id_t		ll_linkid;
	avl_node_t		ll_node_by_name;
	avl_node_t		ll_node_by_id;
	uint32_t		ll_flags;
	uint32_t		ll_gen;		/* generation number */
} dlmgmt_link_t;

/*
 * datalink configuration request structure
 */
typedef struct dlmgmt_dlconf_s {
	dlmgmt_linkattr_t	*ld_head;
	char			ld_link[MAXLINKNAMELEN];
	datalink_id_t		ld_linkid;
	datalink_class_t	ld_class;
	uint32_t		ld_media;
	int			ld_id;
	uint32_t		ld_gen;
	avl_node_t		ld_node;
} dlmgmt_dlconf_t;

extern boolean_t	debug;
extern const char	*progname;
extern dladm_handle_t	dld_handle;

extern avl_tree_t	dlmgmt_name_avl;
extern avl_tree_t	dlmgmt_id_avl;
extern avl_tree_t	dlmgmt_dlconf_avl;

boolean_t	linkattr_equal(dlmgmt_linkattr_t **, const char *, void *,
		    size_t);
int		linkattr_unset(dlmgmt_linkattr_t **, const char *);
int		linkattr_set(dlmgmt_linkattr_t **, const char *, void *,
		    size_t, dladm_datatype_t);
int		linkattr_get(dlmgmt_linkattr_t **, const char *, void **,
		    size_t *, dladm_datatype_t *);

void		link_destroy(dlmgmt_link_t *);
dlmgmt_link_t	*link_by_id(datalink_id_t);
dlmgmt_link_t	*link_by_name(const char *);
int		dlmgmt_create_common(const char *, datalink_class_t,
		    uint32_t, uint32_t, dlmgmt_link_t **);
int		dlmgmt_destroy_common(dlmgmt_link_t *, uint32_t);
void		dlmgmt_getattr_common(dlmgmt_linkattr_t **, const char *,
		    dlmgmt_getattr_retval_t *);

void		dlmgmt_advance(dlmgmt_link_t *);
void		dlmgmt_table_lock(boolean_t);
void		dlmgmt_table_unlock();

int		dlconf_create(const char *, datalink_id_t, datalink_class_t,
		    uint32_t, dlmgmt_dlconf_t **);
void		dlconf_destroy(dlmgmt_dlconf_t *);
void		dlmgmt_advance_dlconfid(dlmgmt_dlconf_t *);
void		dlmgmt_dlconf_table_lock(boolean_t);
void		dlmgmt_dlconf_table_unlock(void);

int		dlmgmt_generate_name(const char *, char *, size_t);

int		dlmgmt_linktable_init(void);
void		dlmgmt_linktable_fini(void);

void		dlmgmt_handler(void *, char *, size_t, door_desc_t *, uint_t);
void		dlmgmt_log(int, const char *, ...);
int		dlmgmt_write_db_entry(datalink_id_t, uint32_t);
int		dlmgmt_delete_db_entry(datalink_id_t, uint32_t);
int 		dlmgmt_db_init(void);

#define	DLMGMT_TMPFS_DIR	"/etc/svc/volatile/dladm"

#ifdef  __cplusplus
}
#endif

#endif	/* _DLMGMT_IMPL_H */
