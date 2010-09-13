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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__SHIM_H
#define	__SHIM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * DESCRIPTION: Shim header information not relating to hooks
 *
 */

/*
 * Structure for holding all the information relating to one map. These will
 * probably end up in shared memory so everyone can get at them.
 *
 * DBM pointers are non NULL only while the file is open.
 */
typedef struct {
	/* These are used in all modes */
	DBM	*entries;	/* NIS entry DBM file */
	int	hash_val;	/* Hash of name (to save repeated rehashing) */

	/*
	 * Names.
	 *
	 * There is some duplication of information here but this enables these
	 * strings to be worked out once (when the map_ctrl is created) rather
	 * than many times as it is used.
	 */
	char	*map_name;	/* Name of map, unqualified */
	char	*domain;	/* Domain name */
	char 	*map_path;	/* Full qualified path to map */

	/* These are used only in N2L mode */
	DBM	*ttl;		/* TTL DBM file */
	char	*ttl_path;	/* Full qualified path to TTL file */
	char	*trad_map_path;	/* Equivalent qualified traditional map name */
	datum	key_data;	/* See NOTE at top of shim.c */

	/* Open parameters (in case of reopen ) */
	mode_t	open_mode;
	int	open_flags;

	int	magic;		/* Check that this really is a map_ctrl */

}map_ctrl;
#define	MAP_MAGIC	0x09876543

/*
 * Structure for holding unique map IDs.
 * Used for locking purposes, in N2L mode only.
 */
typedef struct map_id_elt {
	char *map_name;
	int map_id;
	struct map_id_elt *next;
} map_id_elt_t;

/*
 * Success and failure codes the same as used by DBM
 */
typedef int suc_code;
#define	SUCCESS 0
#define	FAILURE -1

/*
 * Extern defs for new DBM calls. Must have identical args to traditional
 * version.
 */
extern void 	shim_dbm_close(DBM *db);
extern int 	shim_dbm_delete(DBM *db, datum key);
extern datum 	shim_dbm_fetch(DBM *db, datum key);
extern datum 	shim_dbm_fetch_noupdate(DBM *db, datum key);
extern datum	shim_dbm_firstkey(DBM *db);
extern datum 	shim_dbm_nextkey(DBM *db);
extern DBM 	*shim_dbm_open(const  char  *file,  int  open_flags,
				mode_t file_mode);
extern int  	shim_dbm_store(DBM  *db,  datum  key,  datum  content,
				int store_mode);

/*
 * Other externs
 */
extern map_ctrl *get_map_ctrl(DBM *);
extern map_ctrl *create_map_ctrl(char *);
extern void 	free_map_ctrl(map_ctrl *);
extern map_ctrl *dup_map_ctrl(map_ctrl *);
extern void 	dump_map_ctrl(map_ctrl *);
extern suc_code map_ctrl_init(map_ctrl *map, char *name);
extern int	lock_map_ctrl(map_ctrl *map);
extern int	unlock_map_ctrl(map_ctrl *map);
extern int	map_id_list_init();
extern void	get_list_max(map_id_elt_t ***list, int *max);

extern int	try_lock_map_update(map_ctrl *map);
extern suc_code lock_map_update(map_ctrl *map);
extern suc_code unlock_map_update(map_ctrl *map);
extern bool_t init_update_lock_map();

/*
 * Globals
 */
extern bool_t yptol_mode;
extern bool_t yptol_newlock;
extern bool_t ypxfrd_flag;
extern int yp2ldap;

/*
 * String extensions used in N2L
 */

/* Prefix used for N2L map names */
#define	NTOL_PREFIX "LDAP_"

/* Postfix used for TTL DBM files */
#define	TTL_POSTFIX "_TTL"

/* Postfix for temporary files */
#define	TEMP_POSTFIX "_TMP"

/* File separator character. If this is defined elsewhere can be removed */
#define	SEP_CHAR '/'

/*
 * Special keys used in DBM files. No real NIS map can use these keys.
 */
#define	MAP_EXPIRY_KEY "YP_EXPIRY_TIME"
#define	MAP_OLD_MAP_DATE_KEY "YP_OLD_MAP_DATE_TIME"

/* Mmaped file used for update flags shared memory */
#define	SHM_FILE "/var/run/nis_shim"

/* used for map arrays reallocation purposes */
#define	ARRAY_CHUNK	10

#ifdef	__cplusplus
}
#endif

#endif	/* __SHIM_H */
