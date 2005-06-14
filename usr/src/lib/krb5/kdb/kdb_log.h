/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_KDB_LOG_H
#define	_KDB_LOG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <k5-int.h>
#include <iprop_hdr.h>
#include <iprop.h>
#include <limits.h>
#include <kadm5/admin.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * DB macros
 */
#define	INDEX(ulogaddr, i) ((ulong_t) ulogaddr + sizeof (kdb_hlog_t) + \
	(i*ulog->kdb_block))

/*
 * Current DB version #
 */
#define	KDB_VERSION	1

/*
 * DB log states
 */
#define	KDB_STABLE	1
#define	KDB_UNSTABLE	2
#define	KDB_CORRUPT	3

/*
 * DB log constants
 */
#define	KDB_UMAGIC	0x6661212
#define	KDB_HMAGIC	0x6662323

/*
 * DB Flags
 */
#define	FKADMIND	1
#define	FKPROPLOG	2
#define	FKPROPD		3
#define	FKCOMMAND	4	/* Includes kadmin.local and kdb5_util */

/*
 * Default ulog file attributes
 */
#define	ULOG_FILE	"/var/krb5/principal.ulog"
#define	MAX_FILENAME	(PATH_MAX + 1)
#define	MAX_ULOGENTRIES	2500
#define	DEF_ULOGENTRIES	1000
#define	ULOG_IDLE_TIME	10		/* in seconds */
/*
 * Max size of update entry + update header
 * We make this large since resizing can be costly.
 */
#define	ULOG_BLOCK	2048		/* Default size of principal record */

#define	MAXLOGLEN	0x10000000	/* 256 MB log file */

/*
 * Prototype declarations
 */
extern krb5_error_code ulog_map(krb5_context context,
	kadm5_config_params *params, int caller);
extern krb5_error_code ulog_add_update(krb5_context context,
	kdb_incr_update_t *upd);
extern krb5_error_code ulog_delete_update(krb5_context context,
	kdb_incr_update_t *upd);
extern krb5_error_code ulog_finish_update(krb5_context context,
	kdb_incr_update_t *upd);
extern krb5_error_code ulog_get_entries(krb5_context context, kdb_last_t last,
	kdb_incr_result_t *ulog_handle);
extern krb5_error_code ulog_replay(krb5_context context,
	kdb_incr_result_t *incr_ret);
extern krb5_error_code ulog_conv_2logentry(krb5_context context,
	krb5_db_entry *entries, kdb_incr_update_t *updates, int nentries);
extern krb5_error_code ulog_conv_2dbentry(krb5_context context,
	krb5_db_entry *entries, kdb_incr_update_t *updates, int nentries);
extern void ulog_free_entries(kdb_incr_update_t *updates, int no_of_updates);
extern krb5_error_code ulog_set_role(krb5_context ctx, iprop_role role);

typedef struct kdb_hlog {
	uint32_t	kdb_hmagic;	/* Log header magic # */
	uint16_t	db_version_num;	/* Kerberos database version no. */
	uint32_t	kdb_num;	/* # of updates in log */
	kdbe_time_t	kdb_first_time;	/* Timestamp of first update */
	kdbe_time_t	kdb_last_time;	/* Timestamp of last update */
	kdb_sno_t	kdb_first_sno;	/* First serial # in the update log */
	kdb_sno_t	kdb_last_sno;	/* Last serial # in the update log */
	uint16_t	kdb_state;	/* State of update log */
	uint16_t	kdb_block;	/* Block size of each element */
} kdb_hlog_t;

typedef struct kdb_ent_header {
	uint32_t	kdb_umagic;	/* Update entry magic # */
	kdb_sno_t	kdb_entry_sno;	/* Serial # of entry */
	kdbe_time_t	kdb_time;	/* Timestamp of update */
	bool_t		kdb_commit;	/* Is the entry committed or not */
	uint32_t	kdb_entry_size;	/* Size of update entry */
	uchar_t		entry_data[4];	/* Address of kdb_incr_update_t */
} kdb_ent_header_t;

typedef struct _kdb_log_context {
	iprop_role	iproprole;
	kdb_hlog_t	*ulog;
	uint32_t	ulogentries;
	int		ulogfd;
} kdb_log_context;

#ifdef	__cplusplus
}
#endif

#endif	/* !_KDB_LOG_H */
