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

#ifndef	_NSCD_DB_H
#define	_NSCD_DB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nss_dbdefs.h>		/* nssuint_t */
#include "nscd_common.h"

/* make a pointer 8-byte aligned, or an integer a multiple of 8 */
#define	roundup(x)	(((unsigned long)(x)+7) & ~7)

/*
 * type of nscd data
 */
#define	NSCD_DATA_UNKNOWN		0
#define	NSCD_DATA_NSW_CONFIG		1
#define	NSCD_DATA_NSW_STATE_BASE	2
#define	NSCD_DATA_GETENT_CTX_BASE	3
#define	NSCD_DATA_BACKEND_INFO		4
#define	NSCD_DATA_BACKEND_INFO_DB	5
#define	NSCD_DATA_CFG_NSW_DB_INDEX	6
#define	NSCD_DATA_CFG_NSW_SRC_INDEX	7
#define	NSCD_DATA_CFG_PARAM_INDEX	8
#define	NSCD_DATA_CFG_STAT_INDEX	9
#define	NSCD_DATA_ADDR			127
#define	NSCD_DATA_CTX_ADDR		128

/*
 * database operation options
 */
typedef enum {
	NSCD_GET_FIRST_DB_ENTRY		= 1,
	NSCD_GET_NEXT_DB_ENTRY		= 2,
	NSCD_GET_EXACT_DB_ENTRY		= 3,
	NSCD_ADD_DB_ENTRY_FIRST		= 4,
	NSCD_ADD_DB_ENTRY_LAST		= 5,
	NSCD_ADD_DB_ENTRY_REPLACE	= 6,
	NSCD_ADD_DB_ENTRY_IF_NONE	= 7,
	NSCD_DEL_FIRST_DB_ENTRY		= 8,
	NSCD_DEL_ALL_DB_ENTRY		= 9,
	NSCD_DEL_EXACT_DB_ENTRY		= 10
} nscd_db_option_t;

/*
 * This structure defines an instance of the
 * nscd database entry.
 */
typedef struct nscd_db_entry {
	int			type;
	int			id_num;
	int			num_data;
	int			num_array;
	char			*name;
	void			**data_array;
} nscd_db_entry_t;

/*
 * sequence number attached to nscd data
 */
typedef	nssuint_t nscd_seq_num_t;
typedef nssuint_t nscd_cookie_num_t;

/*
 * The nscd_access_s datatype represents a nscd
 * access data structure. It is an opaque structure.
 */
struct nscd_access_s;
typedef struct nscd_access_s	nscd_access_t;
struct nscd_acc_data_s;
typedef struct nscd_acc_data_s	nscd_acc_data_t;

/*
 * The nscd_db_t datatype represents a nscd
 * database. It is also an opaque structure.
 */
struct nscd_db_s;
typedef struct nscd_db_s	nscd_db_t;

/*
 * four sizes for a nscd database:
 * large, medium, small, tiny
 */
#define	NSCD_DB_SIZE_LARGE	1
#define	NSCD_DB_SIZE_MEDIUM	2
#define	NSCD_DB_SIZE_SMALL	3
#define	NSCD_DB_SIZE_TINY	4

/*
 * options for _nscd_alloc()
 */
#define	NSCD_ALLOC_MUTEX	0x0001
#define	NSCD_ALLOC_RWLOCK	0x0002
#define	NSCD_ALLOC_COND		0x0004

/*
 * prototypes
 */
nscd_seq_num_t
_nscd_get_seq_num();

nscd_cookie_num_t
_nscd_get_cookie_num();

nscd_acc_data_t *
_nscd_get(
	nscd_acc_data_t		*data);

nscd_acc_data_t
*_nscd_set(
	nscd_acc_data_t		*old,
	nscd_acc_data_t		*new);

void
_nscd_release(
	nscd_acc_data_t		*data);

nscd_acc_data_t
*_nscd_rdlock(
	nscd_acc_data_t		*data);

nscd_acc_data_t
*_nscd_wrlock(
	nscd_acc_data_t		*data);

void
_nscd_rw_unlock(
	nscd_acc_data_t		*data);

void
_nscd_rw_unlock_no_release(
	nscd_acc_data_t		*data);

nscd_acc_data_t
*_nscd_mutex_lock(
	nscd_acc_data_t		*data);

void
_nscd_mutex_unlock(
	nscd_acc_data_t		*data);

void
_nscd_cond_signal(
	nscd_acc_data_t		*data);

void
_nscd_cond_wait(
	nscd_acc_data_t		*data,
	cond_t			*cond);

nscd_acc_data_t *
_nscd_alloc(
	int			type,
	size_t			size,
	void			(*data_free)(
				nscd_acc_data_t *data),
	int			option);

nscd_rc_t
_nscd_add_int_addr(
	void 			*ptr,
	int 			type,
	nscd_seq_num_t		seq_num);

rwlock_t *
_nscd_is_int_addr(
	void 			*ptr,
	nscd_seq_num_t		seq_num);

void
_nscd_del_int_addr(
	void 			*ptr,
	nscd_seq_num_t		seq_num);

nscd_db_t *
_nscd_alloc_db(
	int			size);

void
_nscd_free_db(
	nscd_db_t		*db);

nscd_db_entry_t *
_nscd_alloc_db_entry(
	int			type,
	const char 		*name,
	int			dataSize,
	int			num_data,
	int			num_array);

const nscd_db_entry_t *
_nscd_get_db_entry(
	const nscd_db_t		*db,
	int			type,
	const char		*str,
	nscd_db_option_t	option,
	int			id_num);

nscd_rc_t
_nscd_add_db_entry(
	nscd_db_t		*db,
	const char 		*str,
	nscd_db_entry_t		*entry,
	nscd_db_option_t	option);

nscd_rc_t
_nscd_delete_db_entry(
	nscd_db_t		*db,
	int			type,
	const char		*str,
	nscd_db_option_t	option,
	int			id_num);


void *
_nscd_create_int_addrDB();

void
_nscd_destroy_int_addrDB();

#ifdef	__cplusplus
}
#endif

#endif	/* _NSCD_DB_H */
