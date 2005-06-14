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

#ifndef	_POOLSTAT_H
#define	_POOLSTAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following are types and defines used to collect statistic data.
 * Different statistic providers can be used to collect the data.
 * Two functions build the interface to each provider:
 * 'provider'_init(), and 'provider'_update(). In the update function
 * a provider fills out the passed data structure with statistics data
 * it is responsible for.
 */

/* Error messages for poolstat */
#define	ERR_LOAD_AVERAGE 	"cannot get load average: %s\n"
#define	ERR_BINDING		"cannot get resource binding: %s\n"
#define	ERR_STATS_POOL_N	"cannot get statistics for pool '%s'\n"
#define	ERR_STATS_RES_N		"cannot get statistics for resource '%s': %s\n"
#define	ERR_STATS_POOL		"cannot get pool statistics: %s\n"
#define	ERR_STATS_RES		"cannot get resource statistics: %s\n"
#define	ERR_STATS_FORMAT	"cannot format statistic line: %s\n"
#define	ERR_KSTAT_OPEN		"kstat open failed: %s\n"
#define	ERR_KSTAT_DATA		"cannot get kstat data: %s\n"
#define	ERR_KSTAT_DLOOKUP	"kstat_data_lookup('%s', '%s') failed: %s\n"
#define	ERR_OPTION_ARGS		"Option -%c requires an argument\n"
#define	ERR_OPTION		"poolstat: illegal option -- %c\n"
#define	ERR_CONF_UPDATE		"pool configuration update failed: %s\n"
#define	ERR_UNSUPP_STYPE	"unsupported statistic type: %s\n"
#define	ERR_UNSUPP_RTYPE	"unsupported resource type: %s\n"
#define	ERR_UNSUPP_STAT_FIELD	"unsupported statistic field: %s\n"

#define	POOL_TYPE_NAME 	"pool"
#define	PSET_TYPE_NAME 	"pset"
#define	POOL_SYSID	"pool.sys_id"
#define	PSET_SYSID	"pset.sys_id"

/* set types */
typedef enum { ST_PSET } st_t;

/* update flag, forces refresh of statistic data	*/
#define	SA_REFRESH	1

/* data bag used to collect statistics for a processor set	*/
typedef struct {
	int64_t 	pset_sb_sysid;
	uint64_t 	pset_sb_min;
	uint64_t 	pset_sb_max;
	uint64_t 	pset_sb_size;
	double  	pset_sb_used;
	double		pset_sb_load;
	uint64_t	pset_sb_changed;
} pset_statistic_bag_t;

/* wrapper for different statistic bags	*/
typedef struct {
	const char *sb_name;	/* pool or resource name used as identifier */
	int64_t    sb_sysid; 	/* the sysid 	*/
	const char *sb_type;	/* the type can be "pool", or "pset"	*/
	uint64_t   sb_changed;
	void* bag;
} statistic_bag_t;

/* shortcut to access a element in the pset statistic bag.	*/
#define	PSETBAG_ELEM(p, e) (((pset_statistic_bag_t *)(p)->bag)->e)

/* statistic adapters	*/
extern void sa_libpool_init(void *);
extern void sa_libpool_update(statistic_bag_t *sbag, int flags);
extern void sa_kstat_init(void *);
extern void sa_kstat_update(statistic_bag_t *sbag, int flags);

/*
 * The following types and defines are used to format statistic lines.
 * All formatting information for a particular line are grouped in 'lf_t'
 * structure.
 * Two data sequences are anchored there: an array with all possible formatting
 * directives for fields that can occur in a statistic line, and a list with
 * pointers to elements in this array. This list defines which fields and in
 * which order should be printed.
 * Formatting directives for one field are grouped in 'poolstat_field_format_t'
 * structure. Basically it contains a pointer to a formatting function and some
 * formatting parameters used by this function.
 */

/* the length of a statistic line	*/
#define	MAXLINE 160
/* default print field 		*/
#define	D_FIELD	0x01
/* -x option print field 	*/
#define	X_FIELD	0x02
/* -o option print field 	*/
#define	O_FIELD	0x04

/* print field in default and extended mode */
#define	DX_FIELD	(D_FIELD | X_FIELD)

/* marks a field as printable	*/
#define	PABLE_FIELD	0x80

#define	KILO 1000
#define	MEGA ((uint64_t)(KILO * 1000))
#define	GIGA ((uint64_t)(MEGA * 1000))
#define	TERA ((uint64_t)(GIGA * 1000))
#define	PETA ((uint64_t)(TERA * 1000))
#define	EXA  ((uint64_t)(PETA * 1000))

#define	KBYTE 1024
#define	MBYTE ((uint64_t)(KBYTE * 1024))
#define	GBYTE ((uint64_t)(MBYTE * 1024))
#define	TBYTE ((uint64_t)(GBYTE * 1024))
#define	PBYTE ((uint64_t)(TBYTE * 1024))
#define	EBYTE ((uint64_t)(PBYTE * 1024))

/* statistic data types */
typedef enum { ULL, LL, FL, STR } dt_t;

/* poolstat_field_format_t contains information for one statistic field */
typedef struct poolstat_field_format {
	int		pff_prt;	/* printable flag		*/
	const char 	*pff_name;	/* name of the statistic	*/
	const char 	*pff_header;
	const dt_t	pff_type;	/* the data type		*/
	int		pff_width;	/* width, excluding whitespace	*/
	const int	pff_minwidth;
	char		**pff_data_ptr;
	const size_t	pff_offset;	/* offset in a data block	*/
	/* formatter */
	int (* pff_format)
		(char *, int, int, struct poolstat_field_format *, char *);
} poolstat_field_format_t;

/* list element, used to link arbitrary objects in a list */
typedef struct _myself {
	void		*ple_obj;
	struct _myself	*ple_next;
} poolstat_list_element_t;

/*
 * poolstat_line_format_t contains formatting information for one
 * statistics line.
 */
typedef struct {
	/* pointer to an array with all format fields */
	poolstat_field_format_t *plf_ffs;
	/* the lenght of format field array	*/
	int	plf_ff_len;
	/* the field's print sequence		*/
	poolstat_list_element_t  *plf_prt_seq;
	/* pointer to the last field in prt. sequence */
	poolstat_list_element_t  *plf_last;
} poolstat_line_format_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _POOLSTAT_H */
