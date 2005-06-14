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

#ifndef	_PICLDEVTREE_H
#define	_PICLDEVTREE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "picldefs.h"

#define	DEVICE_TYPE_BLOCK	"block"
#define	DEVICE_TYPE_BYTE	"byte"
#define	DEVICE_TYPE_DISK	"disk"
#define	DEVICE_TYPE_SES		"ses"
#define	DEVICE_TYPE_FP		"fp"

#define	HASH_TABLE_SIZE		64
#define	HASH_INDEX(s, x)	((int)((x) & ((s) - 1)))

#define	MAX_NAMEVAL_SIZE	80
#define	CONFFILE_LINELEN_MAX	1024

#define	KSTAT_STATE_BEGIN	"state_begin"
#define	KSTAT_CPU_INFO		"cpu_info"
#define	ASR_DISABLED		"disabled"
#define	ASR_FAILED		"failed"

#define	DEVTREE_CONFFILE_NAME		"picldevtree.conf"
#define	ASRTREE_CONFFILE_NAME		"picl_asr.conf"
#define	CONFFILE_COMMENT_CHAR		'#'

/*
 * Constants
 */
#define	FFB_MANUF_BUFSIZE	256
#define	SUPPORTED_NUM_CELL_SIZE	2	/* #size-cells */
#define	MAX_STATE_SIZE			32

/*
 * Hash table structure
 */
typedef struct hash_elem {
	picl_nodehdl_t		hdl;
	struct hash_elem	*next;
} hash_elem_t;

typedef struct {
	int			hash_size;
	hash_elem_t		**tbl;
} hash_t;

/*
 * name to class map entries in the conf file
 */
typedef struct conf_entries {
	char			*name;
	char			*piclclass;
	struct conf_entries	*next;
} conf_entries_t;

/*
 * name to address to class map for asr2
 */
typedef struct asr_conf_entries {
	char			*name;
	char			*piclclass;
	char			*status;
	char			*address;
	char			*props;
	struct asr_conf_entries	*next;
} asr_conf_entries_t;

/*
 * type, name, val property triplet for asr2
 */
typedef struct asr_prop_triplet {
	char			*proptype;
	char			*propname;
	char			*propval;
} asr_prop_triplet_t;

/*
 * built-in name to class mapping table
 */
typedef struct {
	char	name[MAX_NAMEVAL_SIZE];
	char	piclclass[PICL_CLASSNAMELEN_MAX];
} builtin_map_t;

/*
 * property name to type mapping table
 */
typedef struct {
	char	pname[PICL_PROPNAMELEN_MAX];
	int	type;
} pname_type_map_t;

/* known values for manufacturer's JED code */
#define	MANF_BROOKTREE		214
#define	MANF_MITSUBISHI		28
#define	FFB_NAME		"ffb"
#define	FFBIOC			('F' << 8)
#define	FFB_SYS_INFO		(FFBIOC| 80)

/* FFB strap reg union */
typedef union {
	struct {
		uint32_t	unused:24;
		uint32_t	afb_flag:1;
		uint32_t	major_rev:2;
		uint32_t	board_rev:2;
		uint32_t	board_mem:1;
		uint32_t	cbuf:1;
		uint32_t	bbuf:1;
	} fld;
	uint32_t		ffb_strap_bits;
} strap_un_t;

/* FFB mnufacturer union */
typedef union {
	struct {
		uint32_t	version:4;	/* version of part number */
		uint32_t	partno:16;	/* part number */
		uint32_t	manf:11;	/* manufacturer's JED code */
		uint32_t	one:1;		/* always set to '1' */
	} fld;
	uint32_t		encoded_id;
} manuf_t;

typedef struct ffb_sys_info {
	strap_un_t	ffb_strap_bits;	/* ffb_strapping register	*/
	manuf_t		fbc_version;	/* revision of FBC chip		*/
	manuf_t		dac_version;	/* revision of DAC chip		*/
	manuf_t		fbram_version;	/* revision of FBRAMs chip	*/
	uint32_t	flags;		/* miscellaneous flags		*/
	uint32_t	afb_nfloats;	/* no. of Float asics in AFB	*/
	uint32_t	pad[58];	/* padding for AFB chips & misc. */
} ffb_sys_info_t;

typedef struct memspecs {
	uint32_t physlo;
	uint32_t physhi;
	uint64_t size;
} memspecs_t;

/*
 * UnitAddress property related constants and data structures
 */

#define	DEFAULT_ADDRESS_CELLS		2
#define	MAX_UNIT_ADDRESS_LEN		256

typedef int unitaddr_func_t(char *, int, uint32_t *, uint_t);

typedef struct {
	char		*class;		/* class name */
	unitaddr_func_t	*func;		/* function to encode unit address */
	int		addrcellcnt;	/* #addrcell expected, if non-zero */
} unitaddr_map_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _PICLDEVTREE_H */
