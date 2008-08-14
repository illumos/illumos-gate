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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _SBLK_DEFS_
#define	_SBLK_DEFS_
#include <time.h>

#ifndef _DEFS_
#include "defs.h"
#endif

#define	SHARED_KEY		((key_t)50000)


#define	SMEM_LIB_ENV_KEY "ACSLS_LIB_SHM_KEY"

#define	SMEM_LIB_KEY		((key_t)51000)

#define	SMEM_AC_KEY		((key_t)52000)
#define	SMEM_AC_RPC_KEY		((key_t)52001)
#define	SMEM_AC_ADI_KEY		((key_t)52002)
#define	SMEM_AC_LU62_KEY	 ((key_t)52003)
typedef enum {
	BLOCK_WRITTEN,
	BLOCK_AVAILABLE
} USAGE_STATUS;

struct block_preamble {
	int		block_size;
	USAGE_STATUS		usage_status;
	int		pid;
	time_t		access_time;
	int		process_count;
};


#define	BLK_SIZE_SMALL		512
#define	BLK_NUM_SMALL		128
#define	BLK_SIZE_LARGE		4096
#define	BLK_NUM_LARGE		32

#define	BLK_SMALL_PER	(BLK_NUM_SMALL/2)

#define	BLK_LARGE_PER	(BLK_NUM_LARGE/2)

struct sh_small_block {
	struct block_preamble		bp;
	char	data [BLK_SIZE_SMALL];
};

struct sh_large_block {
	struct block_preamble		bp;
	char	data [BLK_SIZE_LARGE];
};

#define	BLK_TOT_MEM_USED	((sizeof (struct sh_large_block) *
				BLK_NUM_LARGE) +
			(sizeof (struct sh_small_block) * BLK_NUM_SMALL))

#define	BLK_CLEANUP_WAIT	(600)

#define	BLK_CLEANUP_TIME	((time_t)(1800))


typedef struct sh_large_block		CL_SHM_LARGE;
typedef struct block_preamble		CL_SHM_PREAMBLE;
typedef struct sh_small_block		CL_SHM_SMALL;


extern		CL_SHM_LARGE	*large_preamble;
extern		int		semaphore_id;
extern		int		shared_id;
extern		CL_SHM_SMALL	*small_preamble;


struct dshm_hdr {
	BOOLEAN reattach;
	BOOLEAN built;
	time_t		timestamp;
};


struct dshm_id {
	int		semaphore;
	int		shared_mem;
};


enum dshm_build_flag {
	DSHM_FIRST_TIME,
	DSHM_REBUILD
};



#define	SMEM_UNSET INT_MAX
#define	SMEM_NOCOUNT (INT_MAX - 1)

typedef int		COUNT_TYPE;
typedef int		INDEX_TYPE;


typedef struct smem_acs {
	COUNT_TYPE		lsm_count;
	INDEX_TYPE		lsm_index;
} SMEM_ACS;



typedef struct smem_lsm {
	COUNT_TYPE		cap_count;
	COUNT_TYPE		pnl_count;
	INDEX_TYPE		pnl_index;
} SMEM_LSM;


typedef struct smem_pnl {
	COUNT_TYPE		row_count;
	COUNT_TYPE		col_count;
	COUNT_TYPE		drv_count;
} SMEM_PNL;



typedef struct smem_lib {
	COUNT_TYPE		acs_count;
} SMEM_LIB;


typedef struct smem_lib_ptrs {
	SMEM_LIB		*p_lib;
	SMEM_ACS		*p_acs;
	SMEM_LSM		*p_lsm;
	SMEM_PNL		*p_pnl;
} SMEM_LIB_PTRS;

BOOLEAN cl_sblk_attach(void);
BOOLEAN cl_sblk_available(void);
int cl_sblk_cleanup(void);
BOOLEAN cl_sblk_create(void);
BOOLEAN cl_sblk_destroy(void);
BOOLEAN cl_sblk_read(char *packet, int message_number, int *message_size);
BOOLEAN cl_sblk_remove(int message_number);
int cl_sblk_write(void *message, int message_count, int process_count);


#endif /* _SBLK_DEFS_ */
