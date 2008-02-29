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

#ifndef	_LDMSVCS_UTILS_H
#define	_LDMSVCS_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/ldc.h>
#include <sys/vldc.h>
#include <sys/ds.h>
#include <sys/ds_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Service Information
 */
typedef struct fds_svc {
	ds_svc_hdl_t hdl;	/* handle assigned by DS */
	ds_svc_state_t state;	/* current service state */
	ds_ver_t ver;		/* svc protocol version in use */
	char *name;
} fds_svc_t;

/*
 * table of registered services
 */
typedef struct fds_reg_svcs {
	pthread_mutex_t mt;
	pthread_cond_t cv;
	fds_svc_t **tbl;		/* the table itself */
	uint_t nsvcs;		/* current number of items */
} fds_reg_svcs_t;


typedef enum {
	CHANNEL_UNINITIALIZED,	/* status of channel unknown */
	CHANNEL_CLOSED,		/* port structure not in use */
	CHANNEL_OPEN,		/* open but not initialized/reset */
	CHANNEL_READY,		/* init/reset done */
	CHANNEL_UNUSABLE,	/* cannot be used (possibly busy) */
	CHANNEL_EXIT		/* normal exit */
} fds_chan_state_t;

typedef struct fds_channel {
	int fd;			/* FD for this channel */
	fds_chan_state_t state; /* state of the port */
	ds_ver_t ver;		/* DS protocol version in use */
} fds_channel_t;


/*
 * FMA services
 */
typedef struct {
	uint64_t req_num;
} fma_req_pri_t;

/*
 * definition of fma_pri_resp_t is not shown here.  for more details,
 * see ldmsvcs_utils.c:ldmsvcs_get_core_md().
 */

#define	FMA_CPU_REQ_STATUS	0
#define	FMA_CPU_REQ_OFFLINE	1
#define	FMA_CPU_REQ_ONLINE	2

#define	FMA_CPU_RESP_OK		0
#define	FMA_CPU_RESP_FAILURE	1

#define	FMA_CPU_STAT_ONLINE	0
#define	FMA_CPU_STAT_OFFLINE	1
#define	FMA_CPU_STAT_ILLEGAL	2

typedef struct {
	uint64_t req_num;
	uint32_t msg_type;
	uint32_t cpu_id;
} fma_cpu_service_req_t;

typedef struct {
	uint64_t req_num;
	uint32_t result;
	uint32_t status;
} fma_cpu_resp_t;

#define	FMA_MEM_REQ_STATUS	0
#define	FMA_MEM_REQ_RETIRE	1
#define	FMA_MEM_REQ_RESURRECT	2

#define	FMA_MEM_RESP_OK		0
#define	FMA_MEM_RESP_FAILURE	1

#define	FMA_MEM_STAT_NOTRETIRED	0
#define	FMA_MEM_STAT_RETIRED	1
#define	FMA_MEM_STAT_ILLEGAL	2

typedef struct {
	uint64_t req_num;
	uint32_t msg_type;
	uint32_t _resvd;
	uint64_t real_addr;
	uint64_t length;
} fma_mem_service_req_t;

typedef struct {
	uint64_t req_num;
	uint32_t result;
	uint32_t status;
	uint64_t res_addr;
	uint64_t res_length;
} fma_mem_resp_t;


struct ldom_hdl {
	int major_version;
	int service_ldom;
	void *(*allocp)(size_t size);
	void (*freep)(void *addr, size_t size);
	struct ldmsvcs_info *lsinfo;
};

/*
 * in the default case of ldmd (the LDOM manager daemon/service)
 * not installed/running, set short timeouts for contacting ldmd,
 * so that higher levels in the software stack (ex: diagnosis engines)
 * are not excessively delayed by ldmd's absence. both timeouts are tunable
 * via SMF properties in ldmd's service manifest, and expected to be set
 * thusly to appropriate values when ldmd is installed.
 *
 * timeouts are in seconds. init is the initial timeout; running is
 * for subsequent timeouts.
 */
#define	LDM_INIT_WAIT_TIME	2
#define	LDM_RUNNING_WAIT_TIME	2

#define	LDM_SVC_NM		"svc:/ldoms/ldmd:default"
#define	LDM_PROP_GROUP_NM	"fmd_config"

#define	LDM_INIT_TO_PROP_NM	"fmd_to_ldmd_init_timeout"
#define	LDM_RUNNING_TO_PROP_NM	"fmd_to_ldmd_running_timeout"

extern int ldmsvcs_check_channel(void);

extern void ldmsvcs_init(struct ldom_hdl *lhp);

extern void ldmsvcs_fini(struct ldom_hdl *lhp);

extern ssize_t ldmsvcs_get_core_md(struct ldom_hdl *lhp, uint64_t **buf);

extern int ldmsvcs_cpu_req_status(struct ldom_hdl *lhp, uint32_t cpuid);

extern int ldmsvcs_mem_req_status(struct ldom_hdl *lhp, uint64_t pa);

extern int ldmsvcs_cpu_req_offline(struct ldom_hdl *lhp, uint32_t cpuid);

extern int ldmsvcs_mem_req_retire(struct ldom_hdl *lhp, uint64_t pa);

extern int ldmsvcs_cpu_req_online(struct ldom_hdl *lhp, uint32_t cpuid);

extern int ldmsvcs_mem_req_unretire(struct ldom_hdl *lhp, uint64_t pa);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDMSVCS_UTILS_H */
