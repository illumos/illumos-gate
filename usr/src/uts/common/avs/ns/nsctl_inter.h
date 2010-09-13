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

#ifndef	_SYS_NSCTL_INTER_H
#define	_SYS_NSCTL_INTER_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	__NSC_GEN__
#include <sys/ksynch.h>
#include <sys/nsctl/nsc_dev.h>
#include <sys/nsctl/nsc_gen.h>
#include <sys/nsctl/nsc_mem.h>
#include <sys/nsctl/nsc_rmspin.h>

#ifdef _KERNEL

#include <sys/nsc_ddi.h>

/* prevent errors from typedefs not defined until after this is included */
typedef int	nsc_size_t;
typedef int	nsc_off_t;

int nsc_inval() { }
int nsc_ioerr() { }
int nsc_fatal() { }
int nsc_null()  { }
int nsc_true()  { }
void nsc_decode_param(void *, void *, void *) { }
int nskernd_isdaemon() { }
uchar_t nsc_ldstub(uchar_t *) { }
void nsc_membar_stld(void) { }

#ifndef _BLIND_T
typedef void * blind_t;
#endif
typedef void strategy_fn_t;
nsc_io_t *nsc_register_io(char *, int, void *) { }
int nsc_unregister_io(nsc_io_t *, int) { }
nsc_path_t *nsc_register_path(char *, int, nsc_io_t *) { }
int nsc_unregister_path(nsc_path_t *, int) { }
int nsc_cache_sizes(int *, int *) { }
int nsc_register_down(void (*)()) { }
int nsc_node_hints(unsigned int *) { }
int nsc_node_hints_set(unsigned int) { }
blind_t nsc_register_power(char *, void *) { }
int nsc_unregister_power(blind_t) { }
strategy_fn_t    nsc_get_strategy(major_t) { }
void *nsc_get_devops(major_t) { }
void nsc_do_sysevent(char *, char *, int, int, char *, dev_info_t *) { }
nsc_fd_t *nsc_open(char *, int, void *, blind_t, int *) { }
int nsc_close(nsc_fd_t *) { }
char *nsc_pathname(nsc_fd_t *) { }
int nsc_shared(nsc_fd_t *) { }
int nsc_setval(nsc_fd_t *, char *, int) { }
int nsc_getval(nsc_fd_t *, char *, int *) { }
int nsc_set_trksize(nsc_fd_t *, int) { }
int nsc_discard_pinned(nsc_fd_t *, int, int) { }
kmutex_t *nsc_lock_addr(nsc_fd_t *) { }
int nsc_attach(nsc_fd_t *, int) { }
int nsc_reserve(nsc_fd_t *, int) { }
void nsc_reserve_lk(nsc_fd_t *) { }
void nsc_release(nsc_fd_t *) { }
int nsc_release_lk(nsc_fd_t *) { }
int nsc_detach(nsc_fd_t *, int) { }
int nsc_avail(nsc_fd_t *) { }
int nsc_held(nsc_fd_t *) { }
int nsc_waiting(nsc_fd_t *) { }
int nsc_partsize(nsc_fd_t *, nsc_size_t *) { }
int nsc_maxfbas(nsc_fd_t *, int, nsc_size_t *) { }
int nsc_control(nsc_fd_t *, int, void *, int) { }
int nsc_get_pinned(nsc_fd_t *) { }
int nsc_max_devices(void) { }

void nsc_set_owner(nsc_fd_t *, nsc_iodev_t *) { }
void nsc_pinned_data(nsc_iodev_t *, int, int) { }
void nsc_unpinned_data(nsc_iodev_t *, int, int) { }
int nsc_alloc_buf(nsc_fd_t *, nsc_off_t, nsc_size_t, int, void **) { }
int nsc_alloc_abuf(nsc_off_t, nsc_size_t, int, void **) { }
int nsc_read(void *, nsc_off_t, nsc_size_t, int) { }
int nsc_write(void *, nsc_off_t, nsc_size_t, int) { }
int nsc_zero(void *, nsc_off_t, nsc_size_t, int) { }
int nsc_copy(void *, void *, nsc_off_t, nsc_off_t, nsc_size_t) { }
int nsc_copy_direct(void *, void *, nsc_off_t, nsc_off_t, nsc_size_t) { }
int nsc_uncommit(void *, nsc_off_t, nsc_size_t, int) { }
int nsc_free_buf(void *) { }
void *nsc_alloc_handle(nsc_fd_t *,
	void (*)(), void (*)(), void (*)()) { }
int nsc_free_handle(void *) { }
int nsc_uread(nsc_fd_t *, void *, void *) { }
int nsc_uwrite(nsc_fd_t *, void *, void *) { }

nsc_rmlock_t *nsc_rm_lock_alloc(char *, int, void *) { }
void nsc_rm_lock_dealloc(nsc_rmlock_t *) { }
int nsc_rm_lock(nsc_rmlock_t *) { }
void nsc_rm_unlock(nsc_rmlock_t *) { }

void *nsc_register_mem(char *, int, int) { }
void nsc_unregister_mem(void *) { }
void *nsc_kmem_alloc(size_t, int, void *) { }
void *nsc_kmem_zalloc(size_t, int, void *) { }
void nsc_kmem_free(void *, size_t) { }
void nsc_mem_sizes(void *, size_t *, size_t *, size_t *) { }
size_t nsc_mem_avail(void *) { }

int nsc_commit_mem(void *, void *, size_t, void) { }

void nsc_cm_errhdlr(void *, void *, size_t, int) { }

nsc_svc_t *nsc_register_svc(char *, void (*)(intptr_t)) { }
int nsc_unregister_svc(nsc_svc_t *) { }
int nsc_call_svc(nsc_svc_t *, intptr_t) { }

char *nsc_strdup(char *) { }
void nsc_strfree(char *) { }
int nsc_strmatch(char *, char *) { }
void nsc_sprintf(char *, char *, ...) { }
int nsc_max_nodeid, nsc_min_nodeid;
int nsc_nodeid_data(void) { }
int nsc_node_id(void) { }
int nsc_node_up(int) { }
char *nsc_node_name(void) { }
time_t nsc_time(void) { }
clock_t nsc_lbolt(void) { }
int nsc_delay_sig(clock_t) { }
clock_t nsc_usec(void) { }
void nsc_yield(void) { }
int nsc_create_process(void (*)(void *), void *, boolean_t) { }
int nsc_power_init(void) { }
void nsc_power_deinit(void) { }
void _nsc_global_nvmemmap_lookup(void *) { }
void _nsc_mark_pages(void addr, void size, int dump) { }
void _nsc_init_raw() { }
void _nsc_deinit_raw() { }
void _nsc_init_start() { }
void _nsc_init_os() { }
void _nsc_raw_flags() { }
int _nsc_raw_def[1];
void nskernd_command() { }
void nskern_bsize() { }
int nsc_do_lock() { }
void nsc_do_unlock() { }
int HZ;
uint64_t nsc_strhash(char *) { }
int nsc_fdpathcmp(void *, uint64_t, char *) { }
char *nsc_caller() { }
char *nsc_callee() { }
void *nsc_threadp() { }

/*
 * Misc stuff to make our life easier
 */
#ifndef _VERSION_
#define	_VERSION_	"SunOS 5.11"
#endif

#ifndef ISS_VERSION_STR
#define	ISS_VERSION_STR "SunOS 5.11"
#endif

#ifndef ISS_VERSION_NUM
#define	ISS_VERSION_NUM 61
#endif

#ifndef ISS_VERSION_MAJ
#define	ISS_VERSION_MAJ 11
#endif

#ifndef ISS_VERSION_MIN
#define	ISS_VERSION_MIN 11
#endif

#ifndef ISS_VERSION_MIC
#define	ISS_VERSION_MIC	0
#endif

#ifndef BUILD_DATE_STR
#define	BUILD_DATE_STR "None"
#endif

#ifndef SCMTEST_MAJOR_VERSION
#define	SCMTEST_MAJOR_VERSION "0"
#endif

#ifndef SCMTEST_MINOR_VERSION
#define	SCMTEST_MINOR_VERSION "0"
#endif

#ifndef SCMTEST_PATCH_VERSION
#define	SCMTEST_PATCH_VERSION "0"
#endif

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_NSCTL_INTER_H */
