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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NSCD_H
#define	_NSCD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern admin_t current_admin;

extern int attr_strlen(char *);
extern char *attr_strcpy(char *, char *);

extern nsc_stat_t *getcacheptr(char *s);
extern int nscd_set_lf(admin_t *ptr, char *s);
extern void logit(char *format, ...);
extern int launch_update(nsc_call_t *in);
extern int load_admin_defaults(admin_t *ptr, int will_become_server);
extern void getpw_init(void);
extern void getpw_revalidate(void);
extern void getpw_uid_reaper(void);
extern void getpw_nam_reaper(void);
extern void getpw_invalidate(void);
extern void getpw_lookup(nsc_return_t *out, int maxsize, nsc_call_t *in,
    time_t now);
extern void getgr_init(void);
extern void getgr_revalidate(void);
extern void getgr_uid_reaper(void);
extern void getgr_nam_reaper(void);
extern void getgr_invalidate(void);
extern void getgr_lookup(nsc_return_t *out, int maxsize, nsc_call_t *in,
    time_t now);
extern void gethost_init(void);
extern void gethost_revalidate(void);
extern void gethost_nam_reaper(void);
extern void gethost_addr_reaper(void);
extern void gethost_invalidate(void);
extern void gethost_lookup(nsc_return_t *out, int maxsize, nsc_call_t *in,
    time_t now);
extern void getnode_init(void);
extern void getnode_revalidate(void);
extern void getnode_nam_reaper(void);
extern void getnode_addr_reaper(void);
extern void getnode_invalidate(void);
extern void getnode_name_invalidate(void);
extern void getnode_lookup(nsc_return_t *out, int maxsize, nsc_call_t *in,
    time_t now);
extern hash_t *make_hash(int size);
extern hash_t *make_ihash(int size);
extern char **get_hash(hash_t *tbl, char *key);
extern char **find_hash(hash_t *tbl, char *key);
extern char *del_hash(hash_t *tbl, hash_entry_t *del_this, hash_entry_t *prev,
    int bucket);
extern int operate_hash(hash_t *tbl, void (*ptr)(), char *usr_arg);
extern int operate_hash_addr(hash_t *tbl, void (*ptr)(), char *usr_arg);
extern void nsc_reaper(char *tbl_name, hash_t *tbl,
    nsc_stat_t *admin_ptr, mutex_t *hash_lock);
extern int reap_hash(hash_t *tbl, nsc_stat_t *admin_ptr,
    mutex_t *hash_lock, int howlong);
extern void destroy_hash(hash_t *tbl, int (*ptr)(), char *usr_arg);
extern int *maken(int n);
extern int insertn(int *table, int n, int data);
extern int nscd_parse(char *progname, char *filename);
extern int nscd_set_dl(admin_t *ptr, int value);
extern int nscd_set_ec(nsc_stat_t *cache, char *name, int value);
extern int nscd_set_khc(nsc_stat_t *cache, char *name, int value);
extern int nscd_set_odo(nsc_stat_t *cache, char *name, int value);
extern int nscd_set_ss(nsc_stat_t *cache, char *name, int value);
extern int nscd_set_ttl_positive(nsc_stat_t *cache, char *name, int value);
extern int nscd_set_ttl_negative(nsc_stat_t *cache, char *name, int value);
extern int nscd_wait(waiter_t *wchan, mutex_t *lock, char **key);
extern int nscd_signal(waiter_t *wchan, char **key);
extern int get_clearance(int callnumber);
extern int release_clearance(int callnumber);

extern void getexec_init(void);
extern void getexec_revalidate(void);
extern void getexec_reaper(void);
extern void getexec_invalidate(void);
extern void getexec_lookup(nsc_return_t *out, int maxsize, nsc_call_t *in,
    time_t now);
extern void getprof_init(void);
extern void getprof_revalidate(void);
extern void getprof_reaper(void);
extern void getprof_invalidate(void);
extern void getprof_lookup(nsc_return_t *out, int maxsize, nsc_call_t *in,
    time_t now);
extern void getuser_init(void);
extern void getuser_revalidate(void);
extern void getuser_reaper(void);
extern void getuser_invalidate(void);
extern void getuser_lookup(nsc_return_t *out, int maxsize, nsc_call_t *in,
    time_t now);

extern void leave(int n);
#ifdef	__cplusplus
}
#endif

#endif	/* _NSCD_H */
