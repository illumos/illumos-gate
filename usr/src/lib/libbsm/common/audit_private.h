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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Do not add to this file unless it is to cover an existing private
 * interface and do not write new code that depends on this header
 * file or the interfaces contained in it.
 *
 * This is a private interface, subject to change.  It exists solely
 * as a way of making certain existing clients of libbsm lint clean.
 * As the related interfaces are replaced with the adt.* interfaces,
 * this header should shrink to zero.
 */

#ifndef _AUDIT_PRIVATE_H
#define	_AUDIT_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <bsm/libbsm.h>
#include <pwd.h>

/*
 * audit_settid.c
 * interface users
 * rexecd
 * rlogind
 * rshd
 * telnetd
 * rexd
 */
extern	int	audit_settid(int);

/*
 * audit_allocate.c
 * interface user
 * allocate
 */
extern	void	audit_allocate_argv(int, int, char *[]);
extern	int	audit_allocate_record(int);
extern	void	audit_allocate_list(char *);
extern	void	audit_allocate_device(char *);

/*
 * audit_ftpd.c
 * interface user
 * ftpd
 */
extern	void	audit_ftpd_bad_pw(char *uname);
extern	void	audit_ftpd_excluded(char *uname);
extern	void	audit_ftpd_failure(char *uname);
extern	void	audit_ftpd_no_anon(void);
extern	void	audit_ftpd_success(char *uname);
extern	void	audit_ftpd_unknown(char *uname);
extern	void	audit_ftpd_logout(void);

/*
 * audit_rexecd.c
 * interface user
 * rexecd
 */
extern	void	audit_rexecd_setup(void);
extern	void	audit_rexecd_success(char *, char *, char *);
extern	void	audit_rexecd_fail(char *, char *, char *, char *);

/*
 * audit_rshd.c
 * interface user
 * rshd
 */
extern	int	audit_rshd_setup(void);
extern	int	audit_rshd_success(char *, char *, char *, char *);
extern	int	audit_rshd_fail(char *, char *, char *, char *, char *);

/*
 * audit_at.c
 * interface users
 * atrm
 * at
 */
extern	int	audit_at_delete(char *, char *, int);
extern	int	audit_at_create(char *, int);

/*
 * audit_crontab.c
 * interface user
 * crontab
 */
extern	int	audit_crontab_modify(char *, char *, int);
extern	int	audit_crontab_delete(char *, int);
extern	int	audit_crontab_not_allowed(uid_t, char *);
extern	int	audit_crontab_process_not_audited(void);

/*
 * audit_cron.c
 * interface users
 * cron
 * at
 */
extern	int	audit_cron_session(char *, char *, uid_t, gid_t, char *);
extern	void	audit_cron_new_job(char *, int, void *);
extern	void	audit_cron_bad_user(char *);
extern	void	audit_cron_user_acct_expired(char *);
extern	int	audit_cron_create_anc_file(char *, char *, char *, uid_t);
extern	int	audit_cron_delete_anc_file(char *, char *);
extern	int	audit_cron_is_anc_name(char *);
extern	int	audit_cron_mode(void);
extern	char	*audit_cron_make_anc_name(char *);
extern	int	audit_cron_setinfo(char *, auditinfo_addr_t *);

/*
 * audit_mountd.c
 * interface user
 * mountd
 */
extern	void	audit_mountd_setup(void);
extern	void	audit_mountd_mount(char *, char *, int);
extern	void	audit_mountd_umount(char *, char *);

/*
 * audit_halt.c
 * interface user
 * halt
 */
extern	int	audit_halt_setup(int, char **);
extern	int	audit_halt_success(void);
extern	int	audit_halt_fail(void);

/*
 * audit_shutdown.c
 * interface user
 * shutdown
 */
extern	int	audit_shutdown_setup(int, char **);
extern	int	audit_shutdown_success(void);
extern	int	audit_shutdown_fail(void);

/*
 * audit_reboot.c
 * interface user
 * halt
 */
extern	int	audit_reboot_setup(void);
extern	int	audit_reboot_success(void);
extern	int	audit_reboot_fail(void);

/*
 * audit_rexd.c
 * interface users
 * rpc.rexd
 */
extern	void 	audit_rexd_fail(char *, char *, char *, uid_t, gid_t,
    char *, char **);
extern	void	audit_rexd_success(char *, char *, uid_t, gid_t,
    char *, char **);
extern	void	audit_rexd_setup(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _AUDIT_PRIVATE_H */
