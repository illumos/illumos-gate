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

#ifndef	_GENERIC_H
#define	_GENERIC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern int	cannot_audit(int);
extern void	aug_init(void);
extern dev_t	aug_get_port(void);
extern int 	aug_get_machine(const char *, uint32_t *, uint32_t *);
extern void	aug_save_auid(au_id_t);
extern void	aug_save_uid(uid_t);
extern void	aug_save_euid(uid_t);
extern void	aug_save_gid(gid_t);
extern void	aug_save_egid(gid_t);
extern void	aug_save_pid(pid_t);
extern void	aug_save_asid(au_asid_t);
extern void	aug_save_tid(dev_t, int);
extern void	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
extern int	aug_save_me(void);
extern int	aug_save_namask(void);
extern void	aug_save_event(au_event_t);
extern void	aug_save_sorf(int);
extern void	aug_save_text(char *);
extern void	aug_save_text1(char *);
extern void	aug_save_text2(char *);
extern void	aug_save_na(int);
extern void	aug_save_user(char *);
extern void	aug_save_path(char *);
extern int	aug_save_policy(void);
extern void	aug_save_afunc(int (*)(int));
extern int	aug_audit(void);
extern int	aug_na_selected(void);
extern int	aug_selected(void);
extern int	aug_daemon_session(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _GENERIC_H */
