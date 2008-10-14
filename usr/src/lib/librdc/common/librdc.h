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

#ifndef	_LIBRDC_H
#define	_LIBRDC_H

#ifdef	__cplusplus
extern "C" {
#endif

extern int Is_ipv6present(void);
extern int self_check(char *);
extern int gethost_netaddrs(char *, char *, char *, char *);
extern struct hostent *gethost_byname(const char *);
extern struct netbuf *get_addr(char *, ulong_t, ulong_t, struct netconfig **,
    char *, char *, struct t_info *, int);
extern int convert_nconf_to_knconf(struct netconfig *, struct knetconfig *);
extern int rdc_check_release(char **);

#if !defined(NSC_MAXPATH)
#define	NSC_MAXPATH	64
#endif

#define	RDC_MAX_THREADS	1024
/* user interface to sndr */
typedef struct rdcconfig_s {
	char			phost[NSC_MAXPATH];
	char			pfile[NSC_MAXPATH];
	char			pbmp[NSC_MAXPATH];
	char			shost[NSC_MAXPATH];
	char			sfile[NSC_MAXPATH];
	char			sbmp[NSC_MAXPATH];
	char			direct[NSC_MAXPATH];
	char			mode[NSC_MAXPATH];
	char			group[NSC_MAXPATH];
	char			ctag[NSC_MAXPATH];
	char			options[NSC_MAXPATH];
	int			persist;	/* 0 no, 1 yes */
	struct rdcconfig_s	*next;
} rdcconfig_t;

#define	RDC_ERR_SIZE	256

typedef struct rdc_rc_s {
	int			rc;
	char			msg[RDC_ERR_SIZE];
	struct rdc_rc_s		*next;
	rdcconfig_t		set;
} rdc_rc_t;

#define	RDC_FREEONE	0 /* free one rdcconfig_t* */
#define	RDC_FREEALL	1 /* free entire chain of rdcconfig_t* */

/* and it's operations */
extern rdcconfig_t *rdc_alloc_config(const char *phost, const char *pfile,
    const char *pbmp, const char *shost, const char *sfile, const char *sbmp,
    const char *mode, const char *group, const char *ctag, const char *options,
    int persist);
extern void rdc_free_config(rdcconfig_t *rdc, int all);
extern void rdc_free_rclist(rdc_rc_t *rc);
extern rdc_rc_t *new_rc(void);
extern rdc_rc_t *rdc_enable(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_enable_clrbmp(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_disable(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_log(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_usync(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_fsync(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_rsync(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_ursync(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_wait(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_set_autosync(rdcconfig_t *rdc, int autosync);
extern rdc_rc_t *rdc_set_maxqfbas(rdcconfig_t *rdc, int maxqfbas);
extern rdc_rc_t *rdc_set_maxqitems(rdcconfig_t *rdc, int maxqitems);
extern int rdc_get_maxqfbas(rdcconfig_t *rdc);
extern int rdc_get_maxqitems(rdcconfig_t *rdc);
extern int rdc_get_autosync(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_reconfig_pbmp(rdcconfig_t *rdc, char *pbmp);
extern rdc_rc_t *rdc_reconfig_sbmp(rdcconfig_t *rdc, char *sbmp);
extern rdc_rc_t *rdc_reconfig_group(rdcconfig_t *rdc, char *group);
extern rdc_rc_t *rdc_reconfig_ctag(rdcconfig_t *rdc, char *ctag);
extern rdc_rc_t *rdc_set_sync(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_set_async(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_health(rdcconfig_t *rdc);
extern rdc_rc_t *rdc_reverse_role(rdcconfig_t *rdc);
extern char *rdc_error(int *sev);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBRDC_H */
