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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _INET_SCTP_SCTP_ASCONF_H
#define	_INET_SCTP_SCTP_ASCONF_H

#ifdef __cplusplus
extern "C" {
#endif

#define	SCTP_FADDR_RC_TIMER_RESTART(sctp, fp, intvl)			\
	if ((fp)->rc_timer_mp == NULL) {				\
		(fp)->rc_timer_mp = sctp_timer_alloc((sctp), 		\
		    sctp_rc_timer, KM_NOSLEEP);				\
	}								\
	if ((fp)->rc_timer_mp != NULL) {				\
		((sctpt_t *)((fp)->rc_timer_mp->b_rptr))->sctpt_faddr = fp;  \
		dprint(3, ("faddr_rc_timer_restart: fp=%p %x:%x:%x:%x %d\n", \
		    (void *)(fp), SCTP_PRINTADDR((fp)->faddr),		\
		    (int)(intvl)));					\
		sctp_timer((sctp), (fp)->rc_timer_mp, (intvl));		\
		(fp)->rc_timer_running = 1;				\
	}

#define	SCTP_FADDR_RC_TIMER_STOP(fp)					\
	if ((fp)->rc_timer_running && (fp)->rc_timer_mp != NULL) {	\
		sctp_timer_stop((fp)->rc_timer_mp);			\
		(fp)->rc_timer_running = 0;				\
	}

extern int sctp_add_ip(sctp_t *, const void *, uint32_t);
extern int sctp_del_ip(sctp_t *, const void *, uint32_t, uchar_t *, size_t);
extern void sctp_asconf_free_cxmit(sctp_t *, sctp_chunk_hdr_t *);
extern void sctp_input_asconf(sctp_t *, sctp_chunk_hdr_t *, sctp_faddr_t *);
extern void sctp_input_asconf_ack(sctp_t *, sctp_chunk_hdr_t *, sctp_faddr_t *);
extern int sctp_set_peerprim(sctp_t *, const void *);
extern void sctp_wput_asconf(sctp_t *, sctp_faddr_t *);

#ifdef __cplusplus
}
#endif

#endif /* _INET_SCTP_SCTP_ASCONF_H */
