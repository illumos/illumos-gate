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

#ifndef	_SYS_NCALL_INTER_H
#define	_SYS_NCALL_INTER_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

void ncall_register_svc(int, void (*)(void *, int *)) { }
void ncall_unregister_svc(int) { }
int ncall_register_module(void *, void *);
int ncall_unregister_module(void *);

int  ncall_nodeid(char *) { }
char *ncall_nodename(int) { }
int  ncall_mirror(int) { }
int  ncall_self(void) { }

int  ncall_alloc(int, int, int, void **) { }
int  ncall_timedsend(void *, int, int, struct timeval *, ...) { }
int  ncall_timedsendnotify(void *, int, int, struct timeval *,
    void (*)(void *, void *), void *, ...) { }
int  ncall_send(void *, int, int, ...) { }
int  ncall_read_reply(void *, int, ...) { }
void ncall_reset(void *) { }
void ncall_free(void *) { }

int  ncall_put_data(void *, void *, int) { }
int  ncall_get_data(void *, void *, int) { }

int  ncall_sender(void *) { }
void ncall_reply(void *, ...) { }
void ncall_pend(void  *) { }
void ncall_done(void  *) { }

int ncall_maxnodes(void) { }
int ncall_nextnode(void **) { }
int ncall_errcode(void *, int *) { }


/* Health monitor typedefs, variables and functions */
typedef void hmio_name_t;
typedef void hm_sarea_t;
typedef void hm_statev_t;
#ifndef _HM_TOK_T
#define	_HM_TOK_T
typedef void *hm_tok_t;
#endif

int bchm_load(void) { }
int bchm_unload(void) { }
int bchm_getnetname(hmio_name_t *) { }
int bchm_getstatename(hmio_name_t *) { }
int bchm_startnet(hmio_name_t *, int) { }
int bchm_initted;
hm_sarea_t *bchm_start_addr[1];
hm_sarea_t hm_latest_state;

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_NCALL_INTER_H */
