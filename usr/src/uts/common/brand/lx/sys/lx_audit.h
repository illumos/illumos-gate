/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright 2018 Joyent, Inc.  All rights reserved.
 */

#ifndef	_LX_AUDIT_H
#define	_LX_AUDIT_H

#ifdef	__cplusplus
extern "C" {
#endif

extern void lx_audit_init(int (*)(void *, uint_t, const char *, uint_t));
extern void lx_audit_cleanup(void);
extern void lx_audit_stop_worker(void *, void (*)(void *, boolean_t));
extern int lx_audit_append_rule(void *, uint_t);
extern int lx_audit_delete_rule(void *, uint_t);
extern void lx_audit_list_rules(void *,
    void (*)(void *, void *, uint_t, void *, uint_t));
extern void lx_audit_get_feature(void *, void (*)(void *, void *, uint_t));
extern void lx_audit_get(void *, void (*)(void *, void *, uint_t));
extern int lx_audit_set(void *, void *, uint_t, void (*cb)(void *, boolean_t));
extern void lx_audit_emit_user_msg(uint_t, uint_t, char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_AUDIT_H */
