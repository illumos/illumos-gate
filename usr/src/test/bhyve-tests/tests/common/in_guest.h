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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _IN_GUEST_H_
#define	_IN_GUEST_H_

#include "payload_common.h"

struct vmctx *test_initialize(const char *);
struct vmctx *test_initialize_flags(const char *, uint64_t);
void test_reinitialize(struct vmctx *, uint64_t);
void test_cleanup(bool);
void test_fail(void);
void test_fail_errno(int err, const char *msg);
void test_fail_msg(const char *fmt, ...);
void test_fail_vmexit(const struct vm_exit *vexit);
void test_pass(void);
const char *test_msg_get(struct vmctx *);
void test_msg_print(struct vmctx *);

int test_setup_vcpu(struct vmctx *, int, uint64_t, uint64_t);

enum vm_exit_kind {
	/* Otherwise empty vmexit which should result in immediate re-entry */
	VEK_REENTR,
	/* Write to IOP_TEST_RESULT port with success value (0) */
	VEK_TEST_PASS,
	/* Write to IOP_TEST_RESULT port with failure value (non-zero) */
	VEK_TEST_FAIL,
	/* Payload emitted a message via IOP_TEST_MSG port */
	VEK_TEST_MSG,
	/* Test specific logic must handle exit data */
	VEK_UNHANDLED,
};

enum vm_exit_kind test_run_vcpu(struct vmctx *, int, struct vm_entry *,
    struct vm_exit *);

void ventry_fulfill_inout(const struct vm_exit *, struct vm_entry *, uint32_t);
void ventry_fulfill_mmio(const struct vm_exit *, struct vm_entry *, uint64_t);

bool vexit_match_inout(const struct vm_exit *, bool, uint16_t, uint_t,
    uint32_t *);
bool vexit_match_mmio(const struct vm_exit *, bool, uint64_t, uint_t,
    uint64_t *);

#endif /* _IN_GUEST_H_ */
