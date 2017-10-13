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
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/debug.h>

static kmutex_t hvm_excl_lock;
static const char *hvm_excl_holder = NULL;

/*
 * HVM Exclusion Interface
 *
 * To avoid VMX/SVM conflicts from arising when multiple hypervisor providers
 * (eg. KVM, bhyve) are shipped with the system, this simple advisory locking
 * system is presented for their use.  Until a proper hypervisor API, like the
 * one in OSX, is shipped in illumos, this will serve as opt-in regulation to
 * dictate that only a single hypervisor be allowed to configure the system and
 * run at any given time.
 */

boolean_t
hvm_excl_hold(const char *consumer)
{
	boolean_t res = B_FALSE;

	mutex_enter(&hvm_excl_lock);
	if (hvm_excl_holder == NULL) {
		hvm_excl_holder = consumer;
		res = B_TRUE;
	}
	mutex_exit(&hvm_excl_lock);

	return (res);
}

void
hvm_excl_rele(const char *consumer)
{
	mutex_enter(&hvm_excl_lock);
	VERIFY(consumer == hvm_excl_holder);
	hvm_excl_holder = NULL;
	mutex_exit(&hvm_excl_lock);
}
