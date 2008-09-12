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

#include "includes.h"
#include "log.h"
#include "engine.h"

#define	PKCS11_ENGINE	"pkcs11"

/*
 * Loads the PKCS#11 engine if the UseOpenSSLEngine is set to yes which is the
 * default value.
 */
ENGINE *
pkcs11_engine_load(int use_engine)
{
	ENGINE *e = NULL;

	debug("use_engine is '%s'", use_engine == 1 ? "yes" : "no");
	if (use_engine == 0)
		return (NULL);

	ENGINE_load_pk11();
	/* get structural reference */
	if ((e = ENGINE_by_id(PKCS11_ENGINE)) == NULL) {
		fatal("%s engine does not exist", PKCS11_ENGINE);
	}

	/* get functional reference */
	if (ENGINE_init(e) == 0) {
		fatal("can't initialize %s engine", PKCS11_ENGINE);
	}

	debug("%s engine initialized, now setting it as default for "
	    "RSA, DSA, and symmetric ciphers", PKCS11_ENGINE);

	/*
	 * Offloading RSA, DSA and symmetric ciphers to the engine is all we
	 * want. We don't offload Diffie-Helmann since we use longer DH keys
	 * than supported in ncp/n2cp (2048 bits). And, we don't offload digest
	 * operations since that would be beneficial if only big packets were
	 * processed (~8K). However, that's not the case. For example,
	 * SSH_MSG_CHANNEL_WINDOW_ADJUST messages are always small. Given the
	 * fact that digest operations are fast in software and the inherent
	 * overhead of offloading anything to HW is quite big, not offloading
	 * digests to HW actually makes SSH data transfer faster.
	 */
	if (!ENGINE_set_default_RSA(e)) {
		fatal("can't use %s engine for RSA", PKCS11_ENGINE);
	}
	if (!ENGINE_set_default_DSA(e)) {
		fatal("can't use %s engine for DSA", PKCS11_ENGINE);
	}
	if (!ENGINE_set_default_ciphers(e)) {
		fatal("can't use %s engine for ciphers", PKCS11_ENGINE);
	}

	debug("%s engine initialization complete", PKCS11_ENGINE);
	return (e);
}

/*
 * Finishes the PKCS#11 engine after all remaining structural and functional
 * references to the ENGINE structure are freed.
 */
void
pkcs11_engine_finish(void *engine)
{
	ENGINE *e = (ENGINE *)engine;

	debug("in pkcs11_engine_finish(), engine pointer is %p", e);
	/* UseOpenSSLEngine was 'no' */
	if (engine == NULL)
		return;

	debug("unregistering RSA");
	ENGINE_unregister_RSA(e);
	debug("unregistering DSA");
	ENGINE_unregister_DSA(e);
	debug("unregistering ciphers");
	ENGINE_unregister_ciphers(e);

	debug("calling ENGINE_finish()");
	ENGINE_finish(engine);
	debug("calling ENGINE_remove()");
	ENGINE_remove(engine);
	debug("calling ENGINE_free()");
	ENGINE_free(engine);
	debug("%s engine finished", PKCS11_ENGINE);
}
