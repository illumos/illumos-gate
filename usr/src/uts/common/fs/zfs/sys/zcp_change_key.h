/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _SYS_ZCP_CHANGE_KEY_H
#define	_SYS_ZCP_CHANGE_KEY_H

#include <sys/types.h>
#include <sys/dmu.h>
#include <sys/dsl_crypt.h>

#ifdef __cplusplus
extern "C" {
#endif

void zcp_synctask_change_key_cleanup(void *arg);
int zcp_synctask_change_key_check(void *arg, dmu_tx_t *tx);
void zcp_synctask_change_key_sync(void *arg, dmu_tx_t *tx);
int zcp_synctask_change_key_create_params(const char *key, size_t keylen,
    zfs_keyformat_t keyformat, dsl_crypto_params_t **dcpp);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ZCP_CHANGE_KEY_H */
