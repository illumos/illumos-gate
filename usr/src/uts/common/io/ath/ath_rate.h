/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2002-2004 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer,
 * without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 * similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 * redistribution must be conditioned upon including a substantially
 * similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 * of any contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 */

#ifndef _ATH_RATE_H
#define	_ATH_RATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ath_impl.h"

void ath_rate_ctl_start(ath_t *asc, struct ieee80211_node *in);
void ath_rate_ctl_reset(ath_t *asc, enum ieee80211_state state);
void ath_rate_ctl(void *arg, struct ieee80211_node *in);
void ath_rate_update(ath_t *asc, struct ieee80211_node *in, int32_t rate);
void ath_rate_setup(ath_t *asc, uint32_t mode);
void ath_rate_cb(void *arg, struct ieee80211_node *in);

#ifdef __cplusplus
}
#endif

#endif /* _ATH_RATE_H */
