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

#ifndef _ATH_AUX_H
#define	_ATH_AUX_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ath_hal.h"
#include "ath_impl.h"

uint32_t ath_calcrxfilter(ath_t *asc);
void ath_beacon_config(ath_t *asc);
int ath_reset(ieee80211com_t *ic);
int32_t ath_startrecv(ath_t *asc);
void ath_stoprecv(ath_t *asc);
uint32_t ath_chan2flags(ieee80211com_t *isc,
    struct ieee80211_channel *chan);
int32_t ath_getchannels(ath_t *asc, uint32_t cc,
    HAL_BOOL outdoor, HAL_BOOL xchanmode);
void ath_chan_change(ath_t *asc, struct ieee80211_channel *chan);
int32_t ath_chan_set(ath_t *asc, struct ieee80211_channel *chan);
int ath_txq_setup(ath_t *asc);
void ath_txq_cleanup(ath_t *asc);
void ath_rate_setup(ath_t *asc, uint32_t mode);
void ath_setcurmode(ath_t *asc, enum ieee80211_phymode mode);
void ath_mode_init(ath_t *asc);
void ath_draintxq(ath_t *asc);
int ath_key_alloc(ieee80211com_t *ic, const struct ieee80211_key *k,
    ieee80211_keyix *keyix, ieee80211_keyix *rxkeyix);
int ath_key_delete(ieee80211com_t *ic, const struct ieee80211_key *k);
int ath_key_set(ieee80211com_t *ic, const struct ieee80211_key *k,
    const uint8_t mac[IEEE80211_ADDR_LEN]);
void ath_set_shortslot(ieee80211com_t *ic, int onoff);
const char *ath_get_hal_status_desc(HAL_STATUS status);

#ifdef __cplusplus
}
#endif

#endif /* _ATH_AUX_H */
