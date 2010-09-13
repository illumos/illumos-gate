/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "arn_core.h"
#include "arn_hw.h"
#include "arn_regd.h"
#include "arn_regd_common.h"

static int
ath9k_regd_chansort(const void *a, const void *b)
{
	const struct ath9k_channel *ca = a;
	const struct ath9k_channel *cb = b;

	return (ca->channel == cb->channel) ?
	    (ca->channelFlags & CHAN_FLAGS) -
	    (cb->channelFlags & CHAN_FLAGS) : ca->channel - cb->channel;
}

static void
ath9k_regd_sort(void *a, uint32_t n, uint32_t size, ath_hal_cmp_t *cmp)
{
	uint8_t *aa = a;
	uint8_t *ai, *t;

	for (ai = aa + size; --n >= 1; ai += size)
		for (t = ai; t > aa; t -= size) {
			uint8_t *u = t - size;
			if (cmp(u, t) <= 0)
				break;
			swap(u, t, size);
		}
}

static uint16_t
ath9k_regd_get_eepromRD(struct ath_hal *ah)
{
	return (ah->ah_currentRD & ~WORLDWIDE_ROAMING_FLAG);
}

static boolean_t
ath9k_regd_is_chan_bm_zero(uint64_t *bitmask)
{
	int i;

	for (i = 0; i < BMLEN; i++) {
		if (bitmask[i] != 0)
			return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
ath9k_regd_is_eeprom_valid(struct ath_hal *ah)
{
	uint16_t rd = ath9k_regd_get_eepromRD(ah);
	int i;

	if (rd & COUNTRY_ERD_FLAG) {
		uint16_t cc = rd & ~COUNTRY_ERD_FLAG;
		for (i = 0; i < ARRAY_SIZE(allCountries); i++)
			if (allCountries[i].countryCode == cc)
				return (B_TRUE);
	} else {
		for (i = 0; i < ARRAY_SIZE(regDomainPairs); i++)
			if (regDomainPairs[i].regDmnEnum == rd)
				return (B_TRUE);
	}

	ARN_DBG((ARN_DBG_REGULATORY,
	    "%s: invalid regulatory domain/country code 0x%x\n",
	    __func__, rd));

	return (B_FALSE);
}

static boolean_t
ath9k_regd_is_fcc_midband_supported(struct ath_hal *ah)
{
	uint32_t regcap;

	regcap = ah->ah_caps.reg_cap;

	if (regcap & AR_EEPROM_EEREGCAP_EN_FCC_MIDBAND)
		return (B_TRUE);
	else
		return (B_FALSE);
}

static boolean_t
ath9k_regd_is_ccode_valid(struct ath_hal *ah, uint16_t cc)
{
	uint16_t rd;
	int i;

	if (cc == CTRY_DEFAULT)
		return (B_TRUE);
	if (cc == CTRY_DEBUG)
		return (B_TRUE);

	rd = ath9k_regd_get_eepromRD(ah);

	ARN_DBG((ARN_DBG_REGULATORY, "%s: EEPROM regdomain 0x%x\n",
	    __func__, rd));

	if (rd & COUNTRY_ERD_FLAG) {
		ARN_DBG((ARN_DBG_REGULATORY,
		    "%s: EEPROM setting is country code %u\n",
		    __func__, rd & ~COUNTRY_ERD_FLAG));
		return (cc == (rd & ~COUNTRY_ERD_FLAG));
	}

	for (i = 0; i < ARRAY_SIZE(allCountries); i++) {
		if (cc == allCountries[i].countryCode) {
#ifdef ARN_SUPPORT_11D
			if ((rd & WORLD_SKU_MASK) == WORLD_SKU_PREFIX)
				return (B_TRUE);
#endif
			if (allCountries[i].regDmnEnum == rd ||
			    rd == DEBUG_REG_DMN || rd == NO_ENUMRD)
				return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static void
ath9k_regd_get_wmodes_nreg(struct ath_hal *ah,
    struct country_code_to_enum_rd *country,
    struct regDomain *rd5GHz,
    uint8_t *modes_allowed)

{
	bcopy(ah->ah_caps.wireless_modes, modes_allowed,
	    sizeof (ah->ah_caps.wireless_modes));

	if (is_set(ATH9K_MODE_11G, ah->ah_caps.wireless_modes) &&
	    (!country->allow11g))
		clr_bit(ATH9K_MODE_11G, modes_allowed);

	if (is_set(ATH9K_MODE_11A, ah->ah_caps.wireless_modes) &&
	    (ath9k_regd_is_chan_bm_zero(rd5GHz->chan11a)))
		clr_bit(ATH9K_MODE_11A, modes_allowed);

	if (is_set(ATH9K_MODE_11NG_HT20, ah->ah_caps.wireless_modes) &&
	    (!country->allow11ng20))
		clr_bit(ATH9K_MODE_11NG_HT20, modes_allowed);

	if (is_set(ATH9K_MODE_11NA_HT20, ah->ah_caps.wireless_modes) &&
	    (!country->allow11na20))
		clr_bit(ATH9K_MODE_11NA_HT20, modes_allowed);

	if (is_set(ATH9K_MODE_11NG_HT40PLUS, ah->ah_caps.wireless_modes) &&
	    (!country->allow11ng40))
		clr_bit(ATH9K_MODE_11NG_HT40PLUS, modes_allowed);

	if (is_set(ATH9K_MODE_11NG_HT40MINUS, ah->ah_caps.wireless_modes) &&
	    (!country->allow11ng40))
		clr_bit(ATH9K_MODE_11NG_HT40MINUS, modes_allowed);

	if (is_set(ATH9K_MODE_11NA_HT40PLUS, ah->ah_caps.wireless_modes) &&
	    (!country->allow11na40))
		clr_bit(ATH9K_MODE_11NA_HT40PLUS, modes_allowed);

	if (is_set(ATH9K_MODE_11NA_HT40MINUS, ah->ah_caps.wireless_modes) &&
	    (!country->allow11na40))
		clr_bit(ATH9K_MODE_11NA_HT40MINUS, modes_allowed);
}

boolean_t
ath9k_regd_is_public_safety_sku(struct ath_hal *ah)
{
	uint16_t rd;

	rd = ath9k_regd_get_eepromRD(ah);

	switch (rd) {
	case FCC4_FCCA:
	case (CTRY_UNITED_STATES_FCC49 | COUNTRY_ERD_FLAG):
		return (B_TRUE);
	case DEBUG_REG_DMN:
	case NO_ENUMRD:
		if (ah->ah_countryCode == CTRY_UNITED_STATES_FCC49)
			return (B_TRUE);
		break;
	}
	return (B_FALSE);
}

static struct country_code_to_enum_rd *
ath9k_regd_find_country(uint16_t countryCode)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(allCountries); i++) {
		if (allCountries[i].countryCode == countryCode)
			return (&allCountries[i]);
	}
	return (NULL);
}

static uint16_t
ath9k_regd_get_default_country(struct ath_hal *ah)
{
	uint16_t rd;
	int i;

	rd = ath9k_regd_get_eepromRD(ah);
	if (rd & COUNTRY_ERD_FLAG) {
		struct country_code_to_enum_rd *country = NULL;
		uint16_t cc = rd & ~COUNTRY_ERD_FLAG;

		country = ath9k_regd_find_country(cc);
		if (country != NULL)
			return (cc);
	}

	for (i = 0; i < ARRAY_SIZE(regDomainPairs); i++)
		if (regDomainPairs[i].regDmnEnum == rd) {
			if (regDomainPairs[i].singleCC != 0)
				return (regDomainPairs[i].singleCC);
			else
				i = ARRAY_SIZE(regDomainPairs);
		}
	return (CTRY_DEFAULT);
}

static boolean_t
ath9k_regd_is_valid_reg_domain(int regDmn, struct regDomain *rd)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(regDomains); i++) {
		if (regDomains[i].regDmnEnum == regDmn) {
			if (rd != NULL) {
				(void) memcpy(rd, &regDomains[i],
				    sizeof (struct regDomain));
			}
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static boolean_t
ath9k_regd_is_valid_reg_domainPair(int regDmnPair)
{
	int i;

	if (regDmnPair == NO_ENUMRD)
		return (B_FALSE);
	for (i = 0; i < ARRAY_SIZE(regDomainPairs); i++) {
		if (regDomainPairs[i].regDmnEnum == regDmnPair)
			return (B_TRUE);
	}
	return (B_FALSE);
}

static boolean_t
ath9k_regd_get_wmode_regdomain(struct ath_hal *ah, int regDmn,
    uint16_t channelFlag, struct regDomain *rd)
{
	int i, found;
	uint64_t flags = NO_REQ;
	struct reg_dmn_pair_mapping *regPair = NULL;
	int regOrg;

	regOrg = regDmn;
	if (regDmn == CTRY_DEFAULT) {
		uint16_t rdnum;
		rdnum = ath9k_regd_get_eepromRD(ah);

		if (!(rdnum & COUNTRY_ERD_FLAG)) {
			if (ath9k_regd_is_valid_reg_domain(rdnum, NULL) ||
			    ath9k_regd_is_valid_reg_domainPair(rdnum)) {
				regDmn = rdnum;
			}
		}
	}

	if ((regDmn & MULTI_DOMAIN_MASK) == 0) {
		for (i = 0, found = 0;
		    (i < ARRAY_SIZE(regDomainPairs)) && (!found); i++) {
			if (regDomainPairs[i].regDmnEnum == regDmn) {
				regPair = &regDomainPairs[i];
				found = 1;
			}
		}
		if (!found) {
			ARN_DBG((ARN_DBG_REGULATORY,
			    "%s: Failed to find reg domain pair %u\n",
			    __func__, regDmn));
			return (B_FALSE);
		}
		if (!(channelFlag & CHANNEL_2GHZ)) {
			regDmn = regPair->regDmn5GHz;
			flags = regPair->flags5GHz;
		}
		if (channelFlag & CHANNEL_2GHZ) {
			regDmn = regPair->regDmn2GHz;
			flags = regPair->flags2GHz;
		}
	}

	found = ath9k_regd_is_valid_reg_domain(regDmn, rd);
	if (!found) {
		ARN_DBG((ARN_DBG_REGULATORY,
		    "%s: Failed to find unitary reg domain %u\n",
		    __func__, regDmn));
		return (B_FALSE);
	} else {
		rd->pscan &= regPair->pscanMask;
		if (((regOrg & MULTI_DOMAIN_MASK) == 0) &&
		    (flags != NO_REQ)) {
			rd->flags = (uint32_t)flags; /* LINT */
		}

		rd->flags &= (channelFlag & CHANNEL_2GHZ) ?
		    REG_DOMAIN_2GHZ_MASK : REG_DOMAIN_5GHZ_MASK;
		return (B_TRUE);
	}
}

static boolean_t
ath9k_regd_is_bit_set(int bit, uint64_t *bitmask)
{
	int byteOffset, bitnum;
	uint64_t val;

	byteOffset = bit / 64;
	bitnum = bit - byteOffset * 64;
	val = ((uint64_t)1) << bitnum;
	if (bitmask[byteOffset] & val)
		return (B_TRUE);
	else
		return (B_FALSE);
}

static void
ath9k_regd_add_reg_classid(uint8_t *regclassids, uint32_t maxregids,
    uint32_t *nregids, uint8_t regclassid)
{
	int i;

	if (regclassid == 0)
		return;

	for (i = 0; i < maxregids; i++) {
		if (regclassids[i] == regclassid)
			return;
		if (regclassids[i] == 0)
			break;
	}

	if (i == maxregids)
		return;
	else {
		regclassids[i] = regclassid;
		*nregids += 1;
	}
}

static boolean_t
ath9k_regd_get_eeprom_reg_ext_bits(struct ath_hal *ah,
    enum reg_ext_bitmap bit)
{
	return ((ah->ah_currentRDExt & (1 << bit)) ? B_TRUE : B_FALSE);
}

#ifdef ARN_NF_PER_CHAN

static void
ath9k_regd_init_rf_buffer(struct ath9k_channel *ichans, int nchans)
{
	int i, j, next;

	for (next = 0; next < nchans; next++) {
		for (i = 0; i < NUM_NF_READINGS; i++) {
			ichans[next].nfCalHist[i].currIndex = 0;
			ichans[next].nfCalHist[i].privNF =
			    AR_PHY_CCA_MAX_GOOD_VALUE;
			ichans[next].nfCalHist[i].invalidNFcount =
			    AR_PHY_CCA_FILTERWINDOW_LENGTH;
			for (j = 0; j < ATH9K_NF_CAL_HIST_MAX; j++) {
				ichans[next].nfCalHist[i].nfCalBuffer[j] =
				    AR_PHY_CCA_MAX_GOOD_VALUE;
			}
		}
	}
}
#endif

static int
ath9k_regd_is_chan_present(struct ath_hal *ah, uint16_t c)
{
	int i;

	for (i = 0; i < 150; i++) {
		if (!ah->ah_channels[i].channel)
			return (-1);
		else if (ah->ah_channels[i].channel == c)
			return (i);
	}

	return (-1);
}

/* ARGSUSED */
static boolean_t
ath9k_regd_add_channel(
    struct ath_hal *ah,
    uint16_t c,
    uint16_t c_lo,
    uint16_t c_hi,
    uint16_t maxChan,
    uint8_t ctl,
    int pos,
    struct regDomain rd5GHz,
    struct RegDmnFreqBand *fband,
    struct regDomain *rd,
    const struct cmode *cm,
    struct ath9k_channel *ichans,
    boolean_t enableExtendedChannels)
{
	struct ath9k_channel *chan;
	int ret;
	uint32_t channelFlags = 0;
	uint8_t privFlags = 0;

	if (!(c_lo <= c && c <= c_hi)) {
		ARN_DBG((ARN_DBG_REGULATORY,
		    "%s: c %u out of range [%u..%u]\n",
		    __func__, c, c_lo, c_hi));
		return (B_FALSE);
	}
	if ((fband->channelBW == CHANNEL_HALF_BW) &&
	    !(ah->ah_caps.hw_caps & ATH9K_HW_CAP_CHAN_HALFRATE)) {
		ARN_DBG((ARN_DBG_REGULATORY,
		    "%s: Skipping %u half rate channel\n",
		    __func__, c));
		return (B_FALSE);
	}

	if ((fband->channelBW == CHANNEL_QUARTER_BW) &&
	    !(ah->ah_caps.hw_caps & ATH9K_HW_CAP_CHAN_QUARTERRATE)) {
		ARN_DBG((ARN_DBG_REGULATORY,
		    "%s: Skipping %u quarter rate channel\n",
		    __func__, c));
		return (B_FALSE);
	}

	if (((c + fband->channelSep) / 2) > (maxChan + HALF_MAXCHANBW)) {
		ARN_DBG((ARN_DBG_REGULATORY,
		    "%s: c %u > maxChan %u\n",
		    __func__, c, maxChan));
		return (B_FALSE);
	}

	if ((fband->usePassScan & IS_ECM_CHAN) && !enableExtendedChannels) {
		ARN_DBG((ARN_DBG_REGULATORY,
		    "Skipping ecm channel\n"));
		return (B_FALSE);
	}

	if ((rd->flags & NO_HOSTAP) && (ah->ah_opmode == ATH9K_M_HOSTAP)) {
		ARN_DBG((ARN_DBG_REGULATORY,
		    "Skipping HOSTAP channel\n"));
		return (B_FALSE);
	}

	if (IS_HT40_MODE(cm->mode) &&
	    !(ath9k_regd_get_eeprom_reg_ext_bits(ah, REG_EXT_FCC_DFS_HT40)) &&
	    (fband->useDfs) &&
	    (rd->conformanceTestLimit != MKK)) {
		ARN_DBG((ARN_DBG_REGULATORY,
		    "Skipping HT40 channel (en_fcc_dfs_ht40 = 0)\n"));
		return (B_FALSE);
	}

	if (IS_HT40_MODE(cm->mode) &&
	    !(ath9k_regd_get_eeprom_reg_ext_bits(ah,
	    REG_EXT_JAPAN_NONDFS_HT40)) &&
	    !(fband->useDfs) && (rd->conformanceTestLimit == MKK)) {
		ARN_DBG((ARN_DBG_REGULATORY,
		    "Skipping HT40 channel (en_jap_ht40 = 0)\n"));
		return (B_FALSE);
	}

	if (IS_HT40_MODE(cm->mode) &&
	    !(ath9k_regd_get_eeprom_reg_ext_bits(ah, REG_EXT_JAPAN_DFS_HT40)) &&
	    (fband->useDfs) &&
	    (rd->conformanceTestLimit == MKK)) {
		ARN_DBG((ARN_DBG_REGULATORY,
		    "Skipping HT40 channel (en_jap_dfs_ht40 = 0)\n"));
		return (B_FALSE);
	}

	/* Calculate channel flags */

	channelFlags = cm->flags;

	switch (fband->channelBW) {
	case CHANNEL_HALF_BW:
		channelFlags |= CHANNEL_HALF;
		break;
	case CHANNEL_QUARTER_BW:
		channelFlags |= CHANNEL_QUARTER;
		break;
	}

	if (fband->usePassScan & rd->pscan)
		channelFlags |= CHANNEL_PASSIVE;
	else
		channelFlags &= ~CHANNEL_PASSIVE;
	if (fband->useDfs & rd->dfsMask)
		privFlags = CHANNEL_DFS;
	else
		privFlags = 0;
	if (rd->flags & LIMIT_FRAME_4MS)
		privFlags |= CHANNEL_4MS_LIMIT;
	if (privFlags & CHANNEL_DFS)
		privFlags |= CHANNEL_DISALLOW_ADHOC;
	if (rd->flags & ADHOC_PER_11D)
		privFlags |= CHANNEL_PER_11D_ADHOC;

	if (channelFlags & CHANNEL_PASSIVE) {
		if ((c < 2412) || (c > 2462)) {
			if (rd5GHz.regDmnEnum == MKK1 ||
			    rd5GHz.regDmnEnum == MKK2) {
				uint32_t regcap = ah->ah_caps.reg_cap;
				if (!(regcap &
				    (AR_EEPROM_EEREGCAP_EN_KK_U1_EVEN |
				    AR_EEPROM_EEREGCAP_EN_KK_U2 |
				    AR_EEPROM_EEREGCAP_EN_KK_MIDBAND)) &&
				    isUNII1OddChan(c)) {
					channelFlags &= ~CHANNEL_PASSIVE;
				} else {
					privFlags |= CHANNEL_DISALLOW_ADHOC;
				}
			} else {
				privFlags |= CHANNEL_DISALLOW_ADHOC;
			}
		}
	}

	if ((cm->mode == ATH9K_MODE_11A) ||
	    (cm->mode == ATH9K_MODE_11NA_HT20) ||
	    (cm->mode == ATH9K_MODE_11NA_HT40PLUS) ||
	    (cm->mode == ATH9K_MODE_11NA_HT40MINUS)) {
		if (rd->flags & (ADHOC_NO_11A | DISALLOW_ADHOC_11A))
			privFlags |= CHANNEL_DISALLOW_ADHOC;
	}

	/* Fill in channel details */

	ret = ath9k_regd_is_chan_present(ah, c);
	if (ret == -1) {
		chan = &ah->ah_channels[pos];
		chan->channel = c;
		chan->maxRegTxPower = fband->powerDfs;
		chan->antennaMax = fband->antennaMax;
		chan->regDmnFlags = rd->flags;
		chan->maxTxPower = AR5416_MAX_RATE_POWER;
		chan->minTxPower = AR5416_MAX_RATE_POWER;
		chan->channelFlags = channelFlags;
		chan->privFlags = privFlags;
	} else {
		chan = &ah->ah_channels[ret];
		chan->channelFlags |= channelFlags;
		chan->privFlags |= privFlags;
	}

	/* Set CTLs */

	if ((cm->flags & CHANNEL_ALL) == CHANNEL_A)
		chan->conformanceTestLimit[0] = ctl;
	else if ((cm->flags & CHANNEL_ALL) == CHANNEL_B)
		chan->conformanceTestLimit[1] = ctl;
	else if ((cm->flags & CHANNEL_ALL) == CHANNEL_G)
		chan->conformanceTestLimit[2] = ctl;

	return ((ret == -1) ? B_TRUE : B_FALSE);
}

static boolean_t
ath9k_regd_japan_check(struct ath_hal *ah, int b, struct regDomain *rd5GHz)
{
	boolean_t skipband = B_FALSE;
	int i;
	uint32_t regcap;

	for (i = 0; i < ARRAY_SIZE(j_bandcheck); i++) {
		if (j_bandcheck[i].freqbandbit == b) {
			regcap = ah->ah_caps.reg_cap;
			if ((j_bandcheck[i].eepromflagtocheck & regcap) == 0) {
				skipband = B_TRUE;
			} else if ((regcap & AR_EEPROM_EEREGCAP_EN_KK_U2) ||
			    (regcap & AR_EEPROM_EEREGCAP_EN_KK_MIDBAND)) {
				rd5GHz->dfsMask |= DFS_MKK4;
				rd5GHz->pscan |= PSCAN_MKK3;
			}
			break;
		}
	}

	ARN_DBG((ARN_DBG_REGULATORY,
	    "%s: Skipping %d freq band\n",
	    __func__, j_bandcheck[i].freqbandbit));

	return (skipband);
}

boolean_t
ath9k_regd_init_channels(
    struct ath_hal *ah,
    uint32_t maxchans,
    uint32_t *nchans,
    uint8_t *regclassids,
    uint32_t maxregids,
    uint32_t *nregids,
    uint16_t cc,
    boolean_t enableOutdoor,
    boolean_t enableExtendedChannels)
{
	uint16_t maxChan = 7000;
	struct country_code_to_enum_rd *country = NULL;
	struct regDomain rd5GHz, rd2GHz;
	const struct cmode *cm;
	struct ath9k_channel *ichans = &ah->ah_channels[0];
	int next = 0, b;
	uint8_t ctl;
	int regdmn;
	uint16_t chanSep;
	uint8_t *modes_avail;
	uint8_t modes_allowed[4];

	(void) memset(modes_allowed, 0, sizeof (modes_allowed));
	ARN_DBG((ARN_DBG_REGULATORY, "arn: ath9k_regd_init_channels(): "
	    "cc %u %s %s\n",
	    cc,
	    enableOutdoor ? "Enable outdoor" : "",
	    enableExtendedChannels ? "Enable ecm" : ""));

	if (!ath9k_regd_is_ccode_valid(ah, cc)) {
		ARN_DBG((ARN_DBG_XMIT, "arn: ath9k_regd_init_channels(): "
		    "invalid country code %d\n", cc));
		return (B_FALSE);
	}

	if (!ath9k_regd_is_eeprom_valid(ah)) {
		ARN_DBG((ARN_DBG_ANY, "arn: ath9k_regd_init_channels(): "
		    "invalid EEPROM contents\n"));
		return (B_FALSE);
	}

	ah->ah_countryCode = ath9k_regd_get_default_country(ah);

	if (ah->ah_countryCode == CTRY_DEFAULT) {
		ah->ah_countryCode = cc & COUNTRY_CODE_MASK;
		if ((ah->ah_countryCode == CTRY_DEFAULT) &&
		    (ath9k_regd_get_eepromRD(ah) == CTRY_DEFAULT)) {
			ah->ah_countryCode = CTRY_UNITED_STATES;
		}
	}

#ifdef ARN_SUPPORT_11D
	if (ah->ah_countryCode == CTRY_DEFAULT) {
		regdmn = ath9k_regd_get_eepromRD(ah);
		country = NULL;
	} else {
#endif
		country = ath9k_regd_find_country(ah->ah_countryCode);
		if (country == NULL) {
			ARN_DBG((ARN_DBG_REGULATORY,
			    "arn: ath9k_regd_init_channels(): "
			    "Country is NULL!!!!, cc= %d\n",
			    ah->ah_countryCode));

			return (B_FALSE);
		} else {
			regdmn = country->regDmnEnum;
#ifdef ARN_SUPPORT_11D
			if (((ath9k_regd_get_eepromRD(ah) &
			    WORLD_SKU_MASK) == WORLD_SKU_PREFIX) &&
			    (cc == CTRY_UNITED_STATES)) {
				if (!isWwrSKU_NoMidband(ah) &&
				    ath9k_regd_is_fcc_midband_supported(ah))
					regdmn = FCC3_FCCA;
				else
					regdmn = FCC1_FCCA;
			}
#endif
		}
#ifdef ARN_SUPPORT_11D
	}
#endif
	if (!ath9k_regd_get_wmode_regdomain(ah, regdmn,
	    ~CHANNEL_2GHZ, &rd5GHz)) {
		ARN_DBG((ARN_DBG_REGULATORY, "arn: ath9k_regd_init_channels(): "
		    "couldn't find unitary "
		    "5GHz reg domain for country %u\n",
		    ah->ah_countryCode));
		return (B_FALSE);
	}
	if (!ath9k_regd_get_wmode_regdomain(ah, regdmn,
	    CHANNEL_2GHZ, &rd2GHz)) {
		ARN_DBG((ARN_DBG_REGULATORY, "arn: ath9k_regd_init_channels(): "
		    "couldn't find unitary 2GHz "
		    "reg domain for country %u\n",
		    ah->ah_countryCode));
		return (B_FALSE);
	}

	if (!isWwrSKU(ah) && ((rd5GHz.regDmnEnum == FCC1) ||
	    (rd5GHz.regDmnEnum == FCC2))) {
		if (ath9k_regd_is_fcc_midband_supported(ah)) {
			if (!ath9k_regd_get_wmode_regdomain(ah,
			    FCC3_FCCA, ~CHANNEL_2GHZ, &rd5GHz)) {
				ARN_DBG((ARN_DBG_REGULATORY,
				    "arn: ath9k_regd_init_channels(): "
				    "couldn't find unitary 5GHz "
				    "reg domain for country %u\n",
				    ah->ah_countryCode));
				return (B_FALSE);
			}
		}
	}

	if (country == NULL) {
		modes_avail = ah->ah_caps.wireless_modes;
	} else {
		ath9k_regd_get_wmodes_nreg(ah, country, &rd5GHz, modes_allowed);
		modes_avail = modes_allowed;

		if (!enableOutdoor)
			maxChan = country->outdoorChanStart;
	}

	next = 0;

	if (maxchans > ARRAY_SIZE(ah->ah_channels))
		maxchans = ARRAY_SIZE(ah->ah_channels);

	for (cm = modes; cm < &modes[ARRAY_SIZE(modes)]; cm++) {
		uint16_t c, c_hi, c_lo;
		uint64_t *channelBM = NULL;
		struct regDomain *rd = NULL;
		struct RegDmnFreqBand *fband = NULL, *freqs;
		int8_t low_adj = 0, hi_adj = 0;

		if (!is_set(cm->mode, modes_avail)) {
			ARN_DBG((ARN_DBG_REGULATORY,
			    "%s: !avail mode %d flags 0x%x\n",
			    __func__, cm->mode, cm->flags));
			continue;
		}
		if (!ath9k_get_channel_edges(ah, cm->flags, &c_lo, &c_hi)) {
			ARN_DBG((ARN_DBG_REGULATORY,
			    "arn: ath9k_regd_init_channels(): "
			    "channels 0x%x not supported "
			    "by hardware\n", cm->flags));
			continue;
		}

		switch (cm->mode) {
		case ATH9K_MODE_11A:
		case ATH9K_MODE_11NA_HT20:
		case ATH9K_MODE_11NA_HT40PLUS:
		case ATH9K_MODE_11NA_HT40MINUS:
			rd = &rd5GHz;
			channelBM = rd->chan11a;
			freqs = &regDmn5GhzFreq[0];
			ctl = rd->conformanceTestLimit;
			break;
		case ATH9K_MODE_11B:
			rd = &rd2GHz;
			channelBM = rd->chan11b;
			freqs = &regDmn2GhzFreq[0];
			ctl = rd->conformanceTestLimit | CTL_11B;
			break;
		case ATH9K_MODE_11G:
		case ATH9K_MODE_11NG_HT20:
		case ATH9K_MODE_11NG_HT40PLUS:
		case ATH9K_MODE_11NG_HT40MINUS:
			rd = &rd2GHz;
			channelBM = rd->chan11g;
			freqs = &regDmn2Ghz11gFreq[0];
			ctl = rd->conformanceTestLimit | CTL_11G;
			break;
		default:
			ARN_DBG((ARN_DBG_REGULATORY,
			    "arn: ath9k_regd_init_channels(): "
			    "Unknown HAL mode 0x%x\n", cm->mode));
			continue;
		}

		if (ath9k_regd_is_chan_bm_zero(channelBM))
			continue;

		if ((cm->mode == ATH9K_MODE_11NA_HT40PLUS) ||
		    (cm->mode == ATH9K_MODE_11NG_HT40PLUS)) {
			hi_adj = -20;
		}

		if ((cm->mode == ATH9K_MODE_11NA_HT40MINUS) ||
		    (cm->mode == ATH9K_MODE_11NG_HT40MINUS)) {
			low_adj = 20;
		}

		/* XXX: Add a helper here instead */
		for (b = 0; b < 64 * BMLEN; b++) {
			if (ath9k_regd_is_bit_set(b, channelBM)) {
				fband = &freqs[b];
				if (rd5GHz.regDmnEnum == MKK1 ||
				    rd5GHz.regDmnEnum == MKK2) {
					if (ath9k_regd_japan_check(ah,
					    b, &rd5GHz))
						continue;
				}

				ath9k_regd_add_reg_classid(regclassids,
				    maxregids,
				    nregids,
				    fband->regClassId);

				if (IS_HT40_MODE(cm->mode) && (rd == &rd5GHz)) {
					chanSep = 40;
					if (fband->lowChannel == 5280)
						low_adj += 20;

					if (fband->lowChannel == 5170)
						continue;
				} else
					chanSep = fband->channelSep;

				for (c = fband->lowChannel + low_adj;
				    ((c <= (fband->highChannel + hi_adj)) &&
				    (c >= (fband->lowChannel + low_adj)));
				    c += chanSep) {
					if (next >= maxchans) {
						ARN_DBG((ARN_DBG_REGULATORY,
						    "too many channels "
						    "for channel table\n"));
						goto done;
					}
					if (ath9k_regd_add_channel(ah,
					    c, c_lo, c_hi,
					    maxChan, ctl,
					    next,
					    rd5GHz,
					    fband, rd, cm,
					    ichans,
					    enableExtendedChannels))
						next++;
				}
				if (IS_HT40_MODE(cm->mode) &&
				    (fband->lowChannel == 5280)) {
					low_adj -= 20;
				}
			}
		}
	}
done:
	if (next != 0) {
		int i;

		if (next > ARRAY_SIZE(ah->ah_channels)) {
			ARN_DBG((ARN_DBG_REGULATORY,
			    "arn: ath9k_regd_init_channels(): "
			    "too many channels %u; truncating to %u\n",
			    next, (int)ARRAY_SIZE(ah->ah_channels)));
			next = ARRAY_SIZE(ah->ah_channels);
		}
#ifdef ARN_NF_PER_CHAN
		ath9k_regd_init_rf_buffer(ichans, next);
#endif
		ath9k_regd_sort(ichans, next, sizeof (struct ath9k_channel),
		    ath9k_regd_chansort);

		ah->ah_nchan = next;

		ARN_DBG((ARN_DBG_REGULATORY, "arn: ath9k_regd_init_channels(): "
		    "Channel list:\n"));
		for (i = 0; i < next; i++) {
			ARN_DBG((ARN_DBG_REGULATORY, "arn: "
			    "chan: %d flags: 0x%x\n",
			    ah->ah_channels[i].channel,
			    ah->ah_channels[i].channelFlags));
		}
	}
	*nchans = next;

	ah->ah_countryCode = ah->ah_countryCode;

	ah->ah_currentRDInUse = (uint16_t)regdmn; /* LINT */
	ah->ah_currentRD5G = rd5GHz.regDmnEnum;
	ah->ah_currentRD2G = rd2GHz.regDmnEnum;
	if (country == NULL) {
		ah->ah_iso[0] = 0;
		ah->ah_iso[1] = 0;
	} else {
		ah->ah_iso[0] = country->isoName[0];
		ah->ah_iso[1] = country->isoName[1];
	}

	return (next != 0);
}

struct ath9k_channel *
ath9k_regd_check_channel(struct ath_hal *ah, const struct ath9k_channel *c)
{
	struct ath9k_channel *base, *cc;

	int flags = c->channelFlags & CHAN_FLAGS;
	int n, lim;

	ARN_DBG((ARN_DBG_REGULATORY, "arn: "
	    "%s: channel %u/0x%x (0x%x) requested\n", __func__,
	    c->channel, c->channelFlags, flags));

	cc = ah->ah_curchan;
	if (cc != NULL && cc->channel == c->channel &&
	    (cc->channelFlags & CHAN_FLAGS) == flags) {
		if ((cc->privFlags & CHANNEL_INTERFERENCE) &&
		    (cc->privFlags & CHANNEL_DFS))
			return (NULL);
		else
			return (cc);
	}

	base = ah->ah_channels;
	n = ah->ah_nchan;

	for (lim = n; lim != 0; lim >>= 1) {
		int d;
		cc = &base[lim >> 1];
		d = c->channel - cc->channel;
		if (d == 0) {
			if ((cc->channelFlags & CHAN_FLAGS) == flags) {
				if ((cc->privFlags & CHANNEL_INTERFERENCE) &&
				    (cc->privFlags & CHANNEL_DFS))
					return (NULL);
				else
					return (cc);
			}
			d = flags - (cc->channelFlags & CHAN_FLAGS);
		}

		ARN_DBG((ARN_DBG_REGULATORY, "arn: "
		    "%s: channel %u/0x%x d %d\n", __func__,
		    cc->channel, cc->channelFlags, d));

		if (d > 0) {
			base = cc + 1;
			lim--;
		}
	}

	ARN_DBG((ARN_DBG_REGULATORY, "arn: "
	    "%s: no match for %u/0x%x\n",
	    __func__, c->channel, c->channelFlags));

	return (NULL);
}

uint32_t
ath9k_regd_get_antenna_allowed(struct ath_hal *ah, struct ath9k_channel *chan)
{
	struct ath9k_channel *ichan = NULL;

	ichan = ath9k_regd_check_channel(ah, chan);
	if (!ichan)
		return (0);

	return (ichan->antennaMax);
}

uint32_t
ath9k_regd_get_ctl(struct ath_hal *ah, struct ath9k_channel *chan)
{
	uint32_t ctl = NO_CTL;
	struct ath9k_channel *ichan;

	if (ah->ah_countryCode == CTRY_DEFAULT && isWwrSKU(ah)) {
		if (IS_CHAN_B(chan))
			ctl = SD_NO_CTL | CTL_11B;
		else if (IS_CHAN_G(chan))
			ctl = SD_NO_CTL | CTL_11G;
		else
			ctl = SD_NO_CTL | CTL_11A;
	} else {
		ichan = ath9k_regd_check_channel(ah, chan);
		if (ichan != NULL) {
			/* FIXME */
			if (IS_CHAN_A(ichan))
				ctl = ichan->conformanceTestLimit[0];
			else if (IS_CHAN_B(ichan))
				ctl = ichan->conformanceTestLimit[1];
			else if (IS_CHAN_G(ichan))
				ctl = ichan->conformanceTestLimit[2];

			if (IS_CHAN_G(chan) && (ctl & 0xf) == CTL_11B)
				ctl = (ctl & ~0xf) | CTL_11G;
		}
	}
	return (ctl);
}

void
ath9k_regd_get_current_country(struct ath_hal *ah,
    struct ath9k_country_entry *ctry)
{
	uint16_t rd = ath9k_regd_get_eepromRD(ah);

	ctry->isMultidomain = B_FALSE;
	if (rd == CTRY_DEFAULT)
		ctry->isMultidomain = B_TRUE;
	else if (!(rd & COUNTRY_ERD_FLAG))
		ctry->isMultidomain = isWwrSKU(ah);

	ctry->countryCode = ah->ah_countryCode;
	ctry->regDmnEnum = ah->ah_currentRD;
	ctry->regDmn5G = ah->ah_currentRD5G;
	ctry->regDmn2G = ah->ah_currentRD2G;
	ctry->iso[0] = ah->ah_iso[0];
	ctry->iso[1] = ah->ah_iso[1];
	ctry->iso[2] = ah->ah_iso[2];
}
