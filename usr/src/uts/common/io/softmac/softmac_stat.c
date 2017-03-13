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
 *
 * Copyright 2015 Garrett D'Amore <garret@damore.org>
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/mac.h>
#include <sys/dls.h>
#include <sys/softmac_impl.h>

typedef struct i_softmac_stat_info_s {
	uint_t		ssi_stat;
	char		*ssi_name;
	char		*ssi_alias;
} i_softmac_stat_info_t;

/*
 * Must be the same order as mac_driver_stat.
 */
static i_softmac_stat_info_t	i_softmac_driver_si[] = {
	{ MAC_STAT_IFSPEED,	"ifspeed", 	"link_speed"	},
	{ MAC_STAT_MULTIRCV,	"multircv",	NULL		},
	{ MAC_STAT_BRDCSTRCV,	"brdcstrcv", 	NULL		},
	{ MAC_STAT_MULTIXMT,	"multixmt",	NULL		},
	{ MAC_STAT_BRDCSTXMT,	"brdcstxmt",	NULL		},
	{ MAC_STAT_NORCVBUF,	"norcvbuf",	"rx_no_buf"	},
	{ MAC_STAT_IERRORS,	"ierrors",	NULL		},
	{ MAC_STAT_UNKNOWNS,	"unknowns",	NULL		},
	{ MAC_STAT_NOXMTBUF,	"noxmtbuf",	"No Txpkt "	},
	{ MAC_STAT_OERRORS,	"oerrors",	NULL		},
	{ MAC_STAT_COLLISIONS,	"collisions",	NULL		},
	{ MAC_STAT_RBYTES,	"rbytes64",	"rbytes"	},
	{ MAC_STAT_IPACKETS,	"ipackets64",	"ipackets"	},
	{ MAC_STAT_OBYTES,	"obytes64",	"obytes"	},
	{ MAC_STAT_OPACKETS,	"opackets64",	"opackets"	},
	{ MAC_STAT_UNDERFLOWS,	"uflo",		NULL		},
	{ MAC_STAT_OVERFLOWS,	"oflo",		NULL		}
};

#define	SOFTMAC_DRIVER_SI_SZ						\
	(sizeof (i_softmac_driver_si) / sizeof (i_softmac_driver_si[0]))

/*
 * Must be the same order as ether_stat.
 */
static i_softmac_stat_info_t	i_softmac_ether_si[] = {
	{ ETHER_STAT_ALIGN_ERRORS,	"align_errors",
	    "alignment_err" },
	{ ETHER_STAT_FCS_ERRORS, 	"fcs_errors",		"crc_err" },
	{ ETHER_STAT_FIRST_COLLISIONS,	"first_collisions",	NULL },
	{ ETHER_STAT_MULTI_COLLISIONS,	"multi_collisions",	NULL },
	{ ETHER_STAT_SQE_ERRORS,	"sqe_errors",		NULL },
	{ ETHER_STAT_DEFER_XMTS,	"defer_xmts",		NULL },
	{ ETHER_STAT_TX_LATE_COLLISIONS, "tx_late_collisions",
	    "late_collisions" },
	{ ETHER_STAT_EX_COLLISIONS,	"ex_collisions",
	    "excessive_collisions" },
	{ ETHER_STAT_MACXMT_ERRORS,	"macxmt_errors",	NULL },
	{ ETHER_STAT_CARRIER_ERRORS,	"carrier_errors",	NULL },
	{ ETHER_STAT_TOOLONG_ERRORS,	"toolong_errors", 	"length_err" },
	{ ETHER_STAT_MACRCV_ERRORS, 	"macrcv_errors",
	    "Rx Error Count" },

	{ ETHER_STAT_XCVR_ADDR,		"xcvr_addr",		NULL },
	{ ETHER_STAT_XCVR_ID,		"xcvr_id",		NULL },
	{ ETHER_STAT_XCVR_INUSE,	"xcvr_inuse",		NULL },

	{ ETHER_STAT_CAP_1000FDX,	"cap_1000fdx",		NULL },
	{ ETHER_STAT_CAP_1000HDX,	"cap_1000hdx",		NULL },
	{ ETHER_STAT_CAP_100FDX,	"cap_100fdx",		NULL },
	{ ETHER_STAT_CAP_100HDX,	"cap_100hdx",		NULL },
	{ ETHER_STAT_CAP_10FDX,		"cap_10fdx",		NULL },
	{ ETHER_STAT_CAP_10HDX,		"cap_10hdx",		NULL },
	{ ETHER_STAT_CAP_ASMPAUSE,	"cap_asmpause",		NULL },
	{ ETHER_STAT_CAP_PAUSE,		"cap_pause",		NULL },
	{ ETHER_STAT_CAP_AUTONEG,	"cap_autoneg",		NULL },

	{ ETHER_STAT_ADV_CAP_1000FDX,	"adv_cap_1000fdx",	NULL },
	{ ETHER_STAT_ADV_CAP_1000HDX,	"adv_cap_1000hdx",	NULL },
	{ ETHER_STAT_ADV_CAP_100FDX,	"adv_cap_100fdx",	NULL },
	{ ETHER_STAT_ADV_CAP_100HDX,	"adv_cap_100hdx",	NULL },
	{ ETHER_STAT_ADV_CAP_10FDX,	"adv_cap_10fdx",	NULL },
	{ ETHER_STAT_ADV_CAP_10HDX,	"adv_cap_10hdx",	NULL },
	{ ETHER_STAT_ADV_CAP_ASMPAUSE,	"adv_cap_asmpause",	NULL },
	{ ETHER_STAT_ADV_CAP_PAUSE,	"adv_cap_pause", 	NULL },
	{ ETHER_STAT_ADV_CAP_AUTONEG,	"adv_cap_autoneg", 	NULL },

	{ ETHER_STAT_LP_CAP_1000FDX,	"lp_cap_1000fdx",	NULL },
	{ ETHER_STAT_LP_CAP_1000HDX,	"lp_cap_1000hdx",	NULL },
	{ ETHER_STAT_LP_CAP_100FDX,	"lp_cap_100fdx",	NULL },
	{ ETHER_STAT_LP_CAP_100HDX,	"lp_cap_100hdx",	NULL },
	{ ETHER_STAT_LP_CAP_10FDX,	"lp_cap_10fdx",		NULL },
	{ ETHER_STAT_LP_CAP_10HDX,	"lp_cap_10hdx",		NULL },
	{ ETHER_STAT_LP_CAP_ASMPAUSE,	"lp_cap_asmpause",	NULL },
	{ ETHER_STAT_LP_CAP_PAUSE,	"lp_cap_pause",		NULL },
	{ ETHER_STAT_LP_CAP_AUTONEG,	"lp_cap_autoneg",	NULL },

	{ ETHER_STAT_LINK_ASMPAUSE,	"link_asmpause",	NULL },
	{ ETHER_STAT_LINK_PAUSE,	"link_pause",		NULL },
	{ ETHER_STAT_LINK_AUTONEG,	"link_autoneg", 	NULL },
	{ ETHER_STAT_LINK_DUPLEX,	"link_duplex",		"duplex" },

	{ ETHER_STAT_TOOSHORT_ERRORS,	"runt_errors",		NULL },
	{ ETHER_STAT_CAP_REMFAULT,	"cap_rem_fault",	NULL },
	{ ETHER_STAT_ADV_REMFAULT,	"adv_rem_fault",	NULL },
	{ ETHER_STAT_LP_REMFAULT,	"lp_rem_fault",		NULL },

	{ ETHER_STAT_JABBER_ERRORS,	"jabber_errors",	NULL },
	{ ETHER_STAT_CAP_100T4,		"cap_100T4",		NULL },
	{ ETHER_STAT_ADV_CAP_100T4,	"adv_cap_100T4",	NULL },
	{ ETHER_STAT_LP_CAP_100T4,	"lp_cap_100T4",		NULL },

	{ ETHER_STAT_CAP_10GFDX,	"cap_10gfdx",		NULL },
	{ ETHER_STAT_ADV_CAP_10GFDX,	"adv_cap_10gfdx",	NULL },
	{ ETHER_STAT_LP_CAP_1000FDX,	"lp_cap_10gfdx",	NULL },

	{ ETHER_STAT_CAP_40GFDX,	"cap_40gfdx",		NULL },
	{ ETHER_STAT_ADV_CAP_40GFDX,	"adv_cap_40gfdx",	NULL },
	{ ETHER_STAT_LP_CAP_40GFDX,	"lp_cap_40gfdx",	NULL },

	{ ETHER_STAT_CAP_100GFDX,	"cap_100gfdx",		NULL },
	{ ETHER_STAT_ADV_CAP_100GFDX,	"adv_cap_100gfdx",	NULL },
	{ ETHER_STAT_LP_CAP_100GFDX,	"lp_cap_100gfdx",	NULL },

	{ ETHER_STAT_CAP_2500FDX,	"cap_2500fdx",		NULL },
	{ ETHER_STAT_ADV_CAP_2500FDX,	"adv_cap_2500fdx",	NULL },
	{ ETHER_STAT_LP_CAP_2500FDX,	"lp_cap_2500fdx",	NULL },

	{ ETHER_STAT_CAP_5000FDX,	"cap_5000fdx",		NULL },
	{ ETHER_STAT_ADV_CAP_5000FDX,	"adv_cap_5000fdx",	NULL },
	{ ETHER_STAT_LP_CAP_5000FDX,	"lp_cap_5000fdx",	NULL },

	{ ETHER_STAT_CAP_25GFDX,	"cap_25gfdx",		NULL },
	{ ETHER_STAT_ADV_CAP_25GFDX,	"adv_cap_25gfdx",	NULL },
	{ ETHER_STAT_LP_CAP_25GFDX,	"lp_cap_25gfdx",	NULL },

	{ ETHER_STAT_CAP_50GFDX,	"cap_50gfdx",		NULL },
	{ ETHER_STAT_ADV_CAP_50GFDX,	"adv_cap_50gfdx",	NULL },
	{ ETHER_STAT_LP_CAP_50GFDX,	"lp_cap_50gfdx",	NULL },
};

#define	SOFTMAC_ETHER_SI_SZ						\
	(sizeof (i_softmac_ether_si) / sizeof (i_softmac_ether_si[0]))

static kstat_t	*softmac_hold_dev_kstat(softmac_t *);
static void	softmac_rele_dev_kstat(kstat_t *);
static int	softmac_get_kstat(kstat_t *, char *, uint64_t *);

static kstat_t *
softmac_hold_dev_kstat(softmac_t *softmac)
{
	char		drv[MAXLINKNAMELEN];
	uint_t		ppa;
	kstat_t		*ksp;

	if (ddi_parse(softmac->smac_devname, drv, &ppa) != DDI_SUCCESS)
		return (NULL);

	/*
	 * Find the kstat by the module name and the instance number.
	 */
	ksp = kstat_hold_byname(drv, ppa, softmac->smac_devname, ALL_ZONES);
	if (ksp != NULL) {
		KSTAT_ENTER(ksp);

		if ((ksp->ks_data != NULL) &&
		    (ksp->ks_type == KSTAT_TYPE_NAMED)) {
			/*
			 * Update the kstat to get the latest statistics.
			 */
			if (KSTAT_UPDATE(ksp, KSTAT_READ) == 0)
				return (ksp);
		}

		KSTAT_EXIT(ksp);
		kstat_rele(ksp);
	}
	return (NULL);
}

static void
softmac_rele_dev_kstat(kstat_t *ksp)
{
	KSTAT_EXIT(ksp);
	kstat_rele(ksp);
}

/*
 * The kstat needs to be held when calling this function.
 */
static int
softmac_get_kstat(kstat_t *ksp, char *name, uint64_t *valp)
{
	kstat_named_t	*knp;
	int		i;
	int		ret = ENOTSUP;

	if (name == NULL)
		return (ret);

	/*
	 * Search the kstat with the given name.
	 */
	for (i = 0, knp = KSTAT_NAMED_PTR(ksp); i < ksp->ks_ndata; i++, knp++) {
		if (strcmp(knp->name, name) == 0) {
			switch (knp->data_type) {
			case KSTAT_DATA_INT32:
			case KSTAT_DATA_UINT32:
				*valp = (uint64_t)(knp->value.ui32);
				ret = 0;
				break;
			case KSTAT_DATA_INT64:
			case KSTAT_DATA_UINT64:
				*valp = knp->value.ui64;
				ret = 0;
				break;
#ifdef _LP64
			case KSTAT_DATA_LONG:
			case KSTAT_DATA_ULONG:
				*valp = (uint64_t)knp->value.ul;
				ret = 0;
				break;
#endif
			case KSTAT_DATA_CHAR:
				if (strcmp(name, "duplex") != 0)
					break;
				if (strncmp(knp->value.c, "full", 4) == 0)
					*valp = LINK_DUPLEX_FULL;
				else if (strncmp(knp->value.c, "half", 4) == 0)
					*valp = LINK_DUPLEX_HALF;
				else
					*valp = LINK_DUPLEX_UNKNOWN;
				ret = 0;
				break;
			}
			break;
		}
	}

	return (ret);
}

int
softmac_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	softmac_t	*softmac = arg;
	kstat_t		*ksp;
	uint_t		index;
	int		ret;

	if ((ksp = softmac_hold_dev_kstat(softmac)) == NULL)
		return (ENOTSUP);

	if (IS_MAC_STAT(stat)) {
		i_softmac_stat_info_t *ssip = NULL;

		for (index = 0; index < SOFTMAC_DRIVER_SI_SZ; index++) {
			if (stat == i_softmac_driver_si[index].ssi_stat) {
				ssip = &i_softmac_driver_si[index];
				break;
			}
		}

		if (ssip == NULL) {
			ret = ENOTSUP;
		} else {
			if ((ret = softmac_get_kstat(ksp, ssip->ssi_name,
			    val)) != 0)
				ret = softmac_get_kstat(ksp, ssip->ssi_alias,
				    val);
		}
	} else {
		ASSERT(IS_MACTYPE_STAT(stat));

		switch (softmac->smac_media) {
		case DL_ETHER: {
			i_softmac_stat_info_t *ssip = NULL;

			for (index = 0; index < SOFTMAC_ETHER_SI_SZ; index++) {
				if (stat ==
				    i_softmac_ether_si[index].ssi_stat) {
					ssip = &i_softmac_ether_si[index];
					break;
				}
			}

			if (ssip == NULL) {
				ret = ENOTSUP;
			} else {
				if ((ret = softmac_get_kstat(ksp,
				    ssip->ssi_name, val)) != 0)
					ret = softmac_get_kstat(ksp,
					    ssip->ssi_alias, val);
			}

			break;
		}
		default:
			ret = ENOTSUP;
			break;
		}
	}

	softmac_rele_dev_kstat(ksp);
	return (ret);
}
