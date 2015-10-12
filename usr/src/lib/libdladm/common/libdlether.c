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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2015 Garrett D'Amore <garrett@damore.org>
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <libdladm_impl.h>
#include <libdllink.h>
#include <libdlstat.h>
#include <libdlether.h>

/*
 * Ethernet administration library.
 */

/*
 * kstat names for extracting attributes.
 */
typedef struct ether_spdx_s {
	dladm_ether_spdx_t eth_spdx;
	char *eth_spdx_stat_name;
} ether_spdx_t;

static ether_spdx_t cap_spdx[] = {
	{{1000, LINK_DUPLEX_FULL}, "cap_1000fdx"},
	{{1000, LINK_DUPLEX_HALF}, "cap_1000hdx"},
	{{100, LINK_DUPLEX_FULL}, "cap_100fdx"},
	{{100, LINK_DUPLEX_HALF}, "cap_100hdx"},
	{{10, LINK_DUPLEX_FULL}, "cap_10fdx"},
	{{10, LINK_DUPLEX_HALF}, "cap_10hdx"},
	{{0, LINK_DUPLEX_UNKNOWN}, NULL}
};

static ether_spdx_t adv_cap_spdx[] = {
	{{1000, LINK_DUPLEX_FULL}, "adv_cap_1000fdx"},
	{{1000, LINK_DUPLEX_HALF}, "adv_cap_1000hdx"},
	{{100, LINK_DUPLEX_FULL}, "adv_cap_100fdx"},
	{{100, LINK_DUPLEX_HALF}, "adv_cap_100hdx"},
	{{10, LINK_DUPLEX_FULL}, "adv_cap_10fdx"},
	{{10, LINK_DUPLEX_HALF}, "adv_cap_10hdx"},
	{{0, LINK_DUPLEX_UNKNOWN}, NULL}
};

static ether_spdx_t lp_cap_spdx[] = {
	{{1000, LINK_DUPLEX_FULL}, "lp_cap_1000fdx"},
	{{1000, LINK_DUPLEX_HALF}, "lp_cap_1000hdx"},
	{{100, LINK_DUPLEX_FULL}, "lp_cap_100fdx"},
	{{100, LINK_DUPLEX_HALF}, "lp_cap_100hdx"},
	{{10, LINK_DUPLEX_FULL}, "lp_cap_10fdx"},
	{{10, LINK_DUPLEX_HALF}, "lp_cap_10hdx"},
	{{0, LINK_DUPLEX_UNKNOWN}, NULL}
};

typedef struct attr_kstat_s {
	char *autoneg_stat;
	char *pause_stat;
	char *asmpause_stat;
	char *fault_stat;
	ether_spdx_t *spdx_stat;
} attr_kstat_t;

static attr_kstat_t attrstat[] =  {
	{"link_autoneg",	/* current */
	    "link_pause",	"link_asmpause",	NULL,
	    NULL},

	{"cap_autoneg",		/* capable */
	    "cap_pause",	"cap_asmpause",		"cap_rem_fault",
	    cap_spdx},

	{"adv_cap_autoneg",	/* advertised */
	    "adv_cap_pause",	"adv_cap_asmpause",	"adv_rem_fault",
	    adv_cap_spdx},

	{"lp_cap_autoneg",	/* peer advertised */
	    "lp_cap_pause",	"lp_cap_asmpause",	"lp_rem_fault",
	    lp_cap_spdx}
};

/*
 * Get the speed-duplex stats specified in the ether_spdx_t table passed in
 * by querying the appropriate kstat for each entry in the table.
 */
static dladm_status_t
i_dladm_get_spdx(dladm_handle_t handle, datalink_id_t linkid,
    dladm_ether_attr_t *eattr, ether_spdx_t *spdx_stat)
{
	int		i, nspdx = 0;
	uint32_t	speed;
	dladm_status_t	status;
	void		*ptr;

	eattr->le_spdx = NULL;
	for (i = 0; spdx_stat[i].eth_spdx_stat_name != NULL; i++) {
		if ((status = dladm_get_single_mac_stat(handle, linkid,
		    spdx_stat[i].eth_spdx_stat_name,
		    KSTAT_DATA_UINT32, &speed)) != DLADM_STATUS_OK) {

			if (status == DLADM_STATUS_NOTFOUND) {
				/*
				 * Missing statistic.
				 * Skip this one and try the rest.
				 */
				continue;
			} else {
				free(eattr->le_spdx);
				eattr->le_num_spdx = 0;
				return (status);
			}
		}
		if (speed == 0)
			continue;
		nspdx++;
		ptr = realloc(eattr->le_spdx,
		    nspdx * sizeof (dladm_ether_spdx_t));
		if (ptr != NULL) {
			eattr->le_spdx = ptr;
		} else {
			free(eattr->le_spdx);
			eattr->le_num_spdx = 0;
			return (DLADM_STATUS_NOMEM);
		}
		eattr->le_spdx[nspdx - 1] = spdx_stat[i].eth_spdx;
	}
	eattr->le_num_spdx = nspdx;
	return (DLADM_STATUS_OK);
}

/*
 * Returns "yes" or "no" based on the autonegotion capabilities
 * for the parameter type indicated by ptype. The permissible
 * values for ptype are CURRENT, CAPABLE, ADV, PEERADV.
 */
char *
dladm_ether_autoneg2str(char *buf, size_t buflen, dladm_ether_info_t *eattr,
    int ptype)
{
	boolean_t autoneg = eattr->lei_attr[ptype].le_autoneg;

	(void) strlcpy(buf, (autoneg ? "yes" : "no"), buflen);
	return (buf);
}

/*
 * Returns {"bi", "tx", "none"} based on the flow-control capabilities
 * for the parameter type indicated by ptype. The permissible
 * values for ptype are CURRENT, CAPABLE, ADV, PEERADV.
 */
char *
dladm_ether_pause2str(char *buf, size_t buflen, dladm_ether_info_t *eattr,
    int ptype)
{
	boolean_t pause = eattr->lei_attr[ptype].le_pause;
	boolean_t asmpause = eattr->lei_attr[ptype].le_asmpause;

	if (pause)
		(void) strlcpy(buf, "bi", buflen);
	else if (asmpause)
		(void) strlcpy(buf, "tx", buflen);
	else
		(void) strlcpy(buf, "none", buflen);
	return (buf);
}

/*
 * For a given param type, parse the list of speed-duplex pairs in
 * the dladm_ether_info_t and return a  comma-separated string formatted
 * as <speed><speed-unit-char>-<duplex-chars> where <speed> is the value of
 * speed, in units specifid by the <speed-unit-char> which is one
 * of 'M' (Mbits/sec) or 'G' (Gigabits/sec).  The permissible values of
 * <duplex-chars> are 'u' (indicating duplex is "unknown") or one/both of
 * 'f', 'h' (indicating full-duplex and half-duplex respectively)
 */
extern char *
dladm_ether_spdx2str(char *buf, size_t buflen, dladm_ether_info_t *eattr,
    int ptype)
{
	int		i, j;
	boolean_t	is_full, is_half;
	int		speed;
	char		speed_unit;
	char		tmpbuf[DLADM_STRSIZE];
	dladm_ether_spdx_t *spdx;
	uint32_t	nspdx;

	spdx = eattr->lei_attr[ptype].le_spdx;
	nspdx = eattr->lei_attr[ptype].le_num_spdx;
	for (i = 0; i < nspdx; i++) {

		speed = spdx[i].lesd_speed;

		/*
		 * if we have already covered this speed for
		 * the <other>-duplex case before this, skip it
		 */
		for (j = 0; j < i; j++) {
			if (speed == spdx[j].lesd_speed)
				break;
		}
		if (j < i)
			continue;

		if ((speed % 1000) == 0) {
			speed = speed/1000;
			speed_unit = 'G';
		} else {
			speed_unit = 'M';
		}
		(void) snprintf(tmpbuf, DLADM_STRSIZE, "%d%c",
		    speed, speed_unit);
		if (i > 0)
			(void) strncat(buf, ",", buflen);
		(void) strncat(buf, tmpbuf, buflen);

		is_full = is_half = B_FALSE;
		/*
		 * Find all the supported duplex values for this speed.
		 */
		for (j = 0; j < nspdx; j++) {
			if (spdx[j].lesd_speed != spdx[i].lesd_speed)
				continue;
			if (spdx[j].lesd_duplex == LINK_DUPLEX_FULL)
				is_full = B_TRUE;
			if (spdx[j].lesd_duplex == LINK_DUPLEX_HALF)
				is_half = B_TRUE;
		}
		if (is_full && is_half)
			(void) strncat(buf, "-fh", buflen);
		else if (is_full)
			(void) strncat(buf, "-f", buflen);
		else if (is_half)
			(void) strncat(buf, "-h", buflen);
	}
	return (buf);
}

/*
 * Extract Ethernet attributes of the link specified by linkid.
 * Information for the CURRENT, CAPABLE, ADV and PEERADV parameter
 * types is extracted into the lei_attr[] entries in the dladm_ether_info_t.
 * On succesful return, the memory allocated in this function should be
 * freed by calling dladm_ether_info_done().
 */
extern dladm_status_t
dladm_ether_info(dladm_handle_t handle, datalink_id_t linkid,
    dladm_ether_info_t *eattr)
{
	uint32_t	autoneg, pause, asmpause, fault;
	uint64_t	sp64;
	dladm_status_t	status;
	int		i;
	link_duplex_t	link_duplex;

	bzero(eattr, sizeof (*eattr));
	status = dladm_datalink_id2info(handle, linkid, NULL, NULL, NULL,
	    eattr->lei_linkname, sizeof (eattr->lei_linkname));
	if (status != DLADM_STATUS_OK)
		goto bail;

	/* get current values of speed, duplex, state of link */
	eattr->lei_attr[CURRENT].le_num_spdx = 1;
	eattr->lei_attr[CURRENT].le_spdx = malloc(sizeof (dladm_ether_spdx_t));
	if (eattr->lei_attr[CURRENT].le_spdx == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto bail;
	}

	if ((status = dladm_get_single_mac_stat(handle, linkid, "ifspeed",
	    KSTAT_DATA_UINT64, &sp64)) != DLADM_STATUS_OK)
		goto bail;

	if ((status = dladm_get_single_mac_stat(handle, linkid, "link_duplex",
	    KSTAT_DATA_UINT32, &link_duplex)) != DLADM_STATUS_OK)
		goto bail;

	eattr->lei_attr[CURRENT].le_spdx->lesd_speed = (int)(sp64/1000000ull);
	eattr->lei_attr[CURRENT].le_spdx->lesd_duplex = link_duplex;

	status = dladm_get_state(handle, linkid, &eattr->lei_state);
	if (status != DLADM_STATUS_OK)
		goto bail;

	/* get the auto, pause, asmpause, fault values */
	for (i = CURRENT; i <= PEERADV; i++)  {

		status = dladm_get_single_mac_stat(handle, linkid,
		    attrstat[i].autoneg_stat, KSTAT_DATA_UINT32, &autoneg);
		if (status != DLADM_STATUS_OK)
			goto bail;

		status = dladm_get_single_mac_stat(handle, linkid,
		    attrstat[i].pause_stat, KSTAT_DATA_UINT32, &pause);
		if (status != DLADM_STATUS_OK)
			goto bail;

		status = dladm_get_single_mac_stat(handle, linkid,
		    attrstat[i].asmpause_stat, KSTAT_DATA_UINT32, &asmpause);
		if (status != DLADM_STATUS_OK)
			goto bail;

		eattr->lei_attr[i].le_autoneg = (autoneg != 0);
		eattr->lei_attr[i].le_pause = (pause != 0);
		eattr->lei_attr[i].le_asmpause = (asmpause != 0);

		if (i == CURRENT)
			continue;
		status = dladm_get_single_mac_stat(handle, linkid,
		    attrstat[i].fault_stat, KSTAT_DATA_UINT32, &fault);
		if (status != DLADM_STATUS_OK)
			goto bail;
		eattr->lei_attr[i].le_fault = (pause != 0);

		/* get all the supported speed/duplex values */
		status = i_dladm_get_spdx(handle, linkid, &eattr->lei_attr[i],
		    attrstat[i].spdx_stat);
		if (status != DLADM_STATUS_OK)
			goto bail;
	}
	eattr->lei_attr[CURRENT].le_fault =
	    eattr->lei_attr[ADV].le_fault || eattr->lei_attr[PEERADV].le_fault;
bail:
	if (status != DLADM_STATUS_OK)
		dladm_ether_info_done(eattr);
	return (status);
}

extern void
dladm_ether_info_done(dladm_ether_info_t *eattr)
{
	int i;

	for (i = CURRENT; i <= PEERADV; i++)
		free(eattr->lei_attr[i].le_spdx);
}
