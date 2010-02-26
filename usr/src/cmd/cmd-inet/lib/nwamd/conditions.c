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
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inet/ip.h>
#include <inetcfg.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlwlan.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libnwam.h>
#include "conditions.h"
#include "ncu.h"
#include "objects.h"
#include "util.h"

/*
 * conditions.c - contains routines which check state to see if activation
 * conditions for NWAM objects are satisfied and rates activation conditions to
 * help determine which is most specific.
 *
 * If the activation-mode is CONDITIONAL_ANY or CONDITIONAL_ALL, the conditions
 * property is set to a string made up of conditional expressions. Each
 * expression is made up of a condition that can be assigned a boolean value,
 * e.g. "system-domain is sun.com" or "ncu ip:bge0 is-not active". If the
 * activation-mode is CONDITIONAL_ANY, the condition will be satisfied if any
 * one of the conditions is true; if the activation-mode is CONDITIONAL_ALL,
 * the condition is satisfied only if all of the conditions are true.
 */

uint64_t condition_check_interval = CONDITION_CHECK_INTERVAL_DEFAULT;

extern int getdomainname(char *, int);

/* NCP, NCU, ENM and location conditions */
static boolean_t test_condition_ncp(nwam_condition_t condition,
    const char *ncp_name);
static boolean_t test_condition_ncu(nwam_condition_t condition,
    const char *ncu_name);
static boolean_t test_condition_enm(nwam_condition_t condition,
    const char *enm_name);
static boolean_t test_condition_loc(nwam_condition_t condition,
    const char *loc_name);

/* IP address conditions */
static boolean_t test_condition_ip_address(nwam_condition_t condition,
    const char *ip_address);

/* domainname conditions */
static boolean_t test_condition_sys_domain(nwam_condition_t condition,
    const char *domainname);
static boolean_t test_condition_adv_domain(nwam_condition_t condition,
    const char *domainname);

/*  WLAN conditions */
static boolean_t test_condition_wireless_essid(nwam_condition_t condition,
    const char *essid);
static boolean_t test_condition_wireless_bssid(nwam_condition_t condition,
    const char *essid);

struct nwamd_condition_map {
	nwam_condition_object_type_t object_type;
	boolean_t (*condition_func)(nwam_condition_t, const char *);
} condition_map[] =
{
	{ NWAM_CONDITION_OBJECT_TYPE_NCP, test_condition_ncp },
	{ NWAM_CONDITION_OBJECT_TYPE_NCU, test_condition_ncu },
	{ NWAM_CONDITION_OBJECT_TYPE_ENM, test_condition_enm },
	{ NWAM_CONDITION_OBJECT_TYPE_LOC, test_condition_loc },
	{ NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS, test_condition_ip_address },
	{ NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN, test_condition_sys_domain },
	{ NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN, test_condition_adv_domain },
	{ NWAM_CONDITION_OBJECT_TYPE_ESSID, test_condition_wireless_essid },
	{ NWAM_CONDITION_OBJECT_TYPE_BSSID, test_condition_wireless_bssid }
};

/*
 * This function takes which kind of conditions (is or is not) we are testing
 * the object against and an object and applies the conditon to the object.
 */
static boolean_t
test_condition_object_state(nwam_condition_t condition,
    nwam_object_type_t object_type, const char *object_name)
{
	nwamd_object_t object;
	nwam_state_t state;

	object = nwamd_object_find(object_type, object_name);
	if (object == NULL)
		return (B_FALSE);

	state = object->nwamd_object_state;
	nwamd_object_release(object);

	switch (condition) {
	case NWAM_CONDITION_IS:
		return (state == NWAM_STATE_ONLINE);
	case NWAM_CONDITION_IS_NOT:
		return (state != NWAM_STATE_ONLINE);
	default:
		return (B_FALSE);
	}
}

static boolean_t
test_condition_ncp(nwam_condition_t condition, const char *name)
{
	boolean_t active;

	(void) pthread_mutex_lock(&active_ncp_mutex);
	active = (strcasecmp(active_ncp, name) == 0);
	(void) pthread_mutex_unlock(&active_ncp_mutex);

	switch (condition) {
	case NWAM_CONDITION_IS:
		return (active);
	case NWAM_CONDITION_IS_NOT:
		return (active != B_TRUE);
	default:
		return (B_FALSE);
	}
}

static boolean_t
test_condition_ncu(nwam_condition_t condition, const char *name)
{
	char *real_name, *ncu_name;
	nwam_ncu_handle_t ncuh;
	nwam_ncu_type_t ncu_type;
	boolean_t rv;

	/* names are case-insensitive, so get real name from libnwam */
	if (nwam_ncu_read(active_ncph, name, NWAM_NCU_TYPE_INTERFACE, 0, &ncuh)
	    == NWAM_SUCCESS) {
		ncu_type = NWAM_NCU_TYPE_INTERFACE;
	} else if (nwam_ncu_read(active_ncph, name, NWAM_NCU_TYPE_LINK, 0,
	    &ncuh) == NWAM_SUCCESS) {
		ncu_type = NWAM_NCU_TYPE_LINK;
	} else {
		return (B_FALSE);
	}
	if (nwam_ncu_get_name(ncuh, &real_name) != NWAM_SUCCESS) {
		nwam_ncu_free(ncuh);
		return (B_FALSE);
	}
	nwam_ncu_free(ncuh);

	/*
	 * Name may be either unqualified or qualified by NCU type
	 * (interface:/link:).  Need to translate unqualified names
	 * to qualified, specifying interface:name if an interface
	 * NCU is present, otherwise link:ncu.
	 */
	if (nwam_ncu_name_to_typed_name(real_name, ncu_type, &ncu_name)
	    != NWAM_SUCCESS) {
		free(real_name);
		return (B_FALSE);
	}
	free(real_name);

	rv = test_condition_object_state(condition, NWAM_OBJECT_TYPE_NCU,
	    ncu_name);
	free(ncu_name);
	return (rv);
}

static boolean_t
test_condition_enm(nwam_condition_t condition, const char *enm_name)
{
	nwam_enm_handle_t enmh;
	char *real_name;
	boolean_t rv;

	/* names are case-insensitive, so get real name from libnwam */
	if (nwam_enm_read(enm_name, 0, &enmh) != NWAM_SUCCESS)
		return (B_FALSE);
	if (nwam_enm_get_name(enmh, &real_name) != NWAM_SUCCESS) {
		nwam_enm_free(enmh);
		return (B_FALSE);
	}
	nwam_enm_free(enmh);

	rv = test_condition_object_state(condition, NWAM_OBJECT_TYPE_ENM,
	    real_name);
	free(real_name);
	return (rv);
}

static boolean_t
test_condition_loc(nwam_condition_t condition, const char *loc_name)
{
	nwam_loc_handle_t loch;
	char *real_name;
	boolean_t rv;

	/* names are case-insensitive, so get real name from libnwam */
	if (nwam_loc_read(loc_name, 0, &loch) != NWAM_SUCCESS)
		return (B_FALSE);
	if (nwam_loc_get_name(loch, &real_name) != NWAM_SUCCESS) {
		nwam_loc_free(loch);
		return (B_FALSE);
	}
	nwam_loc_free(loch);

	rv = test_condition_object_state(condition, NWAM_OBJECT_TYPE_LOC,
	    real_name);
	free(real_name);
	return (rv);
}

static boolean_t
test_condition_domain(nwam_condition_t condition, const char *target_domain,
    const char *found_domain)
{
	int i, len_t, len_f;
	char target[MAXHOSTNAMELEN], found[MAXHOSTNAMELEN];

	len_t = target_domain == NULL ? 0 : strlen(target_domain);
	len_f = found_domain == NULL ? 0 : strlen(found_domain);

	/* convert target_domain and found_domain to lowercase for strstr() */
	for (i = 0; i < len_t; i++)
		target[i] = tolower(target_domain[i]);
	target[len_t] = '\0';

	for (i = 0; i < len_f; i++)
		found[i] = tolower(found_domain[i]);
	found[len_f] = '\0';

	switch (condition) {
	case NWAM_CONDITION_IS:
		return (found_domain != NULL && strcmp(found, target) == 0);
	case NWAM_CONDITION_IS_NOT:
		return (found_domain == NULL || strcmp(found, target) != 0);
	case NWAM_CONDITION_CONTAINS:
		return (found_domain != NULL && strstr(found, target) != NULL);
	case NWAM_CONDITION_DOES_NOT_CONTAIN:
		return (found_domain == NULL || strstr(found, target) == NULL);
	default:
		return (B_FALSE);
	}
}

struct ncu_adv_domains {
	struct ncu_adv_domains *next;
	char *dns_domain;
	char *nis_domain;
};

static int
get_adv_domains(nwamd_object_t obj, void *arg)
{
	nwamd_ncu_t *ncu = (nwamd_ncu_t *)obj->nwamd_object_data;
	struct ncu_adv_domains **headpp = (struct ncu_adv_domains **)arg;
	struct ncu_adv_domains *adp;
	char *dns, *nis;

	if (ncu->ncu_type != NWAM_NCU_TYPE_INTERFACE)
		return (0);

	dns = nwamd_get_dhcpinfo_data("DNSdmain", ncu->ncu_name);
	nis = nwamd_get_dhcpinfo_data("NISdmain", ncu->ncu_name);

	if (dns != NULL || nis != NULL) {
		adp = (struct ncu_adv_domains *)malloc(sizeof (*adp));
		if (adp == NULL)
			return (1);
		adp->dns_domain = dns;
		adp->nis_domain = nis;
		adp->next = *headpp;
		*headpp = adp;
	}

	return (0);
}

static boolean_t
test_condition_sys_domain(nwam_condition_t condition, const char *domainname)
{
	char cur_domainname[MAXHOSTNAMELEN];

	if (getdomainname(cur_domainname, MAXHOSTNAMELEN) != 0)
		return (B_FALSE);

	return (test_condition_domain(condition, domainname, cur_domainname));
}

static boolean_t
test_condition_adv_domain(nwam_condition_t condition, const char *domainname)
{
	struct ncu_adv_domains *adv_domains = NULL;
	struct ncu_adv_domains *adp, *prev;
	boolean_t positive, rtn;

	(void) nwamd_walk_objects(NWAM_OBJECT_TYPE_NCU, get_adv_domains,
	    &adv_domains);

	positive = (condition == NWAM_CONDITION_IS ||
	    condition == NWAM_CONDITION_CONTAINS);

	/*
	 * Walk the advertised domain list.  Our test function tests one
	 * single domain, but we're dealing with a list: if our condition
	 * is positive ('is' or 'contains'), the test function for each
	 * domain results are or'd together; if our condition is negative
	 * ('is-not' or 'does-not-contain'), the test function results must
	 * be and'd.  Thus our short-circuit exit value depends on our
	 * condition: if the test function returns TRUE it implies immediate
	 * success for a positive condition; if it returns FALSE it implies
	 * immediate failure for a negative condition.
	 */
	adp = adv_domains;
	while (adp != NULL) {
		if ((test_condition_domain(condition, domainname,
		    adp->dns_domain) == positive) ||
		    (test_condition_domain(condition, domainname,
		    adp->nis_domain) == positive)) {
			rtn = positive;
			break;
		}
		adp = adp->next;
	}
	if (adp == NULL) {
		/*
		 * We did not short-circuit; we therefore failed if our
		 * condition was positive, and succeeded if our condition
		 * was negative.
		 */
		rtn = !positive;
	}

	/* now free the domain list */
	adp = adv_domains;
	while (adp != NULL) {
		prev = adp;
		adp = prev->next;
		free(prev->dns_domain);
		free(prev->nis_domain);
		free(prev);
	}

	return (rtn);
}

/*
 * Returns true if prefixlen bits of addr1 match prefixlen bits of addr2.
 */
static boolean_t
prefixmatch(uchar_t *addr1, uchar_t *addr2, int prefixlen)
{
	uchar_t mask[IPV6_ABITS/8];
	int i, j = 0;

	if (prefixlen == 0)
		return (B_TRUE);

	while (prefixlen > 0) {
		if (prefixlen >= 8) {
			mask[j++] = 0xFF;
			prefixlen -= 8;
		} else {
			mask[j] |= 1 << (8 - prefixlen);
			prefixlen--;
		}
	}
	/* Ensure at least one byte is tested */
	if (j == 0) j++;

	for (i = 0; i < j; i++) {
		if ((addr1[i] & mask[i]) != (addr2[i] & mask[i]))
			return (B_FALSE);
	}
	return (B_TRUE);
}

struct nwamd_ipaddr_condition_walk_arg {
	nwam_condition_t condition;
	struct sockaddr_storage sockaddr;
	int prefixlen;
	boolean_t res;
};

static int
check_ipaddr(icfg_if_t *intf, void *arg)
{
	struct nwamd_ipaddr_condition_walk_arg *wa = arg;
	struct sockaddr_storage sockaddr;
	icfg_handle_t h;
	socklen_t addrlen = intf->if_protocol == AF_INET ?
	    sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
	int prefixlen = 0;
	boolean_t match = B_FALSE;
	uchar_t *addr1, *addr2;

	if (icfg_open(&h, intf) != ICFG_SUCCESS)
		return (0);

	if (icfg_get_addr(h, (struct sockaddr *)&sockaddr, &addrlen,
	    &prefixlen, B_TRUE) != ICFG_SUCCESS) {
		nlog(LOG_ERR, "check_ipaddr: icfg_get_addr: %s",
		    strerror(errno));
		return (0);
	}

	if (intf->if_protocol == AF_INET) {
		addr1 = (uchar_t *)&(((struct sockaddr_in *)
		    &sockaddr)->sin_addr.s_addr);
		addr2 = (uchar_t *)&(((struct sockaddr_in *)
		    &(wa->sockaddr))->sin_addr.s_addr);
	} else {
		addr1 = (uchar_t *)&(((struct sockaddr_in6 *)
		    &sockaddr)->sin6_addr.s6_addr);
		addr2 = (uchar_t *)&(((struct sockaddr_in6 *)
		    &(wa->sockaddr))->sin6_addr.s6_addr);
	}

	match = prefixmatch(addr1, addr2, wa->prefixlen);
	icfg_close(h);

	nlog(LOG_DEBUG, "check_ipaddr: match %d\n", match);
	switch (wa->condition) {
	case NWAM_CONDITION_IS:
	case NWAM_CONDITION_IS_IN_RANGE:
		wa->res = match;
		if (match)
			return (1);
		return (0);
	case NWAM_CONDITION_IS_NOT:
	case NWAM_CONDITION_IS_NOT_IN_RANGE:
		wa->res = !match;
		return (0);
	default:
		return (0);
	}
}

static boolean_t
test_condition_ip_address(nwam_condition_t condition,
    const char *ip_address_string)
{
	int proto;
	char *copy, *ip_address, *prefixlen_string, *lasts;
	socklen_t addrlen = sizeof (struct sockaddr_in);
	socklen_t addr6len = sizeof (struct sockaddr_in6);
	struct nwamd_ipaddr_condition_walk_arg wa;

	if ((copy = strdup(ip_address_string)) == NULL)
		return (B_FALSE);

	if ((ip_address = strtok_r(copy, " \t/", &lasts)) == NULL) {
		free(copy);
		return (B_FALSE);
	}

	prefixlen_string = strtok_r(NULL, " \t", &lasts);

	if (icfg_str_to_sockaddr(AF_INET, ip_address,
	    (struct sockaddr *)&(wa.sockaddr), &addrlen) == ICFG_SUCCESS) {
		proto = AF_INET;
		wa.prefixlen = IP_ABITS;
	} else if (icfg_str_to_sockaddr(AF_INET6, ip_address,
	    (struct sockaddr *)&(wa.sockaddr), &addr6len) == ICFG_SUCCESS) {
		proto = AF_INET6;
		wa.prefixlen = IPV6_ABITS;
	} else {
		nlog(LOG_ERR, "test_condition_ip_address: "
		    "icfg_str_to_sockaddr: %s", strerror(errno));
		free(copy);
		return (B_FALSE);
	}

	if (prefixlen_string != NULL)
		wa.prefixlen = atoi(prefixlen_string);

	wa.condition = condition;

	switch (condition) {
	case NWAM_CONDITION_IS:
	case NWAM_CONDITION_IS_IN_RANGE:
		wa.res = B_FALSE;
		break;
	case NWAM_CONDITION_IS_NOT:
	case NWAM_CONDITION_IS_NOT_IN_RANGE:
		wa.res = B_TRUE;
		break;
	default:
		free(copy);
		return (B_FALSE);
	}

	(void) icfg_iterate_if(proto, ICFG_PLUMBED, &wa, check_ipaddr);

	free(copy);

	return (wa.res);
}

struct nwamd_wlan_condition_walk_arg {
	nwam_condition_t condition;
	const char *exp_essid;
	const char *exp_bssid;
	uint_t num_connected;
	boolean_t res;
};

static int
check_wlan(const char *linkname, void *arg)
{
	struct nwamd_wlan_condition_walk_arg *wa = arg;
	datalink_id_t linkid;
	dladm_wlan_linkattr_t attr;
	dladm_status_t status;
	char cur_essid[DLADM_STRSIZE];
	char cur_bssid[DLADM_STRSIZE];
	char errmsg[DLADM_STRSIZE];

	if ((status = dladm_name2info(dld_handle, linkname, &linkid, NULL, NULL,
	    NULL)) != DLADM_STATUS_OK) {
		nlog(LOG_DEBUG, "check_wlan: dladm_name2info() for %s "
		    "failed: %s", linkname,
		    dladm_status2str(status, errmsg));
		return (DLADM_WALK_CONTINUE);
	}

	status = dladm_wlan_get_linkattr(dld_handle, linkid, &attr);
	if (status != DLADM_STATUS_OK) {
		nlog(LOG_DEBUG, "check_wlan: dladm_wlan_get_linkattr() for %s "
		    "failed: %s", linkname,
		    dladm_status2str(status, errmsg));
		return (DLADM_WALK_CONTINUE);
	}
	if (attr.la_status == DLADM_WLAN_LINK_DISCONNECTED)
		return (DLADM_WALK_TERMINATE);

	wa->num_connected++;

	if (wa->exp_essid != NULL) {
		/* Is the NIC associated with the expected access point? */
		(void) dladm_wlan_essid2str(&attr.la_wlan_attr.wa_essid,
		    cur_essid);
		switch (wa->condition) {
		case NWAM_CONDITION_IS:
			wa->res = strcmp(cur_essid, wa->exp_essid) == 0;
			if (wa->res)
				return (DLADM_WALK_TERMINATE);
			break;
		case NWAM_CONDITION_IS_NOT:
			wa->res = strcmp(cur_essid, wa->exp_essid) != 0;
			if (!wa->res)
				return (DLADM_WALK_TERMINATE);
			break;
		case NWAM_CONDITION_CONTAINS:
			wa->res = strstr(cur_essid, wa->exp_essid) != NULL;
			if (wa->res)
				return (DLADM_WALK_TERMINATE);
			break;
		case NWAM_CONDITION_DOES_NOT_CONTAIN:
			wa->res = strstr(cur_essid, wa->exp_essid) == NULL;
			if (!wa->res)
				return (DLADM_WALK_TERMINATE);
			break;
		default:
			return (DLADM_WALK_TERMINATE);
		}
		return (DLADM_WALK_CONTINUE);
	}
	if (wa->exp_bssid != NULL) {
		/* Is the NIC associated with the expected access point? */
		(void) dladm_wlan_bssid2str(&attr.la_wlan_attr.wa_bssid,
		    cur_bssid);
		switch (wa->condition) {
		case NWAM_CONDITION_IS:
			wa->res = strcmp(cur_bssid, wa->exp_bssid) == 0;
			if (wa->res)
				return (DLADM_WALK_TERMINATE);
			break;
		case NWAM_CONDITION_IS_NOT:
			wa->res = strcmp(cur_bssid, wa->exp_bssid) != 0;
			if (!wa->res)
				return (DLADM_WALK_TERMINATE);
			break;
		default:
			return (DLADM_WALK_TERMINATE);
		}
		return (DLADM_WALK_CONTINUE);
	}
	/*
	 * Neither an ESSID or BSSID match is required - being connected to a
	 * WLAN is enough.
	 */
	switch (wa->condition) {
	case NWAM_CONDITION_IS:
		wa->res = B_TRUE;
		return (DLADM_WALK_TERMINATE);
	default:
		wa->res = B_FALSE;
		return (DLADM_WALK_TERMINATE);
	}
	/*NOTREACHED*/
	return (DLADM_WALK_CONTINUE);
}

static boolean_t
test_condition_wireless_essid(nwam_condition_t condition,
    const char *essid)
{
	struct nwamd_wlan_condition_walk_arg wa;

	wa.condition = condition;
	wa.exp_essid = essid;
	wa.exp_bssid = NULL;
	wa.num_connected = 0;
	wa.res = B_FALSE;

	(void) dladm_walk(check_wlan, dld_handle, &wa, DATALINK_CLASS_PHYS,
	    DL_WIFI, DLADM_OPT_ACTIVE);

	return (wa.num_connected > 0 && wa.res == B_TRUE);
}

static boolean_t
test_condition_wireless_bssid(nwam_condition_t condition,
    const char *bssid)
{
	struct nwamd_wlan_condition_walk_arg wa;

	wa.condition = condition;
	wa.exp_bssid = bssid;
	wa.exp_essid = NULL;
	wa.num_connected = 0;
	wa.res = B_FALSE;

	(void) dladm_walk(check_wlan, dld_handle, &wa, DATALINK_CLASS_PHYS,
	    DL_WIFI, DLADM_OPT_ACTIVE);

	return (wa.num_connected > 0 && wa.res == B_TRUE);
}

/*
 * This function takes an activation mode and a string representation of a
 * condition and evaluates it.
 */
boolean_t
nwamd_check_conditions(nwam_activation_mode_t activation_mode,
    char **condition_strings, uint_t num_conditions)
{
	boolean_t ret;
	nwam_condition_t condition;
	nwam_condition_object_type_t object_type;
	char *object_name;
	int i, j;

	for (i = 0; i < num_conditions; i++) {

		if (nwam_condition_string_to_condition(condition_strings[i],
		    &object_type, &condition, &object_name) != NWAM_SUCCESS) {
			nlog(LOG_ERR, "check_conditions: invalid condition %s",
			    condition_strings[i]);
			return (B_FALSE);
		}
		ret = B_FALSE;

		for (j = 0; j < (sizeof (condition_map) /
		    sizeof (struct nwamd_condition_map)); j++) {
			if (condition_map[j].object_type == object_type)
				ret = condition_map[j].condition_func(condition,
				    object_name);
		}

		free(object_name);

		if (activation_mode == NWAM_ACTIVATION_MODE_CONDITIONAL_ANY &&
		    ret) {
			return (B_TRUE);
		}
		if (activation_mode == NWAM_ACTIVATION_MODE_CONDITIONAL_ALL &&
		    !ret) {
			return (B_FALSE);
		}
	}
	if (activation_mode == NWAM_ACTIVATION_MODE_CONDITIONAL_ANY && ret)
		return (B_TRUE);
	if (activation_mode == NWAM_ACTIVATION_MODE_CONDITIONAL_ALL && ret)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * In rating activation conditions, we take the best-rated CONDITIONAL_ANY
 * condition, or sum all the CONDITIONAL_ALL condition ratings. This allows
 * us to compare between location activation conditions to pick the best.
 */
uint64_t
nwamd_rate_conditions(nwam_activation_mode_t activation_mode,
    char **conditions, uint_t num_conditions)
{
	nwam_condition_t condition;
	nwam_condition_object_type_t object_type;
	char *object_name;
	int i;
	uint64_t rating = 0, total_rating = 0;

	for (i = 0; i < num_conditions; i++) {

		object_name = NULL;
		if (nwam_condition_string_to_condition(conditions[i],
		    &object_type, &condition, &object_name) != NWAM_SUCCESS ||
		    nwam_condition_rate(object_type, condition, &rating)
		    != NWAM_SUCCESS) {
			nlog(LOG_ERR, "nwamd_rate_conditions: could not rate "
			    "condition");
			free(object_name);
			return (0);
		}
		free(object_name);

		if (activation_mode == NWAM_ACTIVATION_MODE_CONDITIONAL_ANY) {
			if (rating > total_rating)
				total_rating = rating;
		} else if (activation_mode ==
		    NWAM_ACTIVATION_MODE_CONDITIONAL_ALL) {
			total_rating += rating;
		}
	}
	return (total_rating);
}

/*
 * Different from nwamd_triggered_check_all_conditions() in that this
 * function enqueues a timed check event.
 */
void
nwamd_set_timed_check_all_conditions(void)
{
	nwamd_event_t check_event = nwamd_event_init
	    (NWAM_EVENT_TYPE_TIMED_CHECK_CONDITIONS, NWAM_OBJECT_TYPE_UNKNOWN,
	    0, NULL);
	if (check_event != NULL) {
		/* Add another timed event to recheck conditions */
		nwamd_event_enqueue_timed(check_event,
		    condition_check_interval > CONDITION_CHECK_INTERVAL_MIN ?
		    condition_check_interval : CONDITION_CHECK_INTERVAL_MIN);
	}
}

/*
 * Does not enqueue another check event.
 */
void
nwamd_check_all_conditions(void)
{
	nwamd_enm_check_conditions();
	nwamd_loc_check_conditions();
}

void
nwamd_create_timed_condition_check_event(void)
{
	nwamd_event_t check_event = nwamd_event_init
	    (NWAM_EVENT_TYPE_TIMED_CHECK_CONDITIONS, NWAM_OBJECT_TYPE_UNKNOWN,
	    0, NULL);
	if (check_event != NULL)
		nwamd_event_enqueue(check_event);
}

void
nwamd_create_triggered_condition_check_event(uint32_t when)
{
	nwamd_event_t check_event;

	if (!nwamd_event_enqueued(NWAM_EVENT_TYPE_TRIGGERED_CHECK_CONDITIONS,
	    NWAM_OBJECT_TYPE_UNKNOWN, NULL)) {
		check_event = nwamd_event_init
		    (NWAM_EVENT_TYPE_TRIGGERED_CHECK_CONDITIONS,
		    NWAM_OBJECT_TYPE_UNKNOWN, 0, NULL);
		if (check_event != NULL)
			nwamd_event_enqueue_timed(check_event, when);
	}
}
