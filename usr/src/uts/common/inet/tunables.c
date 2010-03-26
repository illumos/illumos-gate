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

#include <inet/tunables.h>
#include <sys/md5.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <netinet/icmp6.h>
#include <inet/ip_stack.h>
#include <inet/rawip_impl.h>
#include <inet/tcp_stack.h>
#include <inet/tcp_impl.h>
#include <inet/udp_impl.h>
#include <inet/sctp/sctp_stack.h>
#include <inet/sctp/sctp_impl.h>
#include <inet/tunables.h>

static int
prop_perm2const(mod_prop_info_t *pinfo)
{
	if (pinfo->mpi_setf == NULL)
		return (MOD_PROP_PERM_READ);
	if (pinfo->mpi_getf == NULL)
		return (MOD_PROP_PERM_WRITE);
	return (MOD_PROP_PERM_RW);
}

/*
 * Modifies the value of the property to default value or to the `pval'
 * specified by the user.
 */
/* ARGSUSED */
int
mod_set_boolean(void *cbarg, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	char 		*end;
	unsigned long 	new_value;

	if (flags & MOD_PROP_DEFAULT) {
		pinfo->prop_cur_bval = pinfo->prop_def_bval;
		return (0);
	}

	if (ddi_strtoul(pval, &end, 10, &new_value) != 0 || *end != '\0')
		return (EINVAL);
	if (new_value != B_TRUE && new_value != B_FALSE)
		return (EINVAL);
	pinfo->prop_cur_bval = new_value;
	return (0);
}

/*
 * Retrieves property permission, default value, current value or possible
 * values for those properties whose value type is boolean_t.
 */
/* ARGSUSED */
int
mod_get_boolean(void *cbarg, mod_prop_info_t *pinfo, const char *ifname,
    void *pval, uint_t psize, uint_t flags)
{
	boolean_t	get_def = (flags & MOD_PROP_DEFAULT);
	boolean_t	get_perm = (flags & MOD_PROP_PERM);
	boolean_t	get_range = (flags & MOD_PROP_POSSIBLE);
	size_t		nbytes;

	bzero(pval, psize);
	if (get_perm)
		nbytes = snprintf(pval, psize, "%u", prop_perm2const(pinfo));
	else if (get_range)
		nbytes = snprintf(pval, psize, "%u,%u", B_FALSE, B_TRUE);
	else if (get_def)
		nbytes = snprintf(pval, psize, "%u", pinfo->prop_def_bval);
	else
		nbytes = snprintf(pval, psize, "%u", pinfo->prop_cur_bval);
	if (nbytes >= psize)
		return (ENOBUFS);
	return (0);
}

/*
 * Modifies the value of the property to default value or to the `pval'
 * specified by the user.
 */
/* ARGSUSED */
int
mod_set_uint32(void *cbarg, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	char 		*end;
	unsigned long 	new_value;

	if (flags & MOD_PROP_DEFAULT) {
		pinfo->prop_cur_uval = pinfo->prop_def_uval;
		return (0);
	}

	if (ddi_strtoul(pval, &end, 10, &new_value) != 0 || *end != '\0')
		return (EINVAL);
	if (new_value < pinfo->prop_min_uval ||
	    new_value > pinfo->prop_max_uval) {
		return (ERANGE);
	}
	pinfo->prop_cur_uval = (uint32_t)new_value;
	return (0);
}

/*
 * Rounds up the value to make it multiple of 8.
 */
/* ARGSUSED */
int
mod_set_aligned(void *cbarg, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	int	err;

	if ((err = mod_set_uint32(cbarg, cr, pinfo, ifname, pval, flags)) != 0)
		return (err);

	/* if required, align the value to multiple of 8 */
	if (pinfo->prop_cur_uval & 0x7) {
		pinfo->prop_cur_uval &= ~0x7;
		pinfo->prop_cur_uval += 0x8;
	}

	return (0);
}

/*
 * Retrieves property permission, default value, current value or possible
 * values for those properties whose value type is uint32_t.
 */
/* ARGSUSED */
int
mod_get_uint32(void *cbarg, mod_prop_info_t *pinfo, const char *ifname,
    void *pval, uint_t psize, uint_t flags)
{
	boolean_t	get_def = (flags & MOD_PROP_DEFAULT);
	boolean_t	get_perm = (flags & MOD_PROP_PERM);
	boolean_t	get_range = (flags & MOD_PROP_POSSIBLE);
	size_t		nbytes;

	bzero(pval, psize);
	if (get_perm)
		nbytes = snprintf(pval, psize, "%u", prop_perm2const(pinfo));
	else if (get_range)
		nbytes = snprintf(pval, psize, "%u-%u",
		    pinfo->prop_min_uval, pinfo->prop_max_uval);
	else if (get_def)
		nbytes = snprintf(pval, psize, "%u", pinfo->prop_def_uval);
	else
		nbytes = snprintf(pval, psize, "%u", pinfo->prop_cur_uval);
	if (nbytes >= psize)
		return (ENOBUFS);
	return (0);
}

/*
 * Implements /sbin/ndd -get /dev/ip ?, for all the modules. Needed for
 * backward compatibility with /sbin/ndd.
 */
/* ARGSUSED */
int
mod_get_allprop(void *cbarg, mod_prop_info_t *pinfo, const char *ifname,
    void *val, uint_t psize, uint_t flags)
{
	char		*pval = val;
	mod_prop_info_t	*ptbl, *prop;
	ip_stack_t	*ipst;
	tcp_stack_t	*tcps;
	sctp_stack_t	*sctps;
	udp_stack_t	*us;
	icmp_stack_t	*is;
	uint_t		size;
	size_t		nbytes = 0, tbytes = 0;

	bzero(pval, psize);
	size = psize;

	switch (pinfo->mpi_proto) {
	case MOD_PROTO_IP:
	case MOD_PROTO_IPV4:
	case MOD_PROTO_IPV6:
		ipst = (ip_stack_t *)cbarg;
		ptbl = ipst->ips_propinfo_tbl;
		break;
	case MOD_PROTO_RAWIP:
		is = (icmp_stack_t *)cbarg;
		ptbl = is->is_propinfo_tbl;
		break;
	case MOD_PROTO_TCP:
		tcps = (tcp_stack_t *)cbarg;
		ptbl = tcps->tcps_propinfo_tbl;
		break;
	case MOD_PROTO_UDP:
		us = (udp_stack_t *)cbarg;
		ptbl = us->us_propinfo_tbl;
		break;
	case MOD_PROTO_SCTP:
		sctps = (sctp_stack_t *)cbarg;
		ptbl = sctps->sctps_propinfo_tbl;
		break;
	default:
		return (EINVAL);
	}

	for (prop = ptbl; prop->mpi_name != NULL; prop++) {
		if (prop->mpi_name[0] == '\0' ||
		    strcmp(prop->mpi_name, "mtu") == 0 ||
		    strcmp(prop->mpi_name, "?") == 0)
			continue;
		nbytes = snprintf(pval, size, "%s %d %d", prop->mpi_name,
		    prop->mpi_proto, prop_perm2const(prop));
		size -= nbytes + 1;
		pval += nbytes + 1;
		tbytes += nbytes + 1;
		if (tbytes >= psize) {
			/* Buffer overflow, stop copying information */
			return (ENOBUFS);
		}
	}
	return (0);
}

/*
 * Hold a lock while changing *_epriv_ports to prevent multiple
 * threads from changing it at the same time.
 */
/* ARGSUSED */
int
mod_set_extra_privports(void *cbarg, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* val, uint_t flags)
{
	uint_t		proto = pinfo->mpi_proto;
	tcp_stack_t	*tcps;
	sctp_stack_t	*sctps;
	udp_stack_t	*us;
	unsigned long	new_value;
	char		*end;
	kmutex_t	*lock;
	uint_t		i, nports;
	in_port_t	*ports;
	boolean_t	def = (flags & MOD_PROP_DEFAULT);
	const char	*pval = val;

	if (!def) {
		if (ddi_strtoul(pval, &end, 10, &new_value) != 0 ||
		    *end != '\0') {
			return (EINVAL);
		}

		if (new_value < pinfo->prop_min_uval ||
		    new_value > pinfo->prop_max_uval) {
			return (ERANGE);
		}
	}

	switch (proto) {
	case MOD_PROTO_TCP:
		tcps = (tcp_stack_t *)cbarg;
		lock = &tcps->tcps_epriv_port_lock;
		ports = tcps->tcps_g_epriv_ports;
		nports = tcps->tcps_g_num_epriv_ports;
		break;
	case MOD_PROTO_UDP:
		us = (udp_stack_t *)cbarg;
		lock = &us->us_epriv_port_lock;
		ports = us->us_epriv_ports;
		nports = us->us_num_epriv_ports;
		break;
	case MOD_PROTO_SCTP:
		sctps = (sctp_stack_t *)cbarg;
		lock = &sctps->sctps_epriv_port_lock;
		ports = sctps->sctps_g_epriv_ports;
		nports = sctps->sctps_g_num_epriv_ports;
		break;
	default:
		return (ENOTSUP);
	}

	mutex_enter(lock);

	/* if MOD_PROP_DEFAULT is set then reset the ports list to default */
	if (def) {
		for (i = 0; i < nports; i++)
			ports[i] = 0;
		ports[0] = ULP_DEF_EPRIV_PORT1;
		ports[1] = ULP_DEF_EPRIV_PORT2;
		mutex_exit(lock);
		return (0);
	}

	/* Check if the value is already in the list */
	for (i = 0; i < nports; i++) {
		if (new_value == ports[i])
			break;
	}

	if (flags & MOD_PROP_REMOVE) {
		if (i == nports) {
			mutex_exit(lock);
			return (ESRCH);
		}
		/* Clear the value */
		ports[i] = 0;
	} else if (flags & MOD_PROP_APPEND) {
		if (i != nports) {
			mutex_exit(lock);
			return (EEXIST);
		}

		/* Find an empty slot */
		for (i = 0; i < nports; i++) {
			if (ports[i] == 0)
				break;
		}
		if (i == nports) {
			mutex_exit(lock);
			return (EOVERFLOW);
		}
		/* Set the new value */
		ports[i] = (in_port_t)new_value;
	} else {
		/*
		 * If the user used 'assignment' modifier.
		 * For eg:
		 * 	# ipadm set-prop -p extra_priv_ports=3001 tcp
		 *
		 * We clear all the ports and then just add 3001.
		 */
		ASSERT(flags == MOD_PROP_ACTIVE);
		for (i = 0; i < nports; i++)
			ports[i] = 0;
		ports[0] = (in_port_t)new_value;
	}

	mutex_exit(lock);
	return (0);
}

/*
 * Note: No locks are held when inspecting *_epriv_ports
 * but instead the code relies on:
 * - the fact that the address of the array and its size never changes
 * - the atomic assignment of the elements of the array
 */
/* ARGSUSED */
int
mod_get_extra_privports(void *cbarg, mod_prop_info_t *pinfo, const char *ifname,
    void *val, uint_t psize, uint_t flags)
{
	uint_t		proto = pinfo->mpi_proto;
	tcp_stack_t	*tcps;
	sctp_stack_t	*sctps;
	udp_stack_t	*us;
	uint_t		i, nports, size;
	in_port_t	*ports;
	char		*pval = val;
	size_t		nbytes = 0, tbytes = 0;
	boolean_t	get_def = (flags & MOD_PROP_DEFAULT);
	boolean_t	get_perm = (flags & MOD_PROP_PERM);
	boolean_t	get_range = (flags & MOD_PROP_POSSIBLE);

	bzero(pval, psize);
	size = psize;

	if (get_def) {
		tbytes = snprintf(pval, psize, "%u,%u", ULP_DEF_EPRIV_PORT1,
		    ULP_DEF_EPRIV_PORT2);
		goto ret;
	} else if (get_perm) {
		tbytes = snprintf(pval, psize, "%u", MOD_PROP_PERM_RW);
		goto ret;
	}

	switch (proto) {
	case MOD_PROTO_TCP:
		tcps = (tcp_stack_t *)cbarg;
		ports = tcps->tcps_g_epriv_ports;
		nports = tcps->tcps_g_num_epriv_ports;
		break;
	case MOD_PROTO_UDP:
		us = (udp_stack_t *)cbarg;
		ports = us->us_epriv_ports;
		nports = us->us_num_epriv_ports;
		break;
	case MOD_PROTO_SCTP:
		sctps = (sctp_stack_t *)cbarg;
		ports = sctps->sctps_g_epriv_ports;
		nports = sctps->sctps_g_num_epriv_ports;
		break;
	default:
		return (ENOTSUP);
	}

	if (get_range) {
		tbytes = snprintf(pval, psize, "%u-%u", pinfo->prop_min_uval,
		    pinfo->prop_max_uval);
		goto ret;
	}

	for (i = 0; i < nports; i++) {
		if (ports[i] != 0) {
			if (psize == size)
				nbytes = snprintf(pval, size, "%u", ports[i]);
			else
				nbytes = snprintf(pval, size, ",%u", ports[i]);
			size -= nbytes;
			pval += nbytes;
			tbytes += nbytes;
			if (tbytes >= psize)
				return (ENOBUFS);
		}
	}
	return (0);
ret:
	if (tbytes >= psize)
		return (ENOBUFS);
	return (0);
}
