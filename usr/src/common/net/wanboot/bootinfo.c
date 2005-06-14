/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdlib.h>
#include <dhcp_impl.h>
#include <sys/time.h>
#include <sys/nvpair.h>
#include <netinet/inetutil.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>
#include <net/if.h>
#if	defined(_BOOT)
#include <sys/salib.h>
#include <sys/bootcmn.h>
#include <ipv4.h>
#include <dhcpv4.h>
#endif	/* defined(_BOOT) */
#include <bootinfo.h>
#include <bootinfo_aux.h>

/*
 * Declarations and definitions describing parameters which may be known by
 * a bootconf name, a property of /chosen, a DHCP option or a 'bootmisc' name.
 */
typedef struct {
	const char	*opt_name;	/* DHCP option name */
	dsym_cdtype_t	opt_type;	/* DHCP option type (dhcp_symbol.h) */
	uchar_t		opt_cat;	/* DHCP option category */
	uint16_t	opt_code;	/* DHCP option code */
	uint16_t	opt_size;	/* DHCP option size (FIELDs only) */
} bi_dhcpopt_t;

/*
 * Possible values for the 'bi_flags' field below.
 */
#define	BI_F_BYTES	0x01		/* chosen value is bytes, not string */

typedef struct {
	const char	*bi_name;	/* parameter name */
	int		bi_repository;	/* entry's repository(s) */
	int		bi_flags;	/* BI_F_BYTES or zero */
	bi_dhcpopt_t	*bi_dhcp;	/* &dhcpopt struct */
} bi_param_t;

/*
 * DHCP options which have bootinfo equivalents, and the information
 * necessary to retrieve their values via dhcp_getinfo().  The 'type'
 * is necessary so that all values may be converted to ascii strings.
 */
static bi_dhcpopt_t	Yiaddr	    = {
	"Yiaddr",	DSYM_IP,	DSYM_FIELD,	16,	4
};
static bi_dhcpopt_t	Subnet	    = {
	"Subnet",	DSYM_IP,	DSYM_STANDARD,	1,	0
};
static bi_dhcpopt_t	Router	    = {
	"Router",	DSYM_IP,	DSYM_STANDARD,	3,	0
};
static bi_dhcpopt_t	Hostname    = {
	"Hostname",	DSYM_ASCII,	DSYM_STANDARD,	12,	0
};
static bi_dhcpopt_t	ClientID    = {
	"ClientID",	DSYM_OCTET,	DSYM_STANDARD,	61,	0
};
static bi_dhcpopt_t	SHTTPproxy  = {
	"SHTTPproxy",	DSYM_ASCII,	DSYM_VENDOR,	17,	0
};
#if	defined(_BOOT)
static bi_dhcpopt_t	BootFile    = {
	"BootFile",	DSYM_ASCII,	DSYM_FIELD,	108,	128
};
static bi_dhcpopt_t	SbootURI    = {
	"SbootURI",	DSYM_ASCII,	DSYM_VENDOR,	16,	0
};
#else
static bi_dhcpopt_t	SsysidCF    = {
	"SsysidCF",	DSYM_ASCII,	DSYM_VENDOR,	13,	0
};
static bi_dhcpopt_t	SjumpsCF    = {
	"SjumpsCF",	DSYM_ASCII,	DSYM_VENDOR,	14,	0
};
#endif	/* defined(_BOOT) */

/*
 * bootinfo's main data structure.
 */
static bi_param_t	bi_params[] = {
	/*
	 * Parameters from /chosen or DHCP:
	 */
	{ BI_HOST_IP,			BI_R_CHOSEN|BI_R_DHCPOPT,
	    0,		&Yiaddr					},
	{ BI_SUBNET_MASK,		BI_R_CHOSEN|BI_R_DHCPOPT,
	    0,		&Subnet					},
	{ BI_ROUTER_IP,			BI_R_CHOSEN|BI_R_DHCPOPT,
	    0,		&Router					},
	{ BI_HOSTNAME,			BI_R_CHOSEN|BI_R_DHCPOPT,
	    0,		&Hostname				},
	{ BI_CLIENT_ID,			BI_R_CHOSEN|BI_R_DHCPOPT,
	    BI_F_BYTES,	&ClientID				},
	{ BI_HTTP_PROXY,		BI_R_CHOSEN|BI_R_DHCPOPT,
	    0,		&SHTTPproxy				},

#if	defined(_BOOT)
	/*
	 * Parameters from /chosen or DHCP:
	 */
	{ BI_NETWORK_BOOT_FILE,		BI_R_CHOSEN|BI_R_DHCPOPT,
	    0,		&SbootURI				},

	/*
	 * Parameters from DHCP only:
	 */
	{ BI_BOOTFILE,			BI_R_DHCPOPT,
	    0,		&BootFile				},

	/*
	 * Parameters from /chosen only:
	 */
	{ BI_BOOTP_RESPONSE,		BI_R_CHOSEN,
	    BI_F_BYTES,	NULL					},
	{ BI_NET_CONFIG_STRATEGY,	BI_R_CHOSEN,
	    0,		NULL					},

	/*
	 * Parameters from 'bootmisc' only:
	 */
	{ BI_BOOTSERVER,		BI_R_BOOTMISC,
	    0,		NULL					},
	{ BI_AES_KEY,			BI_R_BOOTMISC,
	    BI_F_BYTES,	NULL					},
	{ BI_3DES_KEY,			BI_R_BOOTMISC,
	    BI_F_BYTES,	NULL					},
	{ BI_SHA1_KEY,			BI_R_BOOTMISC,
	    BI_F_BYTES,	NULL					},
#else
	/*
	 * Parameters from DHCP only:
	 */
	{ BI_SYSIDCFG,			BI_R_DHCPOPT,
	    0,		&SsysidCF				},
	{ BI_JUMPSCFG,			BI_R_DHCPOPT,
	    0,		&SjumpsCF				},

	/*
	 * Parameters from /chosen or 'bootmisc':
	 */
	{ BI_NET_CONFIG_STRATEGY,	BI_R_CHOSEN|BI_R_BOOTMISC,
	    0,		NULL					},

	/*
	 * Parameters from 'bootmisc' only:
	 */
	{ BI_ROOTFS_TYPE,		BI_R_BOOTMISC,
	    0,		NULL					},
	{ BI_INTERFACE_NAME,		BI_R_BOOTMISC,
	    0,		NULL					},
#endif	/* defined(_BOOT) */

	NULL
};

/*
 * Bootmisc data is handled internally as a nvpair list.
 */
static nvlist_t		*bi_nvl = NULL;


/*
 * Scan our parameter table to see whether 'name' matches any entry.
 */
static bi_param_t *
bi_find_param(const char *name)
{
	bi_param_t	*bip;

	for (bip = bi_params; bip->bi_name != NULL; bip++) {
		if (strcmp(name, bip->bi_name) == 0 ||
		    ((bip->bi_repository & BI_R_DHCPOPT) &&
		    strcmp(name, bip->bi_dhcp->opt_name) == 0)) {
			return (bip);
		}
	}
	return (NULL);
}

/*
 * Functions for retrieving /chosen, DHCP and bootmisc data.
 */
static int
bi_getval_chosen(bi_param_t *bip, void *valbuf, size_t *vallenp)
{
	size_t	buflen = *vallenp;

	if (!bi_get_chosen_prop(bip->bi_name, valbuf, vallenp)) {
		return (BI_E_NOVAL);
	} else if (*vallenp > buflen) {
		return (BI_E_BUF2SMALL);
	}

	return (BI_E_SUCCESS);
}

static int
bi_getval_dhcpopt(bi_param_t *bip, void *valbuf, size_t *vallenp)
{
	void		*val;
	size_t		len, buflen = *vallenp;
	struct in_addr	ipaddr;

	if (bip->bi_dhcp->opt_type == DSYM_IP) {
		val = &ipaddr;
		len = sizeof (ipaddr);
	} else {
		val = valbuf;
		len = *vallenp;
	}

	if (!bi_get_dhcp_info(bip->bi_dhcp->opt_cat, bip->bi_dhcp->opt_code,
	    bip->bi_dhcp->opt_size, val, &len)) {
		return (BI_E_NOVAL);
	}

	switch (bip->bi_dhcp->opt_type) {
	case DSYM_IP:
		if (buflen < INET_ADDRSTRLEN + 1) {
			*vallenp = len;
			return (BI_E_BUF2SMALL);
		}
		len = strlen(strcpy(valbuf, inet_ntoa(ipaddr))) + 1;
		break;

	case DSYM_ASCII:
		if (len >= buflen)
			return (BI_E_BUF2SMALL);

		((uchar_t *)valbuf)[len++] = '\0';
		break;
	}
	*vallenp = len;

	return (BI_E_SUCCESS);
}

static int
bi_getval_bootmisc(bi_param_t *bip, void *valbuf, size_t *vallenp)
{
	uchar_t		*val;
	uint_t		len;

	if (nvlist_lookup_byte_array(bi_nvl, (char *)bip->bi_name,
	    &val, &len) != 0) {
		return (BI_E_NOVAL);
	} else if (*vallenp < len) {
		*vallenp = len;
		return (BI_E_BUF2SMALL);
	}
	*vallenp = len;
	(void) memcpy(valbuf, val, *vallenp);

	return (BI_E_SUCCESS);
}

/*
 * This is also called from the userland bootinfo_aux.c to initialize
 * its bootmisc data.
 */
boolean_t
bi_put_bootmisc(const char *name, const void *valbuf, size_t vallen)
{
	return (nvlist_add_byte_array(bi_nvl, (char *)name,
	    (uchar_t *)valbuf, (uint_t)vallen) == 0);
}

#if	defined(_BOOT)
/*
 * Functions for storing /chosen and bootmisc data.
 */
static int
bi_putval_chosen(bi_param_t *bip, const void *valbuf, size_t vallen)
{
	return (bi_put_chosen_prop(bip->bi_name, valbuf, vallen,
	    (bip->bi_flags & BI_F_BYTES)) ? BI_E_SUCCESS : BI_E_ERROR);
}

static int
bi_putval_bootmisc(bi_param_t *bip, const void *valbuf, size_t vallen)
{
	return (bi_put_bootmisc(bip->bi_name, valbuf, vallen)
	    ? BI_E_SUCCESS : BI_E_ERROR);
}
#endif	/* defined(_BOOT) */


/*
 * Deallocate resources, etc. after accessing bootinfo.
 */
void
bootinfo_end(void)
{
	if (bi_nvl != NULL) {
		nvlist_free(bi_nvl);
		bi_nvl = NULL;
		bi_end_bootinfo();
	}
}

/*
 * Perform bootinfo initialization.
 */
boolean_t
bootinfo_init(void)
{
	if (bi_nvl == NULL &&
	    nvlist_alloc(&bi_nvl, NV_UNIQUE_NAME, 0) == 0) {
		if (!bi_init_bootinfo()) {
			nvlist_free(bi_nvl);
			bi_nvl = NULL;
		}
	}

	return (bi_nvl != NULL);
}

/*
 * bootinfo_get(const char *name, void *valbuf, size_t *vallenp,
 *     int *repository);
 *
 * Obtain a value for a named boot parameter from one of a number of possible
 * repositories:
 *
 *   - stored properties under /chosen in the device tree;
 *   - returned DHCP data;
 *   - miscellaneous boot information, determined from the standalone or
 *     the kernel (depending on whether we're in the standalone or userland).
 *
 * These repositories are interrogated in the order listed above; the first
 * one to match is value returned.
 *
 * Returns:
 *	0  => successful, value copied to valbuf, length assigned to *vallen.
 *	>0 => error (BI_E_* codes defined in bootinfo.h)
 */
bi_errcode_t
bootinfo_get(const char *name, void *valbufp, size_t *vallenp,
    int *repositoryp)
{
	bi_param_t	*bip;
	int		repositories;
	int		err;
	size_t		zerolen = 0;

	/*
	 * Check whether we were successfully initialized.
	 */
	if (bi_nvl == NULL) {
		return (BI_E_ERROR);
	}

	/*
	 * Determine which repositories might be accessed; a NULL pointer
	 * means to (possibly) access them all.
	 */
	if (repositoryp != NULL) {
		repositories = *repositoryp;
		*repositoryp = 0;
	} else {
		repositories = BI_R_ALL;
	}

	/*
	 * Check that we know about this name in one or more of the
	 * requested repositories.
	 */
	if ((bip = bi_find_param(name)) == NULL) {
		return (BI_E_ILLNAME);
	}
	repositories &= bip->bi_repository;
	if (repositories == 0) {
		return (BI_E_ILLNAME);
	}

	/*
	 * The caller may simply be enquiring whether a value is present:
	 *
	 *    bootinfo_get(name, NULL, NULL, repository) == BI_E_BUF2SMALL
	 *
	 * indicates that there is a value, but doesn't fetch it.
	 */
	if (vallenp == NULL) {
		vallenp = &zerolen;
	}

	/*
	 * To retrieve a value, try the various repositories in order.
	 */
	if ((repositories & BI_R_CHOSEN) != 0 &&
	    (err = bi_getval_chosen(bip, valbufp, vallenp)) != BI_E_NOVAL) {
		if (repositoryp != NULL) {
			*repositoryp = BI_R_CHOSEN;
		}
		return (err);
	}
	if ((repositories & BI_R_DHCPOPT) != 0 &&
	    (err = bi_getval_dhcpopt(bip, valbufp, vallenp)) != BI_E_NOVAL) {
		if (repositoryp != NULL) {
			*repositoryp = BI_R_DHCPOPT;
		}
		return (err);
	}
	if ((repositories & BI_R_BOOTMISC) != 0 &&
	    (err = bi_getval_bootmisc(bip, valbufp, vallenp)) != BI_E_NOVAL) {
		if (repositoryp != NULL) {
			*repositoryp = BI_R_BOOTMISC;
		}
		return (err);
	}

	/*
	 * No-one has a value for 'name'.
	 */
	return (BI_E_NOVAL);
}

#if	defined(_BOOT)
/*
 * bootinfo_put(const char *name, char *valbuf, int vallen,
 *     int repository);
 *
 * Create/update a value in the bootinfo repository (standalone only).
 *
 * Returns:
 *	0  => successful, valbuf[0..vallen-1] bytes stored in repository
 *	>0 => error (BI_E_* codes defined in bootinfo.h)
 */
int
bootinfo_put(const char *name, const void *valbuf, size_t vallen,
    int repository)
{
	bi_param_t	*bip;

	/*
	 * Check whether we were successfully initialized.
	 */
	if (bi_nvl == NULL) {
		return (BI_E_ERROR);
	}

	/*
	 * Determine which repositories might be accessed; a zero value
	 * means to (possibly) access them all.
	 */
	if (repository == 0) {
		repository = BI_R_ALL;
	}

	/*
	 * Check that we know about this name in the specified repository,
	 * and that it may be written (note that DHCP options cannot be
	 * written).
	 */
	if ((bip = bi_find_param(name)) == NULL ||
	    (repository & bip->bi_repository) == 0) {
		return (BI_E_ILLNAME);
	}
	if ((repository & bip->bi_repository) == BI_R_DHCPOPT) {
		return (BI_E_RDONLY);
	}

	/*
	 * To put the value, try the various repositories in order.
	 */
	if ((bip->bi_repository & BI_R_CHOSEN) != 0) {
		return (bi_putval_chosen(bip, valbuf, vallen));
	}
	if ((bip->bi_repository & BI_R_BOOTMISC) != 0) {
		return (bi_putval_bootmisc(bip, valbuf, vallen));
	}

	return (BI_E_ERROR);
}
#endif	/* defined(_BOOT) */
