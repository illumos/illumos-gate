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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/priv_names.h>

/*
 * This file contains generic goo needed to hook the STREAMS modules and
 * drivers that live under uts/common/inet into the DDI.  In order to use it,
 * each module/driver should #define the symbols below (as appropriate) and
 * then #include this source file; see the other uts/common/inet/<star>ddi.c
 * files for examples of this in action.
 *
 * The symbols that all modules and drivers must define are:
 *
 *	INET_NAME	 The name of the module/driver.
 *
 * The symbols that all modules must define are:
 *
 *	INET_MODSTRTAB	 The name of the `streamtab' structure for this module.
 *	INET_MODDESC	 The one-line description for this module.
 *	INET_MODMTFLAGS  The mt-streams(9F) flags for the module.
 *
 * The symbols that all drivers must define are:
 *
 *	INET_DEVSTRTAB	 The name of the `streamtab' structure for this driver.
 *	INET_DEVDESC	 The one-line description for this driver.
 *	INET_DEVMTFLAGS  The mt-streams(9F) flags for the driver.
 *	INET_DEVMINOR	 The minor number of the driver (usually 0).
 *
 * Drivers that need to masquerade as IP should set INET_DEVMTFLAGS to
 * IP_DEVMTFLAGS and set INET_DEVSTRTAB to ipinfo.
 *
 * The symbols that all socket modules must define are:
 *
 *	INET_SOCKDESC	The one-line description for this socket module
 *	INET_SOCK_PROTO_CREATE_FUNC The function used to create PCBs
 *
 * In addition, socket modules that can be converted to TPI must define:
 *
 *	INET_SOCK_PROTO_FB_FUNC The function used to fallback to TPI
 */

#if	!defined(INET_NAME)
#error inetddi.c: INET_NAME is not defined!
#elif	!defined(INET_DEVDESC) && !defined(INET_MODDESC) && \
	!defined(INET_SOCKDESC)
#error inetddi.c: at least one of INET_DEVDESC or INET_MODDESC or \
INET_SOCKDESC must be defined!
#elif	defined(INET_DEVDESC) && !defined(INET_DEVSTRTAB)
#error inetddi.c: INET_DEVDESC is defined but INET_DEVSTRTAB is not!
#elif	defined(INET_DEVDESC) && !defined(INET_DEVMTFLAGS)
#error inetddi.c: INET_DEVDESC is defined but INET_DEVMTFLAGS is not!
#elif	defined(INET_DEVDESC) && !defined(INET_DEVMINOR)
#error inetddi.c: INET_DEVDESC is defined but INET_DEVMINOR is not!
#elif	defined(INET_MODDESC) && !defined(INET_MODSTRTAB)
#error inetddi.c: INET_MODDESC is defined but INET_MODSTRTAB is not!
#elif	defined(INET_MODDESC) && !defined(INET_MODMTFLAGS)
#error inetddi.c: INET_MODDESC is defined but INET_MODMTFLAGS is not!
#elif	defined(INET_SOCKDESC) && !defined(SOCKMOD_VERSION)
#error  inetddi.c: INET_SOCKDESC is defined but SOCKMOD_VERSION is not!
#elif	defined(INET_SOCKDESC) && !defined(INET_SOCK_PROTO_CREATE_FUNC)
#error  inetddi.c: INET_SOCKDESC is defined but INET_SOCK_PROTO_CREATE_FUNC \
is not!
#elif	defined(INET_SOCK_PROTO_FB_FUNC) && !defined(INET_SOCK_FALLBACK_DEV_V4)
#error	inetddi.c: INET_SOCK_PROTO_FB_FUNC is defined but \
INET_SOCK_FALLBACK_DEV_V4 is not!
#elif	defined(INET_SOCK_PROTO_FB_FUNC) && !defined(INET_SOCK_FALLBACK_DEV_V6)
#error	inetddi.c: INET_SOCK_PROTO_FB_FUNC is defined but \
INET_SOCK_FALLBACK_DEV_V6 is not!
#endif

#ifdef	INET_DEVDESC

extern struct streamtab INET_DEVSTRTAB;

/*
 * Drivers that actually want to be IP would set INET_DEVSTRTAB to ipinfo.
 */

static dev_info_t *inet_dev_info;

#define	INET_DEFAULT_PRIV_MODE	0666

static struct dev_priv {
	char *driver;
	int privonly;
	const char *read_priv;
	const char *write_priv;
} netdev_privs[] = {
	{"icmp", PRIVONLY_DEV,	PRIV_NET_ICMPACCESS,	PRIV_NET_ICMPACCESS},
	{"icmp6", PRIVONLY_DEV,	PRIV_NET_ICMPACCESS,	PRIV_NET_ICMPACCESS},
	{"ip", PRIVONLY_DEV,	PRIV_NET_RAWACCESS,	PRIV_NET_RAWACCESS},
	{"ip6", PRIVONLY_DEV,	PRIV_NET_RAWACCESS,	PRIV_NET_RAWACCESS},
	{"keysock", PRIVONLY_DEV, PRIV_SYS_IP_CONFIG,	PRIV_SYS_IP_CONFIG},
	{"ipsecah", PRIVONLY_DEV, PRIV_SYS_IP_CONFIG,	PRIV_SYS_IP_CONFIG},
	{"ipsecesp", PRIVONLY_DEV, PRIV_SYS_IP_CONFIG,	PRIV_SYS_IP_CONFIG},
	{"spdsock", PRIVONLY_DEV, PRIV_SYS_IP_CONFIG,	PRIV_SYS_IP_CONFIG},
	{NULL,	0,		NULL,			NULL}
};

static int
inet_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	size_t i, ndevs;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	inet_dev_info = devi;

	ndevs = sizeof (netdev_privs) / sizeof (struct dev_priv);
	for (i = 0; i < ndevs; i++) {
		char *drv = netdev_privs[i].driver;
		if (drv == NULL || strcmp(drv, ddi_driver_name(devi)) == 0)
			break;
	}

	/* smatch has no idea what VERIFY does. */
	if (i == ndevs) {
		VERIFY(i < ndevs);
		return (DDI_FAILURE);
	}

	return (ddi_create_priv_minor_node(devi, INET_NAME, S_IFCHR,
	    INET_DEVMINOR, DDI_PSEUDO, netdev_privs[i].privonly,
	    netdev_privs[i].read_priv, netdev_privs[i].write_priv,
	    INET_DEFAULT_PRIV_MODE));
}

static int
inet_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ASSERT(devi == inet_dev_info);

	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}


/* ARGSUSED */
static int
inet_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error = DDI_FAILURE;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (inet_dev_info != NULL) {
			*result = (void *)inet_dev_info;
			error = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		error = DDI_SUCCESS;
		break;

	default:
		break;
	}

	return (error);
}

DDI_DEFINE_STREAM_OPS(inet_devops, nulldev, nulldev, inet_attach, inet_detach,
    nulldev, inet_info, INET_DEVMTFLAGS, &INET_DEVSTRTAB,
    ddi_quiesce_not_supported);

static struct modldrv modldrv = {
	&mod_driverops,
	INET_DEVDESC,
	&inet_devops
};

#endif /* INET_DEVDESC */

#ifdef	INET_MODDESC
extern struct streamtab INET_MODSTRTAB;

static struct fmodsw fsw = {
	INET_NAME,
	&INET_MODSTRTAB,
	INET_MODMTFLAGS
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops,
	INET_MODDESC,
	&fsw
};

#endif /* INET_MODDESC */

#ifdef  INET_SOCKDESC

#ifdef	INET_SOCK_PROTO_FB_FUNC
static __smod_priv_t smodpriv = {
	NULL,
	NULL,
	INET_SOCK_PROTO_FB_FUNC,
	INET_SOCK_FALLBACK_DEV_V4,
	INET_SOCK_FALLBACK_DEV_V6
};
#endif	/* INET_SOCK_PROTO_FB_FUNC */

static struct smod_reg_s smodreg = {
	SOCKMOD_VERSION,
	INET_NAME,
	SOCK_UC_VERSION,
	SOCK_DC_VERSION,
	INET_SOCK_PROTO_CREATE_FUNC,
#ifdef	INET_SOCK_PROTO_FB_FUNC
	&smodpriv
#else
	NULL
#endif	/* INET_SOCK_PROTO_FB_FUNC */
};

static struct modlsockmod modlsockmod = {
	&mod_sockmodops,
	INET_SOCKDESC,
	&smodreg
};
#endif	/* INET_SOCKDESC */

static struct modlinkage modlinkage = {
	MODREV_1,
#ifdef	INET_DEVDESC
	&modldrv,
#endif
#ifdef	INET_MODDESC
	&modlstrmod,
#endif
#ifdef	INET_SOCKDESC
	&modlsockmod,
#endif
	NULL
};
