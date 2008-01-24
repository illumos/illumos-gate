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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/param.h>
#include	<sys/types.h>
#include	<sys/user.h>
#include	<sys/vfs.h>
#include	<sys/vnode.h>
#include	<sys/file.h>
#include	<sys/stream.h>
#include	<sys/stropts.h>
#include	<sys/strsubr.h>
#include	<sys/dlpi.h>
#include	<sys/vnode.h>
#include	<sys/socket.h>
#include	<sys/sockio.h>
#include	<net/if.h>

#include	<sys/cred.h>
#include	<sys/sysmacros.h>

#include	<sys/sad.h>
#include	<sys/kstr.h>
#include	<sys/bootconf.h>
#include	<sys/bootprops.h>

#include	<sys/errno.h>
#include	<sys/modctl.h>
#include	<sys/sunddi.h>
#include	<sys/sunldi.h>
#include	<sys/esunddi.h>
#include	<sys/promif.h>

#include	<netinet/in.h>
#include	<netinet/ip6.h>
#include	<netinet/icmp6.h>
#include	<netinet/sctp.h>
#include	<inet/common.h>
#include	<inet/ip.h>
#include	<inet/ip6.h>
#include	<inet/tcp.h>
#include	<inet/sctp_ip.h>

#include	<sys/strlog.h>
#include	<sys/log.h>
#include	<sys/ethernet.h>
#include	<sys/ddi_implfuncs.h>

#include	<sys/dld.h>

/*
 * Debug Macros
 */
int	strplumbdebug = 0;

#define	DBG0(_f) \
	if (strplumbdebug != 0) \
		printf("strplumb: " _f)

#define	DBG1(_f, _a) \
	if (strplumbdebug != 0) \
		printf("strplumb: " _f, (_a))

#define	DBG2(_f, _a, _b) \
	if (strplumbdebug != 0) \
		printf("strplumb: " _f, (_a), (_b))

#define	DBG3(_f, _a, _b, _c) \
	if (strplumbdebug != 0) \
		printf("strplumb: " _f, (_a), (_b), (_c))

/*
 * Module linkage information for the kernel.
 */
#define	STRPLUMB_IDENT	"STREAMS Plumbing Module"

static struct modlmisc modlmisc = {
	&mod_miscops,
	STRPLUMB_IDENT
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlmisc,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#define	ARP		"arp"
#define	TCP		"tcp"
#define	TCP6		"tcp6"
#define	UDP		"udp"
#define	UDP6		"udp6"
#define	SCTP		"sctp"
#define	SCTP6		"sctp6"
#define	ICMP		"icmp"
#define	ICMP6		"icmp6"
#define	IP		"ip"
#define	IP6		"ip6"
#define	TIMOD		"timod"

#define	UDPDEV		"/devices/pseudo/udp@0:udp"
#define	TCP6DEV		"/devices/pseudo/tcp6@0:tcp6"
#define	SCTP6DEV	"/devices/pseudo/sctp6@0:sctp6"
#define	IP6DEV		"/devices/pseudo/ip6@0:ip6"

typedef struct strplumb_modspec {
	char	*sm_type;
	char	*sm_name;
} strplumb_modspec_t;

static strplumb_modspec_t	strplumb_modlist[] = {
	{ "drv", DLD_DRIVER_NAME },
	{ "drv", IP },
	{ "drv", IP6 },
	{ "drv", TCP },
	{ "drv", TCP6 },
	{ "drv", UDP },
	{ "drv", UDP6 },
	{ "drv", SCTP },
	{ "drv", SCTP6 },
	{ "drv", ICMP },
	{ "drv", ICMP6 },
	{ "drv", ARP },
	{ "strmod", TIMOD }
};

/*
 * Called from swapgeneric.c:loadrootmodules() in the network boot case.
 */
int
strplumb_load(void)
{
	uint_t			i;
	strplumb_modspec_t	*p;

	DBG0("loading modules\n");

	for (i = 0, p = strplumb_modlist;
	    i < sizeof (strplumb_modlist) / sizeof (strplumb_modlist[0]);
	    i++, p++) {
		if (modloadonly(p->sm_type, p->sm_name) < 0) {
			printf("strplumb: failed to load %s/%s\n",
			    p->sm_type, p->sm_name);
			return (EFAULT);
		}
	}

	return (0);
}

static int
strplumb_init(void)
{
	uint_t			i;
	strplumb_modspec_t	*p;
	int			err;

	DBG0("initializing modules\n");

	for (i = 0, p = strplumb_modlist;
	    i < sizeof (strplumb_modlist) / sizeof (strplumb_modlist[0]);
	    i++, p++) {
		if (strcmp(p->sm_type, "drv") == 0)
			err = (i_ddi_attach_pseudo_node(p->sm_name) != NULL) ?
			    0 : EFAULT;
		else
			err = (modload(p->sm_type, p->sm_name) < 0) ?
			    EFAULT : 0;

		if (err != 0)  {
			printf("strplumb: failed to initialize %s/%s\n",
			    p->sm_type, p->sm_name);
			return (err);
		}
	}

	return (0);
}

static int
strplumb_autopush(void)
{
	major_t		maj;
	minor_t		min;
	char		*mods[5];
	uint_t		anchor = 1;
	int		err;

	min = (minor_t)-1;
	mods[1] = NULL;

	/*
	 * ARP
	 */
	DBG0("setting up arp autopush\n");

	mods[0] = ARP;

	maj = ddi_name_to_major(ARP);
	if ((err = kstr_autopush(SET_AUTOPUSH, &maj, &min, NULL, &anchor,
	    mods)) != 0) {
		printf("strplumb: kstr_autopush(SET/ARP) failed: %d\n", err);
		return (err);
	}

	return (0);
}

static int
strplumb_sctpq(ldi_ident_t li)
{
	ldi_handle_t	lh = NULL;
	int		err;
	int		rval;

	DBG0("configuring SCTP default queue\n");

	if ((err = ldi_open_by_name(SCTP6DEV, FREAD|FWRITE, CRED(), &lh,
	    li)) != 0) {
		printf("strplumb: open of SCTP6DEV failed: %d\n", err);
		return (err);
	}

	if ((err = ldi_ioctl(lh, SCTP_IOC_DEFAULT_Q, (intptr_t)0, FKIOCTL,
	    CRED(), &rval)) != 0) {
		printf("strplumb: failed to set SCTP default queue: %d\n",
		    err);
		(void) ldi_close(lh, FREAD|FWRITE, CRED());
		return (err);
	}

	return (0);
}

static int
strplumb_tcpq(ldi_ident_t li)
{
	ldi_handle_t	lh = NULL;
	ldi_handle_t	ip_lh = NULL;
	int		err;
	int		rval;

	DBG0("configuring TCP default queue\n");

	/*
	 * We open IP6DEV here because we need to have it open to in
	 * order to open TCP6DEV successfully.
	 */
	if ((err = ldi_open_by_name(IP6DEV, FREAD|FWRITE, CRED(), &ip_lh,
	    li)) != 0) {
		printf("strplumb: open of IP6DEV failed: %d\n", err);
		return (err);
	}

	/*
	 * We set the tcp default queue to IPv6 because IPv4 falls back to
	 * IPv6 when it can't find a client, but IPv6 does not fall back to
	 * IPv4.
	 */
	if ((err = ldi_open_by_name(TCP6DEV, FREAD|FWRITE, CRED(), &lh,
	    li)) != 0) {
		printf("strplumb: open of TCP6DEV failed: %d\n", err);
		goto done;
	}

	if ((err = ldi_ioctl(lh, TCP_IOC_DEFAULT_Q, (intptr_t)0, FKIOCTL,
	    CRED(), &rval)) != 0) {
		printf("strplumb: failed to set TCP default queue: %d\n",
		    err);
		goto done;
	}

done:
	(void) ldi_close(ip_lh, FREAD|FWRITE, CRED());
	return (err);
}

/*
 * Can be set in /etc/system in the case of local booting. See comment below.
 */
char	*ndev_name = 0;
int	ndev_unit = 0;

/*
 * If we booted diskless then strplumb() will have been called from
 * swapgeneric.c:rootconf(). All we can do in that case is plumb the
 * network device that we booted from.
 *
 * If we booted from a local disk, we will have been called from main(),
 * and normally we defer the plumbing of interfaces until network/physical.
 * This can be overridden by setting "ndev_name" in /etc/system.
 */
static int
resolve_boot_path(void)
{
	char			*devpath;
	dev_info_t		*dip;
	const char		*driver;
	int			instance;
#ifdef	_OBP
	char			stripped_path[OBP_MAXPATHLEN];
#endif

	if (strncmp(rootfs.bo_fstype, "nfs", 3) == 0)
		devpath = rootfs.bo_name;
	else
		devpath = strplumb_get_netdev_path();

	if (devpath != NULL) {
		DBG1("resolving boot-path: %s\n", devpath);
#ifdef _OBP
		/*
		 * OBP passes options e.g, "net:dhcp"
		 * remove them here
		 */
		prom_strip_options(devpath, stripped_path);
		devpath = stripped_path;
#endif
		/*
		 * Hold the devi since this is the root device.
		 */
		if ((dip = e_ddi_hold_devi_by_path(devpath, 0)) == NULL) {
			printf("strplumb: unable to hold root device: %s\n",
			    devpath);
			return (ENXIO);
		}

		driver = ddi_driver_name(dip);
		instance = ddi_get_instance(dip);
	} else {
		if (ndev_name == NULL)
			return (ENODEV);

		DBG2("using ndev_name (%s) ndev_unit (%d)\n", ndev_name,
		    ndev_unit);

		if (i_ddi_attach_hw_nodes(ndev_name) != DDI_SUCCESS) {
			printf("strplumb: cannot load ndev_name '%s'\n",
			    ndev_name);
			return (ENXIO);
		}

		driver = ndev_name;
		instance = ndev_unit;
	}

	(void) snprintf(rootfs.bo_devname, BO_MAXOBJNAME,
	    "/devices/pseudo/clone@0:%s", driver);
	(void) snprintf(rootfs.bo_ifname, BO_MAXOBJNAME, "%s%d",
	    driver, instance);
	rootfs.bo_ppa = instance;
	return (0);
}

static int
getifflags(ldi_handle_t lh, struct lifreq *lifrp)
{
	struct strioctl	iocb;
	int		rval;

	iocb.ic_cmd = SIOCGLIFFLAGS;
	iocb.ic_timout = 15;
	iocb.ic_len = sizeof (struct lifreq);
	iocb.ic_dp = (char *)lifrp;

	return (ldi_ioctl(lh, I_STR, (intptr_t)&iocb, FKIOCTL, CRED(), &rval));

}

static int
setifname(ldi_handle_t lh, struct lifreq *lifrp)
{
	struct strioctl	iocb;
	int		rval;

	iocb.ic_cmd = SIOCSLIFNAME;
	iocb.ic_timout = 15;
	iocb.ic_len = sizeof (struct lifreq);
	iocb.ic_dp = (char *)lifrp;

	return (ldi_ioctl(lh, I_STR, (intptr_t)&iocb, FKIOCTL, CRED(), &rval));
}

static int
strplumb_dev(ldi_ident_t li)
{
	ldi_handle_t	lh = NULL;
	ldi_handle_t	mux_lh = NULL;
	int		err;
	struct lifreq	lifr;
	struct ifreq	ifr;
	int		rval;

	bzero(&lifr, sizeof (struct lifreq));
	bzero(&ifr, sizeof (ifr));

	/*
	 * Now set up the links. Ultimately, we should have two streams
	 * permanently linked underneath UDP (which is actually IP with UDP
	 * autopushed). One stream consists of the ARP-[ifname] combination,
	 * while the other consists of ARP-IP-[ifname]. The second combination
	 * seems a little weird, but is linked underneath UDP just to keep it
	 * around.
	 *
	 * We pin underneath UDP here to match what is done in ifconfig(1m);
	 * otherwise, ifconfig will be unable to unplumb the stream (the major
	 * number and mux id must both match for a successful I_PUNLINK).
	 *
	 * There are subtleties in the plumbing which make it essential to
	 * follow the logic used in ifconfig(1m) very closely.
	 */

	/*
	 * Plumb UDP-ARP-IP-<dev>
	 */

	if ((err = ldi_open_by_name(rootfs.bo_devname, FREAD|FWRITE, CRED(),
	    &lh, li)) != 0) {
		printf("strplumb: open %s failed: %d\n", rootfs.bo_devname,
		    err);
		goto done;
	}


	if ((err = ldi_ioctl(lh, I_PUSH, (intptr_t)IP, FKIOCTL, CRED(),
	    &rval)) != 0) {
		printf("strplumb: push IP failed: %d\n", err);
		goto done;
	}

	if ((err = getifflags(lh, &lifr)) != 0)
		goto done;

	lifr.lifr_flags |= IFF_IPV4;
	lifr.lifr_flags &= ~IFF_IPV6;

	if ((err = ldi_ioctl(lh, I_PUSH, (intptr_t)ARP, FKIOCTL, CRED(),
	    &rval)) != 0) {
		printf("strplumb: push ARP failed: %d\n", err);
		goto done;
	}

	(void) strlcpy(lifr.lifr_name, rootfs.bo_ifname,
	    sizeof (lifr.lifr_name));
	lifr.lifr_ppa = rootfs.bo_ppa;

	if ((err = setifname(lh, &lifr)) != 0)
		goto done;

	/* Get the flags and check if ARP is needed */
	if ((err = getifflags(lh, &lifr)) != 0) {
		printf("strplumb: getifflags %s IP failed, error %d\n",
		    lifr.lifr_name, err);
		goto done;
	}

	/* Pop out ARP if not needed */
	if (lifr.lifr_flags & IFF_NOARP) {
		err = ldi_ioctl(lh, I_POP, (intptr_t)0, FKIOCTL, CRED(),
		    &rval);
		if (err != 0) {
			printf("strplumb: pop ARP failed, error %d\n", err);
			goto done;
		}
	}

	if ((err = ldi_open_by_name(UDPDEV, FREAD|FWRITE, CRED(), &mux_lh,
	    li)) != 0) {
		printf("strplumb: open of UDPDEV failed: %d\n", err);
		goto done;
	}

	if ((err = ldi_ioctl(mux_lh, I_PLINK, (intptr_t)lh,
	    FREAD|FWRITE|FNOCTTY|FKIOCTL, CRED(),
	    &(ifr.ifr_ip_muxid))) != 0) {
		printf("strplumb: plink UDP-ARP-IP-%s failed: %d\n",
		    rootfs.bo_ifname, err);
		goto done;
	}

	DBG2("UDP-ARP-IP-%s muxid: %d\n", rootfs.bo_ifname, ifr.ifr_ip_muxid);

	(void) ldi_close(lh, FREAD|FWRITE, CRED());
	lh = NULL;

	/*
	 * Plumb UDP-ARP-<dev>
	 */

	if ((err = ldi_open_by_name(rootfs.bo_devname, FREAD|FWRITE, CRED(),
	    &lh, li)) != 0) {
		printf("strplumb: open %s failed: %d\n", rootfs.bo_devname,
		    err);
		goto done;
	}

	if ((err = ldi_ioctl(lh, I_PUSH, (intptr_t)ARP, FKIOCTL, CRED(),
	    &rval)) != 0) {
		printf("strplumb: push ARP failed: %d\n", err);
		goto done;
	}

	if ((err = setifname(lh, &lifr)) != 0)
		goto done;

	if ((err = ldi_ioctl(mux_lh, I_PLINK, (intptr_t)lh,
	    FREAD|FWRITE|FNOCTTY|FKIOCTL, CRED(),
	    &(ifr.ifr_arp_muxid))) != 0) {
		printf("strplumb: plink UDP-ARP-%s failed: %d\n",
		    rootfs.bo_ifname, err);
		goto done;
	}

	DBG2("UDP-ARP-%s muxid: %d\n", rootfs.bo_ifname, ifr.ifr_arp_muxid);

	/*
	 * Cache the mux ids.
	 */
	(void) strlcpy(ifr.ifr_name, rootfs.bo_ifname, sizeof (ifr.ifr_name));

	if ((err = ldi_ioctl(mux_lh, SIOCSIFMUXID, (intptr_t)&ifr, FKIOCTL,
	    CRED(), &rval)) != 0) {
		printf("strplumb: SIOCSIFMUXID failed: %d\n", err);
		goto done;
	}

done:
	if (lh != NULL)
		(void) ldi_close(lh, FREAD|FWRITE, CRED());

	if (mux_lh != NULL)
		(void) ldi_close(mux_lh, FREAD|FWRITE, CRED());

	return (err);
}

/*
 * Do streams plumbing for internet protocols.
 */
int
strplumb(void)
{
	ldi_ident_t	li;
	int		err;

	if ((err = strplumb_init()) != 0)
		return (err);

	if ((err = strplumb_autopush()) != 0)
		return (err);

	if ((err = ldi_ident_from_mod(&modlinkage, &li)) != 0)
		return (err);

	/*
	 * Setup the TCP and SCTP default queues for the global stack.
	 * tcp/sctp_stack_init will do this for additional stack instances.
	 */
	if ((err = strplumb_sctpq(li)) != 0)
		goto done;

	if ((err = strplumb_tcpq(li)) != 0)
		goto done;

	if ((err = resolve_boot_path()) != 0)
		goto done;

	DBG1("rootfs.bo_devname: %s\n", rootfs.bo_devname);
	DBG1("rootfs.bo_ifname: %s\n", rootfs.bo_ifname);
	DBG1("rootfs.bo_ppa: %d\n", rootfs.bo_ppa);

	if ((err = strplumb_dev(li)) != 0)
		goto done;

done:
	ldi_ident_release(li);

	return (err);
}

/* multiboot:  diskless boot interface discovery */

#ifndef	_OBP

static uchar_t boot_macaddr[16];
static int boot_maclen;
static uchar_t *getmacaddr(dev_info_t *dip, size_t *maclenp);
static int matchmac(dev_info_t *dip, void *arg);

#endif  /* !_OBP */

char *
strplumb_get_netdev_path(void)
{
#ifdef	_OBP
	char fstype[OBP_MAXPROPNAME];

	if (bop_getprop("fstype", fstype) == -1)
		return (NULL);

	if (strncmp(fstype, "nfs", 3) == 0)
		return (prom_bootpath());
	else
		return (NULL);
#else

	char *macstr, *devpath = NULL;
	uchar_t *bootp;
	uint_t bootp_len;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_BOOT_MAC, &macstr) == DDI_SUCCESS) {
		/*
		 * hard coded ether mac len for booting floppy on
		 * machines with old cards
		 */
		boot_maclen = ether_aton(macstr, boot_macaddr);
		if (boot_maclen != 6) {
			cmn_err(CE_WARN,
			    "malformed boot_mac property, %d bytes",
			    boot_maclen);
		}
		ddi_prop_free(macstr);
	} else if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_BOOTP_RESPONSE, &bootp, &bootp_len)
	    == DDI_SUCCESS) {

		/*
		 * These offsets are defined by dhcp standard
		 * Should use structure offsets
		 */
		boot_maclen = *(bootp + 2);
		ASSERT(boot_maclen <= 16);
		bcopy(bootp + 28, boot_macaddr, boot_maclen);

		dhcack = kmem_alloc(bootp_len, KM_SLEEP);
		bcopy(bootp, dhcack, bootp_len);
		dhcacklen = bootp_len;

		ddi_prop_free(bootp);
	} else
		return (NULL);

	ddi_walk_devs(ddi_root_node(), matchmac, (void *)&devpath);
	return (devpath);

#endif  /* _OBP */
}

#ifndef _OBP

/*
 * Get boot path from the boot_mac address
 */
/*ARGSUSED*/
static int
matchmac(dev_info_t *dip, void *arg)
{
	char **devpathp = (char **)arg;
	char *model_str;
	uchar_t *macaddr;
	size_t maclen;

	/* XXX Should use "device-type" per IEEE 1275 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
	    "model", &model_str) != DDI_SUCCESS)
		return (DDI_WALK_CONTINUE);

	if (strcmp(model_str, "Ethernet controller") != 0) {
		ddi_prop_free(model_str);
		return (DDI_WALK_CONTINUE);
	}
	ddi_prop_free(model_str);

	/* We have a network device now */
	if (i_ddi_attach_node_hierarchy(dip) != DDI_SUCCESS) {
		return (DDI_WALK_CONTINUE);
	}

	ASSERT(boot_maclen != 0);
	macaddr = getmacaddr(dip, &maclen);
	if (macaddr == NULL)
		return (DDI_WALK_CONTINUE);

	if (maclen != boot_maclen ||
	    bcmp(macaddr, boot_macaddr, maclen) != 0) {
		kmem_free(macaddr, maclen);
		return (DDI_WALK_CONTINUE);
	}

	/* found hardware with the mac address */
	(void) localetheraddr((struct ether_addr *)macaddr, NULL);
	kmem_free(macaddr, maclen);

	*devpathp = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, *devpathp);

	/* fill in dhcifname */
	if (dhcack) {
		(void) snprintf(dhcifname, IFNAMSIZ, "%s%d",
		    ddi_driver_name(dip), i_ddi_devi_get_ppa(dip));
	}
	return (DDI_WALK_TERMINATE);
}

static uchar_t *
getmacaddr(dev_info_t *dip, size_t *maclenp)
{
	int rc, ppa;
	ldi_ident_t li;
	ldi_handle_t lh;
	const char *drv_name = ddi_driver_name(dip);
	char *clonepath;
	uchar_t *macaddr = NULL;

	if (rc = ldi_ident_from_mod(&modlinkage, &li)) {
		cmn_err(CE_WARN,
		    "getmacaddr: ldi_ident_from_mod failed: %d\n", rc);
		return (NULL);
	}

	clonepath = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) snprintf(clonepath, MAXPATHLEN,
	    "/devices/pseudo/clone@0:%s", drv_name);

	rc = ldi_open_by_name(clonepath, FREAD|FWRITE, CRED(), &lh, li);
	ldi_ident_release(li);
	if (rc) {
		cmn_err(CE_WARN,
		    "getmacaddr: ldi_open_by_name(%s) failed: %d\n",
		    clonepath, rc);
		kmem_free(clonepath, MAXPATHLEN);
		return (NULL);
	}
	kmem_free(clonepath, MAXPATHLEN);

	ppa = i_ddi_devi_get_ppa(dip);
	if ((dl_attach(lh, ppa, NULL) != 0) ||
	    (dl_bind(lh, ETHERTYPE_IP, NULL) != 0)) {
		(void) ldi_close(lh, FREAD|FWRITE, CRED());
		cmn_err(CE_WARN,
		    "getmacaddr: dl_attach/bind(%s%d) failed: %d\n",
		    drv_name, ppa, rc);
		return (NULL);
	}

	*maclenp = ETHERADDRL;
	macaddr = kmem_alloc(ETHERADDRL, KM_SLEEP);
	if (dl_phys_addr(lh, macaddr, maclenp, NULL) != 0 ||
	    *maclenp != ETHERADDRL) {
		kmem_free(macaddr, ETHERADDRL);
		macaddr = NULL;
		*maclenp = 0;
		cmn_err(CE_WARN,
		    "getmacaddr: dl_phys_addr(%s%d) failed: %d\n",
		    drv_name, ppa, rc);
	}
	(void) ldi_close(lh, FREAD|FWRITE, CRED());
	return (macaddr);
}
#endif	/* !_OBP */
