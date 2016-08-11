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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * lxinit performs zone-specific initialization prior to handing control to the
 * guest Linux init.  This primarily consists of:
 *
 * - Starting ipmgmtd
 * - Configuring network interfaces
 * - Adding a default route
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <sys/ioccom.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/sockio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/varargs.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <libcmdutils.h>

#include <netinet/dhcp.h>
#include <dhcpagent_util.h>
#include <dhcpagent_ipc.h>

#include <arpa/inet.h>
#include <net/route.h>
#include <libipadm.h>
#include <libzonecfg.h>
#include <libinetutil.h>
#include <sys/lx_brand.h>

#include "run_command.h"

static void lxi_err(char *msg, ...) __NORETURN;
static void lxi_err(char *msg, ...);

#define	IPMGMTD_PATH	"/lib/inet/ipmgmtd"
#define	IN_NDPD_PATH	"/usr/lib/inet/in.ndpd"

#define	PREFIX_LOG_WARN	"lx_init warn: "
#define	PREFIX_LOG_ERR	"lx_init err: "

#define	RTMBUFSZ	(sizeof (struct rt_msghdr) + \
		(3 * sizeof (struct sockaddr_in)))

ipadm_handle_t iph;

static void
lxi_err(char *msg, ...)
{
	char buf[1024];
	int len;
	va_list ap;

	va_start(ap, msg);
	/*LINTED*/
	len = vsnprintf(buf, sizeof (buf), msg, ap);
	va_end(ap);

	(void) write(1, PREFIX_LOG_ERR, strlen(PREFIX_LOG_ERR));
	(void) write(1, buf, len);
	(void) write(1, "\n", 1);

	/*
	 * Since a non-zero exit will cause the zone to reboot, a pause here
	 * will prevent a mis-configured zone from spinning in a reboot loop.
	 */
	(void) pause();
	exit(1);
	/*NOTREACHED*/
}

static void
lxi_warn(char *msg, ...)
{
	char buf[1024];
	int len;
	va_list ap;

	va_start(ap, msg);
	/*LINTED*/
	len = vsnprintf(buf, sizeof (buf), msg, ap);
	va_end(ap);

	(void) write(1, PREFIX_LOG_WARN, strlen(PREFIX_LOG_WARN));
	(void) write(1, buf, len);
	(void) write(1, "\n", 1);
}

static void
lxi_log_open()
{
	int fd = open("/dev/console", O_WRONLY);

	if (fd < 0) {
		/* hard to log at this point... */
		exit(1);
	} else if (fd != 1) {
		/*
		 * Use stdout as the log fd.  Init should start with no files
		 * open, so we should be required to perform this relocation
		 * every time.
		 */
		if (dup2(fd, 1) != 1) {
			exit(1);
		}
	}
}

static void
lxi_log_close()
{
	(void) close(0);
	(void) close(1);
}

static zone_dochandle_t
lxi_config_open()
{
	zoneid_t zoneid;
	char zonename[ZONENAME_MAX];
	zone_dochandle_t handle;
	zone_iptype_t iptype;
	int res;

	zoneid = getzoneid();
	if (getzonenamebyid(zoneid, zonename, sizeof (zonename)) < 0) {
		lxi_err("could not determine zone name");
	}

	if ((handle = zonecfg_init_handle()) == NULL)
		lxi_err("internal libzonecfg.so.1 error", 0);

	if ((res = zonecfg_get_handle(zonename, handle)) != Z_OK) {
		zonecfg_fini_handle(handle);
		lxi_err("could not locate zone config %d", res);
	}

	/*
	 * Only exclusive stack is supported.
	 */
	if (zonecfg_get_iptype(handle, &iptype) != Z_OK ||
	    iptype != ZS_EXCLUSIVE) {
		zonecfg_fini_handle(handle);
		lxi_err("lx zones do not support shared IP stacks");
	}

	return (handle);

}

#if 0 /* XXX KEBE SAYS NOT YET */
static int
zone_find_attr(struct zone_res_attrtab *attrs, const char *name,
    const char **result)
{
	while (attrs != NULL) {
		if (strncmp(attrs->zone_res_attr_name, name,
		    MAXNAMELEN) == 0) {
			*result = attrs->zone_res_attr_value;
			return (0);
		}
		attrs = attrs->zone_res_attr_next;
	}
	return (-1);
}
#endif /* XXX KEBE SAYS NOT YET */

static void
lxi_svc_start(char *name, char *path, char *fmri)
{
	pid_t pid;
	int status;
	char *argv[] = {
		NULL,
		NULL
	};
	char *envp[] = {
		NULL,
		NULL
	};
	argv[0] = name;
	envp[0] = fmri;

	pid = fork();
	if (pid == -1) {
		lxi_err("fork() failed: %s", strerror(errno));
	}

	if (pid == 0) {
		/* child */
		const char *zroot = zone_get_nroot();
		char cmd[MAXPATHLEN];

		/*
		 * Construct the full path to the binary, including the native
		 * system root (e.g. "/native") if in use for this zone:
		 */
		(void) snprintf(cmd, sizeof (cmd), "%s%s", zroot != NULL ?
		    zroot : "", path);

		(void) execve(cmd, argv, envp);

		lxi_err("execve(%s) failed: %s", cmd, strerror(errno));
		/* NOTREACHED */
	}

	/* parent */
	while (wait(&status) != pid)
		;

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != 0) {
			lxi_err("%s[%d] exited: %d", name,
			    (int)pid, WEXITSTATUS(status));
		}
	} else if (WIFSIGNALED(status)) {
		lxi_err("%s[%d] died on signal: %d", name,
		    (int)pid, WTERMSIG(status));
	} else {
		lxi_err("%s[%d] failed in unknown way", name,
		    (int)pid);
	}
}

void
lxi_net_ipmgmtd_start()
{
	lxi_svc_start("ipmgmtd", IPMGMTD_PATH,
	    "SMF_FMRI=svc:/network/ip-interface-management:default");
}

void
lxi_net_ndpd_start()
{
	lxi_svc_start("in.ndpd", IN_NDPD_PATH,
	    "SMF_FMRI=svc:/network/routing/ndp:default");
}


static void
lxi_net_ipadm_open()
{
	ipadm_status_t status;

	if ((status = ipadm_open(&iph, IPH_LEGACY)) != IPADM_SUCCESS) {
		lxi_err("Error opening ipadm handle: %s",
		    ipadm_status2str(status));
	}
}

static void
lxi_net_ipadm_close()
{
	ipadm_close(iph);
}

void
lxi_net_plumb(const char *iface)
{
	ipadm_status_t status;
	char ifbuf[LIFNAMSIZ];

	/* ipadm_create_if stomps on ifbuf, so create a copy: */
	(void) strncpy(ifbuf, iface, sizeof (ifbuf));

	if ((status = ipadm_create_if(iph, ifbuf, AF_INET, IPADM_OPT_ACTIVE))
	    != IPADM_SUCCESS) {
		lxi_err("ipadm_create_if error %d: %s/v4: %s",
		    status, iface, ipadm_status2str(status));
	}

	if ((status = ipadm_create_if(iph, ifbuf, AF_INET6, IPADM_OPT_ACTIVE))
	    != IPADM_SUCCESS) {
		lxi_err("ipadm_create_if error %d: %s/v6: %s",
		    status, iface, ipadm_status2str(status));
	}
}

static int
lxi_getif(int af, char *iface, int len, boolean_t first_ipv4_configured)
{
	struct lifreq lifr;
	int s = socket(af, SOCK_DGRAM, 0);
	if (s < 0) {
		lxi_warn("socket error %d: bringing up %s: %s",
		    errno, iface, strerror(errno));
		return (-1);
	}

	/*
	 * We need a new logical interface for every IP address we add, except
	 * for the very first IPv4 address.
	 */
	if (af == AF_INET6 || first_ipv4_configured) {
		(void) strncpy(lifr.lifr_name, iface, sizeof (lifr.lifr_name));
		(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
		if (ioctl(s, SIOCLIFADDIF, (caddr_t)&lifr) < 0) {
			if (close(s) != 0) {
				lxi_warn("failed to close socket: %s\n",
				    strerror(errno));
			}
			return (-1);
		}
		(void) strncpy(iface, lifr.lifr_name, len);
	}

	if (close(s) != 0) {
		lxi_warn("failed to close socket: %s\n",
		    strerror(errno));
	}
	return (0);
}

static int
lxi_iface_ip(const char *origiface, const char *addr,
    boolean_t *first_ipv4_configured)
{
	static int addrnum = 0;
	ipadm_status_t status;
	ipadm_addrobj_t ipaddr = NULL;
	char iface[LIFNAMSIZ];
	char aobjname[IPADM_AOBJSIZ];
	int af, err = 0;

	(void) strncpy(iface, origiface, sizeof (iface));

	af = strstr(addr, ":") == NULL ? AF_INET : AF_INET6;
	if (lxi_getif(af, iface, sizeof (iface), *first_ipv4_configured) != 0) {
		lxi_warn("failed to create new logical interface "
		    "on %s: %s", origiface, strerror(errno));
		return (-1);
	}

	(void) snprintf(aobjname, IPADM_AOBJSIZ, "%s/addr%d", iface,
	    addrnum++);

	if ((status = ipadm_create_addrobj(IPADM_ADDR_STATIC, aobjname,
	    &ipaddr)) != IPADM_SUCCESS) {
		lxi_warn("ipadm_create_addrobj error %d: addr %s, "
		    "interface %s: %s\n", status, addr, iface,
		    ipadm_status2str(status));
		return (-2);
	}

	if ((status = ipadm_set_addr(ipaddr, addr, AF_UNSPEC))
	    != IPADM_SUCCESS) {
		lxi_warn("ipadm_set_addr error %d: addr %s"
		    ", interface %s: %s\n", status, addr,
		    iface, ipadm_status2str(status));
		err = -3;
		goto done;
	}

	if ((status = ipadm_create_addr(iph, ipaddr,
	    IPADM_OPT_ACTIVE | IPADM_OPT_UP)) != IPADM_SUCCESS) {
		lxi_warn("ipadm_create_addr error for %s: %s\n", iface,
		    ipadm_status2str(status));
		err = -4;
		goto done;
	}

	if (af == AF_INET) {
		*first_ipv4_configured = B_TRUE;
	}

done:
	ipadm_destroy_addrobj(ipaddr);
	return (err);
}

#if 0 /* XXX KEBE SAYS NOT YET */
static int
lxi_iface_dhcp(const char *origiface, boolean_t *first_ipv4_configured)
{
	dhcp_ipc_request_t *dhcpreq = NULL;
	dhcp_ipc_reply_t *dhcpreply = NULL;
	int err = 0, timeout = 5;
	char iface[LIFNAMSIZ];

	(void) strncpy(iface, origiface, sizeof (iface));

	if (lxi_getif(AF_INET, iface, sizeof (iface), *first_ipv4_configured)
	    != 0) {
		lxi_warn("failed to create new logical interface "
		    "on %s: %s", origiface, strerror(errno));
		return (-1);
	}

	if (dhcp_start_agent(timeout) != 0) {
		lxi_err("Failed to start dhcpagent\n");
		/* NOTREACHED */
	}

	dhcpreq = dhcp_ipc_alloc_request(DHCP_START, iface,
	    NULL, 0, DHCP_TYPE_NONE);
	if (dhcpreq == NULL) {
		lxi_warn("Unable to allocate memory "
		    "to start DHCP on %s\n", iface);
		return (-1);
	}

	err = dhcp_ipc_make_request(dhcpreq, &dhcpreply, timeout);
	if (err != 0) {
		free(dhcpreq);
		lxi_warn("Failed to start DHCP on %s: %s\n", iface,
		    dhcp_ipc_strerror(err));
		return (-1);
	}
	err = dhcpreply->return_code;
	if (err != 0) {
		lxi_warn("Failed to start DHCP on %s: %s\n", iface,
		    dhcp_ipc_strerror(err));
		goto done;
	}

	*first_ipv4_configured = B_TRUE;

done:
	free(dhcpreq);
	free(dhcpreply);
	return (err);
}
#endif /* XXX KEBE SAYS NOT YET */

/*
 * Initialize an IPv6 link-local address on a given interface
 */
static int
lxi_iface_ipv6_link_local(const char *iface)
{
	struct lifreq lifr;
	int s;

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s == -1) {
		lxi_warn("socket error %d: bringing up %s: %s",
		    errno, iface, strerror(errno));
	}

	(void) strncpy(lifr.lifr_name, iface, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		lxi_warn("SIOCGLIFFLAGS error %d: bringing up %s: %s",
		    errno, iface, strerror(errno));
		return (-1);
	}

	lifr.lifr_flags |= IFF_UP;
	if (ioctl(s, SIOCSLIFFLAGS, (caddr_t)&lifr) < 0) {
		lxi_warn("SIOCSLIFFLAGS error %d: bringing up %s: %s",
		    errno, iface, strerror(errno));
		return (-1);
	}

	(void) close(s);
	return (0);
}

static int
lxi_iface_gateway(const char *iface, const char *dst, int dstpfx,
    const char *gwaddr)
{
	int idx, len, sockfd;
	/* For lint-happy alignment, use a uint32_t array... */
	uint32_t rtbuf[RTMBUFSZ / sizeof (uint32_t)];
	struct rt_msghdr *rtm = (struct rt_msghdr *)rtbuf;
	struct sockaddr_in *dst_sin = (struct sockaddr_in *)(rtm + 1);
	struct sockaddr_in *gw_sin = (struct sockaddr_in *)(dst_sin + 1);
	struct sockaddr_in *netmask_sin = (struct sockaddr_in *)(gw_sin + 1);

	(void) bzero(rtm, RTMBUFSZ);
	rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	rtm->rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY;
	rtm->rtm_msglen = sizeof (rtbuf);
	rtm->rtm_pid = getpid();
	rtm->rtm_type = RTM_ADD;
	rtm->rtm_version = RTM_VERSION;


	/*
	 * The destination and netmask components have already been zeroed,
	 * which represents the default gateway.  If we were passed a more
	 * specific destination network, use that instead.
	 */
	dst_sin->sin_family = AF_INET;
	netmask_sin->sin_family = AF_INET;
	if (dst != NULL) {
		struct sockaddr *mask = (struct sockaddr *)netmask_sin;

		if ((inet_pton(AF_INET, dst, &(dst_sin->sin_addr))) != 1 ||
		    plen2mask(dstpfx, AF_INET, mask) != 0) {
			lxi_warn("bad destination network %s/%d: %s", dst,
			    dstpfx, strerror(errno));
			return (-1);
		}
	}

	if ((inet_pton(AF_INET, gwaddr, &(gw_sin->sin_addr))) != 1) {
		lxi_warn("bad gateway %s: %s", gwaddr, strerror(errno));
		return (-1);
	}

	if (iface != NULL) {
		if ((idx = if_nametoindex(iface)) == 0) {
			lxi_warn("unable to get interface index for %s: %s\n",
			    iface, strerror(errno));
			return (-1);
		}
		rtm->rtm_index = idx;
	}

	if ((sockfd = socket(PF_ROUTE, SOCK_RAW, AF_INET)) < 0) {
		lxi_warn("socket(PF_ROUTE): %s\n", strerror(errno));
		return (-1);
	}

	if ((len = write(sockfd, rtbuf, rtm->rtm_msglen)) < 0) {
		lxi_warn("could not write rtmsg: %s", strerror(errno));
		(void) close(sockfd);
		return (-1);
	} else if (len < rtm->rtm_msglen) {
		lxi_warn("write() rtmsg incomplete");
		(void) close(sockfd);
		return (-1);
	}

	(void) close(sockfd);
	return (0);
}

static void
lxi_net_loopback()
{
	const char *iface = "lo0";
	boolean_t first_ipv4_configured = B_FALSE;

	lxi_net_plumb(iface);
	(void) lxi_iface_ip(iface, "127.0.0.1/8", &first_ipv4_configured);
	(void) lxi_iface_ipv6_link_local(iface);
}



#if 0 /* XXX KEBE SAYS NOT YET */
/*
 * This function is used when the "ips" property doesn't exist in a zone's
 * configuration. It may be an older configuration, so we should search for
 * "ip" and "netmask" and convert them into the new format.
 */
static int
lxi_get_old_ip(struct zone_res_attrtab *attrs, const char **ipaddrs,
    char *cidraddr, int len)
{

	const char *netmask;
	int prefixlen;
	struct sockaddr_in mask_sin;

	lxi_warn("Could not find \"ips\" property for zone. Looking "
	    "for older \"ip\" and \"netmask\" properties, instead.");

	if (zone_find_attr(attrs, "ip", ipaddrs) != 0) {
		return (-1);
	}

	if (strcmp(*ipaddrs, "dhcp") == 0) {
		return (0);
	}

	if (zone_find_attr(attrs, "netmask", &netmask) != 0) {
		lxi_err("could not find netmask for interface");
		/* NOTREACHED */
	}

	/* Convert the netmask to a number */
	mask_sin.sin_family = AF_INET;
	if (inet_pton(AF_INET, netmask, &mask_sin.sin_addr) != 1) {
		lxi_err("invalid netmask address: %s\n",
		    strerror(errno));
		/* NOTREACHED */
	}
	prefixlen = mask2plen((struct sockaddr *)&mask_sin);

	/*
	 * Write out the IP address in the new format and use
	 * that instead
	 */
	(void) snprintf(cidraddr, len, "%s/%d", *ipaddrs, prefixlen);

	*ipaddrs = cidraddr;
	return (0);
}
#endif /* XXX KEBE SAYS NOT YET */

static void
lxi_net_setup(zone_dochandle_t handle)
{
	struct zone_nwiftab lookup;
	boolean_t do_addrconf = B_FALSE;

	if (zonecfg_setnwifent(handle) != Z_OK)
		return;
	while (zonecfg_getnwifent(handle, &lookup) == Z_OK) {
		const char *iface = lookup.zone_nwif_physical;
#if 0	/* XXX KEBE SAYS NOT YET */
		struct zone_res_attrtab *attrs = lookup.zone_nwif_attrp;
		const char *ipaddrs, *primary, *gateway;
		char ipaddrs_copy[MAXNAMELEN], cidraddr[BUFSIZ],
		    *ipaddr, *tmp, *lasts;
		boolean_t first_ipv4_configured = B_FALSE;
		boolean_t *ficp = &first_ipv4_configured;
#endif	/* XXX KEBE */

		lxi_net_plumb(iface);

		/* XXX KEBE SAYS this bit was shuffled around. */
		if (lxi_iface_ipv6_link_local(iface) != 0) {
			lxi_warn("unable to bring up link-local address on "
			    "interface %s", iface);
		} else {
			/* XXX KEBE SAYS this bit is new. */
			do_addrconf = B_TRUE;
		}

#if 0	/* XXX KEBE SAYS NOT YET */
		if (zone_find_attr(attrs, "ips", &ipaddrs) != 0 &&
		    lxi_get_old_ip(attrs, &ipaddrs, cidraddr, BUFSIZ) != 0) {
			lxi_warn("Could not find a valid network configuration "
			    "for the %s interface", iface);
			continue;
		}

		/*
		 * If we're going to be doing DHCP, we have to do it first since
		 * dhcpagent doesn't like to operate on non-zero logical
		 * interfaces.
		 */
		if (strstr(ipaddrs, "dhcp") != NULL &&
		    lxi_iface_dhcp(iface, ficp) != 0) {
			lxi_warn("Failed to start DHCP on %s\n", iface);
		}

		/*
		 * Copy the ipaddrs string, since strtok_r will write NUL
		 * characters into it.
		 */
		(void) strlcpy(ipaddrs_copy, ipaddrs, MAXNAMELEN);
		tmp = ipaddrs_copy;

		/*
		 * Iterate over each IP and then set it up on the interface.
		 */
		while ((ipaddr = strtok_r(tmp, ",", &lasts)) != NULL) {
			tmp = NULL;
			if (strcmp(ipaddr, "addrconf") == 0) {
				do_addrconf = B_TRUE;
			} else if (strcmp(ipaddr, "dhcp") == 0) {
				continue;
			} else if (lxi_iface_ip(iface, ipaddr, ficp) < 0) {
				lxi_warn("Unable to add new IP address (%s) "
				    "to interface %s", ipaddr, iface);
			}
		}

		if (zone_find_attr(attrs, "primary", &primary) == 0 &&
		    strncmp(primary, "true", MAXNAMELEN) == 0 &&
		    zone_find_attr(attrs, "gateway", &gateway) == 0) {
			lxi_iface_gateway(iface, NULL, 0, gateway);
		}
#endif /* XXX KEBE */
	}

	if (do_addrconf) {
		lxi_net_ndpd_start();
	}

	(void) zonecfg_endnwifent(handle);
}

static void
lxi_net_static_route(const char *line)
{
	/*
	 * Each static route line is a string of the form:
	 *
	 *	"10.77.77.2|10.1.1.0/24|false"
	 *
	 * i.e. gateway address, destination network, and whether this is
	 * a "link local" route or a next hop route.
	 */
	custr_t *cu = NULL;
	char *gw = NULL, *dst = NULL;
	int pfx = -1;
	int i;

	if (custr_alloc(&cu) != 0) {
		lxi_err("custr_alloc failure");
	}

	for (i = 0; line[i] != '\0'; i++) {
		if (gw == NULL) {
			if (line[i] == '|') {
				if ((gw = strdup(custr_cstr(cu))) == NULL) {
					lxi_err("strdup failure");
				}
				custr_reset(cu);
			} else {
				if (custr_appendc(cu, line[i]) != 0) {
					lxi_err("custr_appendc failure");
				}
			}
			continue;
		}

		if (dst == NULL) {
			if (line[i] == '/') {
				if ((dst = strdup(custr_cstr(cu))) == NULL) {
					lxi_err("strdup failure");
				}
				custr_reset(cu);
			} else {
				if (custr_appendc(cu, line[i]) != 0) {
					lxi_err("custr_appendc failure");
				}
			}
			continue;
		}

		if (pfx == -1) {
			if (line[i] == '|') {
				pfx = atoi(custr_cstr(cu));
				custr_reset(cu);
			} else {
				if (custr_appendc(cu, line[i]) != 0) {
					lxi_err("custr_appendc failure");
				}
			}
			continue;
		}

		if (custr_appendc(cu, line[i]) != 0) {
			lxi_err("custr_appendc failure");
		}
	}

	/*
	 * We currently only support "next hop" routes, so ensure that
	 * "linklocal" is false:
	 */
	if (strcmp(custr_cstr(cu), "false") != 0) {
		lxi_warn("invalid static route: %s", line);
	}

	if (lxi_iface_gateway(NULL, dst, pfx, gw) != 0) {
		lxi_err("failed to add route: %s/%d -> %s", dst, pfx, gw);
	}

	custr_free(cu);
	free(gw);
	free(dst);
}

static void
lxi_net_static_routes(void)
{
	const char *cmd = "/native/usr/lib/brand/lx/routeinfo";
	char *const argv[] = { "routeinfo", NULL };
	char *const envp[] = { NULL };
	int code;
	struct stat st;
	char errbuf[512];

	if (stat(cmd, &st) != 0 || !S_ISREG(st.st_mode)) {
		/*
		 * This binary is (potentially) shipped from another
		 * consolidation.  If it does not exist, then the platform does
		 * not currently support static routes for LX-branded zones.
		 */
		return;
	}

	/*
	 * Run the command, firing the callback for each line that it
	 * outputs.  When this function returns, static route processing
	 * is complete.
	 */
	if (run_command(cmd, argv, envp, errbuf, sizeof (errbuf),
	    lxi_net_static_route, &code) != 0 || code != 0) {
		lxi_err("failed to run \"%s\": %s", cmd, errbuf);
	}
}

static void
lxi_config_close(zone_dochandle_t handle)
{
	zonecfg_fini_handle(handle);
}

static void
lxi_init_exec(char **argv)
{
	const char *cmd = "/sbin/init";
	char *const envp[] = { "container=zone", NULL };
	int e;

	argv[0] = "init";

	/*
	 * systemd uses the 'container' env var to determine it is running
	 * inside a container. It only supports a few well-known types and
	 * treats anything else as 'other' but this is enough to make it
	 * behave better inside a zone. See 'detect_container' in systemd.
	 */
	(void) execve(cmd, argv, envp);
	e = errno;

	/*
	 * Because stdout was closed prior to exec, it must be opened again in
	 * the face of failure to log the error.
	 */
	lxi_log_open();
	lxi_err("execve(%s) failed: %s", cmd, strerror(e));
}

/*ARGSUSED*/
int
main(int argc, char *argv[])
{
	zone_dochandle_t handle;

	lxi_log_open();

	lxi_net_ipmgmtd_start();
	lxi_net_ipadm_open();

	handle = lxi_config_open();
	lxi_net_loopback();
	lxi_net_setup(handle);
	lxi_config_close(handle);

	lxi_net_static_routes();

	lxi_net_ipadm_close();

	lxi_log_close();

	lxi_init_exec(argv);

	/* NOTREACHED */
	return (0);
}
