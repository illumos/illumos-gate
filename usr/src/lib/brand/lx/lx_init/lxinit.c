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
 * - Starting ipmgmtd chrooted into /native
 * - Configuring network interfaces
 * - Adding a default route
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
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

#include <arpa/inet.h>
#include <net/route.h>
#include <libipadm.h>
#include <libzonecfg.h>
#include <libinetutil.h>
#include <sys/lx_brand.h>

static void lxi_err(char *msg, ...) __NORETURN;
static void lxi_err(char *msg, ...);

#define	CHROOT_NAME	"lx_init-chroot"
#define	CHROOT_PREFIX	"/native"

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
	pause();
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

void
lxi_net_ipmgmtd_start()
{
	pid_t pid;
	int status;
	char *cmd[] = {
		"/lib/inet/ipmgmtd",
		"ipmgmtd",
		NULL
	};
	char *env[] = {
		/* ipmgmtd thinks SMF is awesome */
		"SMF_FMRI=svc:/network/ip-interface-management:default",
		NULL
	};

	pid = fork();
	if (pid == -1) {
		lxi_err("fork() failed: %s", strerror(errno));
	}

	if (pid == 0) {
		/* child */
		execve(cmd[0], cmd + 1, env);

		lxi_err("execve(%s) failed: %s", cmd[0],
		    strerror(errno));
		/* NOTREACHED */
	}

	/* parent */
	while (wait(&status) != pid) {
		/* EMPTY */;
	}

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != 0) {
			lxi_err("ipmgmtd[%d] exited: %d",
			    (int)pid, WEXITSTATUS(status));
		}
	} else if (WIFSIGNALED(status)) {
		lxi_err("ipmgmtd[%d] died on signal: %d",
		    (int)pid, WTERMSIG(status));
	} else {
		lxi_err("ipmgmtd[%d] failed in unknown way",
		    (int)pid);
	}
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
lxi_iface_ipv4(const char *iface, const char *addr, const char *netmask)
{
	ipadm_status_t status;
	ipadm_addrobj_t ipaddr;
	char cidraddr[BUFSIZ];
	int prefixlen;
	struct sockaddr_in mask_sin;

	mask_sin.sin_family = AF_INET;
	if (inet_pton(AF_INET, netmask, &mask_sin.sin_addr) != 1) {
		lxi_warn("invalid netmask address: %s\n", strerror(errno));
		return (-1);
	}

	prefixlen = mask2plen((struct sockaddr *)&mask_sin);
	(void) snprintf(cidraddr, sizeof (cidraddr), "%s/%d",
	    addr, prefixlen);

	if ((status = ipadm_create_addrobj(IPADM_ADDR_STATIC, iface, &ipaddr))
	    != IPADM_SUCCESS) {
		lxi_warn("ipadm_create_addrobj error %d: addr %s (%s), "
		    "interface %s: %s\n", status, addr, cidraddr, iface,
		    ipadm_status2str(status));
		return (-2);
	}

	if ((status = ipadm_set_addr(ipaddr, cidraddr, AF_INET))
	    != IPADM_SUCCESS) {
		lxi_warn("ipadm_set_addr error %d: addr %s (%s)"
		    ", interface %s: %s\n", status, addr, cidraddr,
		    iface, ipadm_status2str(status));
		return (-3);
	}

	if ((status = ipadm_create_addr(iph, ipaddr,
	    IPADM_OPT_ACTIVE | IPADM_OPT_UP)) != IPADM_SUCCESS) {
		lxi_warn("ipadm_create_addr error for %s: %s\n", iface,
		    ipadm_status2str(status));
		ipadm_destroy_addrobj(ipaddr);
		return (-4);
	}

	ipadm_destroy_addrobj(ipaddr);
	return (0);
}

static int
lxi_iface_ipv6(const char *iface)
{
	struct lifreq lifr;
	int s;

	/* XXX: Just perform link-local init for now */
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
lxi_iface_gateway(const char *iface, const char *gwaddr)
{
	int idx, len, sockfd;
	char rtbuf[RTMBUFSZ];
	struct rt_msghdr *rtm = (struct rt_msghdr *)rtbuf;
	struct sockaddr_in *dst_sin = (struct sockaddr_in *)
	    (rtbuf + sizeof (struct rt_msghdr));
	struct sockaddr_in *gw_sin = (struct sockaddr_in *)(dst_sin + 1);
	struct sockaddr_in *netmask_sin = (struct sockaddr_in *)(gw_sin + 1);

	(void) bzero(rtm, RTMBUFSZ);
	rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	rtm->rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY;
	rtm->rtm_msglen = sizeof (rtbuf);
	rtm->rtm_pid = getpid();
	rtm->rtm_type = RTM_ADD;
	rtm->rtm_version = RTM_VERSION;

	/* The destination and netmask components have already been zeroed */
	dst_sin->sin_family = AF_INET;
	netmask_sin->sin_family = AF_INET;

	dst_sin->sin_family = AF_INET;
	if ((inet_pton(AF_INET, gwaddr, &(gw_sin->sin_addr))) != 1) {
		lxi_warn("bad gateway %s: %s", gwaddr, strerror(errno));
		return (-1);
	}

	if ((idx = if_nametoindex(iface)) == 0) {
		lxi_warn("unable to get interface index for %s: %s\n",
		    iface, strerror(errno));
		return (-1);
	}
	rtm->rtm_index = idx;

	if ((sockfd = socket(PF_ROUTE, SOCK_RAW, AF_INET)) < 0) {
		lxi_warn("socket(PF_ROUTE): %s\n", strerror(errno));
		return (-1);
	}

	if ((len = write(sockfd, rtbuf, rtm->rtm_msglen)) < 0) {
		lxi_warn("could not write rtmsg: %s", strerror(errno));
		close(sockfd);
		return (-1);
	} else if (len < rtm->rtm_msglen) {
		lxi_warn("write() rtmsg incomplete");
		close(sockfd);
		return (-1);
	}

	close(sockfd);
	return (0);
}

static void
lxi_net_loopback()
{
	const char *iface = "lo0";

	lxi_net_plumb(iface);
	(void) lxi_iface_ipv4(iface, "127.0.0.1", "255.0.0.0");
	(void) lxi_iface_ipv6(iface);
}

static void
lxi_net_setup(zone_dochandle_t handle)
{
	struct zone_nwiftab lookup;

	if (zonecfg_setnwifent(handle) != Z_OK)
		return;
	while (zonecfg_getnwifent(handle, &lookup) == Z_OK) {
		const char *iface = lookup.zone_nwif_physical;
		struct zone_res_attrtab *attrs = lookup.zone_nwif_attrp;
		const char *ipaddr, *netmask, *primary, *gateway;

		lxi_net_plumb(iface);
		if (zone_find_attr(attrs, "ip", &ipaddr) != 0) {
			continue;
		}
		if (zone_find_attr(attrs, "netmask", &netmask) != 0) {
			lxi_err("could not find netmask for interface");
			/* NOTREACHED */
		}
		if (lxi_iface_ipv4(iface, ipaddr, netmask) != 0 ||
		    lxi_iface_ipv6(iface) != 0) {
			continue;
		}
		if (zone_find_attr(attrs, "primary", &primary) == 0 &&
		    strncmp(primary, "true", MAXNAMELEN) == 0 &&
		    zone_find_attr(attrs, "gateway", &gateway) == 0) {
			lxi_iface_gateway(iface, gateway);
		}
	}
	(void) zonecfg_endnwifent(handle);
}

static void
lxi_config_close(zone_dochandle_t handle)
{
	zonecfg_fini_handle(handle);
}

static void
lxi_init_exec()
{
	char *cmd[] = {"/sbin/init", "init", NULL};
	char *env[] = {"container=zone", NULL};

	/*
	 * systemd uses the 'container' env var to determine it is running
	 * inside a container. It only supports a few well-known types and
	 * treats anything else as 'other' but this is enough to make it
	 * behave better inside a zone. See 'detect_container' in systemd.
	 */
	execve(cmd[0], cmd + 1, env);

	/*
	 * Because stdout was closed prior to exec, it must be opened again in
	 * the face of failure to log the error.
	 */
	lxi_log_open();
	lxi_err("exec(%s) failed: %s", cmd[0], strerror(errno));
}

int
main(int argc, char *argv[])
{
	zone_dochandle_t handle;
	pid_t pid;
	int status = 0;

	if (strcmp(argv[0], CHROOT_NAME) == 0) {
		/* we've been forked/chrooted, run setup */
		lxi_net_ipmgmtd_start();
		lxi_net_ipadm_open();

		handle = lxi_config_open();
		lxi_net_loopback();
		lxi_net_setup(handle);
		lxi_config_close(handle);

		lxi_net_ipadm_close();
		/* failures will bail before now */
		exit(0);
	}

	lxi_log_open();

	/* The config stuff needs to be chrooted to /native */
	pid = fork();
	if (pid < 0) {
		lxi_err("fork() failed: %s"), strerror(errno);
	} else if (pid == 0) {
		const char *execname;
		char *args[] = {
			CHROOT_NAME, NULL
		};

		if ((execname = getexecname()) == NULL) {
			lxi_err("getexecname() failed: %s",
			    strerror(errno));
		}
		execname += strlen(CHROOT_PREFIX);

		if (chroot(CHROOT_PREFIX) != 0) {
			lxi_err("chroot() failed: %s",
			    strerror(errno));
		}
		execv(execname, args);
		exit(1);
	} else {
		/* parent */
		while (wait(&status) != pid) {
			/* EMPTY */;
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			lxi_err("configuration error %d", status);
		}
	}

	lxi_log_close();
	lxi_init_exec();
	/* NOTREACHED */
	return (0);
}
