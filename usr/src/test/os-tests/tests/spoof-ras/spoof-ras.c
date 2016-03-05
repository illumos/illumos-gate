/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc. All rights reserved.
 */

#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in_systm.h> /* legacy network types needed by ip_icmp.h */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <priv.h>

/*
 * This program is meant to test the behaviour of processing incoming Router
 * Advertisements when IP spoofing protection (ip-nospoof) is enabled. When
 * run, it creates an etherstub on which it places two VNICs: a source VNIC,
 * and a destination VNIC with protection enabled. It then sends out spoofed
 * Router Advertisements with varying incorrect values.
 *
 * IMPORTANT: These tests expect that there is no other IPv6 traffic on the
 * machine that would be delivered to a VNIC with spoofing protection enabled,
 * since this would trip the DTrace probes installed by this suite of tests.
 * Care should therefore be taken to not run it as a part of any series of
 * tests which may be executed in such an environment, as it could lead to
 * spurious failures.
 */

#define	DLADM(args...) spoof_run_proc("/usr/sbin/dladm", \
	(char *[]) { "dladm", args, NULL })
#define	IFCONFIG(args...) spoof_run_proc("/usr/sbin/ifconfig", \
	(char *[]) { "ifconfig", args, NULL })

typedef	struct	sockaddr_in6	sin6_t;
typedef	int	(spoof_test_f)(int, struct lif_nd_req *, sin6_t *);

/*
 * Get the link-layer address of the given interface by querying
 * the neighbour cache.
 */
static int
spoof_get_lla(int s, const char *iface, struct lifreq *addrp,
    struct lifreq *llap)
{
	if (strstr(iface, ":")) {
		warnx("Specified interface should be the zeroth "
		    "logical interface on the physical device.");
	}

	bzero(addrp, sizeof (*addrp));
	bzero(llap, sizeof (*llap));

	(void) strlcpy(addrp->lifr_name, iface, LIFNAMSIZ);
	if (ioctl(s, SIOCGLIFADDR, addrp) < 0) {
		warn("Unable to get link-local address");
		return (-1);
	}

	(void) strlcpy(llap->lifr_name, iface, LIFNAMSIZ);
	bcopy(&addrp->lifr_addr, &llap->lifr_nd.lnr_addr,
	    sizeof (struct sockaddr_storage));

	if (ioctl(s, SIOCLIFGETND, llap) < 0) {
		warn("Failed to get link-layer address");
		return (-1);
	}

	return (0);
}

static void
spoof_prepare_lla(struct nd_opt_lla *llap, struct lif_nd_req *nce,
    struct iovec *iov)
{
	uint_t optlen;

	bzero(llap, sizeof (*llap));
	llap->nd_opt_lla_type = ND_OPT_SOURCE_LINKADDR;
	optlen = ((sizeof (struct nd_opt_hdr) +
	    nce->lnr_hdw_len + 7) / 8) * 8;
	llap->nd_opt_lla_len = optlen / 8;
	bcopy(&nce->lnr_hdw_addr,
	    &llap->nd_opt_lla_hdw_addr, nce->lnr_hdw_len);

	iov->iov_base = (caddr_t)llap;
	iov->iov_len = optlen;
}

static void
spoof_prepare_pi(const char *prefix, int prefix_len,
    struct nd_opt_prefix_info *pip, struct iovec *iov)
{
	bzero(pip, sizeof (*pip));

	pip->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	pip->nd_opt_pi_len = 4;
	pip->nd_opt_pi_prefix_len = prefix_len;
	pip->nd_opt_pi_flags_reserved =
	    ND_OPT_PI_FLAG_AUTO | ND_OPT_PI_FLAG_ONLINK;
	pip->nd_opt_pi_valid_time = 86400;
	pip->nd_opt_pi_preferred_time = 86400;
	if (inet_pton(AF_INET6, prefix, &pip->nd_opt_pi_prefix) == 0) {
		errx(EXIT_FAILURE, "The prefix \"%s\" is "
		    "not a valid input prefix", prefix);
	}

	iov->iov_base = (caddr_t)pip;
	iov->iov_len = sizeof (*pip);
}

static void
spoof_prepare_header(struct nd_router_advert *ichdrp, struct iovec *iov)
{
	bzero(ichdrp, sizeof (*ichdrp));

	ichdrp->nd_ra_type = ND_ROUTER_ADVERT;
	ichdrp->nd_ra_curhoplimit = 0;

	iov->iov_base = (caddr_t)ichdrp;
	iov->iov_len = sizeof (*ichdrp);
}

static int
spoof_set_max_hops(int s)
{
	int ttl = 255;

	if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
	    (char *)&ttl, sizeof (ttl)) < 0) {
		warn("Failed to set IPV6_UNICAST_HOPS socket option");
		return (-1);
	}
	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
	    (char *)&ttl, sizeof (ttl)) < 0) {
		warn("Failed to set IPV6_UNICAST_HOPS socket option");
		return (-1);
	}

	return (0);
}

/*
 * Send bad option lengths in the Link-Layer Source Address option
 */
static int
spoof_bad_lla_optlen_test(int s, struct lif_nd_req *nce, sin6_t *multicast)
{
	struct msghdr msg6;
	struct iovec iovs[3];
	struct nd_router_advert ichdr;
	struct nd_opt_lla lla;
	struct nd_opt_prefix_info pi;
	uint8_t old_lla_len;

	spoof_prepare_header(&ichdr, &iovs[0]);
	spoof_prepare_lla(&lla, nce, &iovs[1]);
	spoof_prepare_pi("fd00::", 64, &pi, &iovs[2]);

	/* Prepare message */
	bzero(&msg6, sizeof (struct msghdr));
	msg6.msg_name = multicast;
	msg6.msg_namelen = sizeof (sin6_t);
	msg6.msg_iov = iovs;
	msg6.msg_iovlen = 3;

	old_lla_len = lla.nd_opt_lla_len;


	/*
	 * Length is now smaller than the option is, so this should
	 * be rejected.
	 */
	lla.nd_opt_lla_len = 0;
	if (sendmsg(s, &msg6, 0) < 0) {
		warn("Failed to send ICMPv6 message");
		return (-1);
	}

	/*
	 * Length is bigger than the option, so the following prefix
	 * will be offset.
	 */
	lla.nd_opt_lla_len = 2;
	if (sendmsg(s, &msg6, 0) < 0) {
		warn("Failed to send ICMPv6 message");
		return (-1);
	}

	/*
	 * Restore the length, but shorten the amount of data to send, so we're
	 * sending truncated packets. (Stop before 0, so that we still send part
	 * of the option.)
	 */
	lla.nd_opt_lla_len = old_lla_len;
	for (iovs[1].iov_len--; iovs[1].iov_len > 0; iovs[1].iov_len--) {
		if (sendmsg(s, &msg6, 0) < 0) {
			warn("Failed to send ICMPv6 message");
			return (-1);
		}
	}

	return (0);
}

/*
 * Send bad option lengths in the Prefix Information option
 */
static int
spoof_bad_pi_optlen_test(int s, struct lif_nd_req *nce, sin6_t *multicast)
{
	struct msghdr msg6;
	struct iovec iovs[3];
	struct nd_router_advert ichdr;
	struct nd_opt_lla lla;
	struct nd_opt_prefix_info pi;
	uint8_t old_pi_len;

	spoof_prepare_header(&ichdr, &iovs[0]);
	spoof_prepare_lla(&lla, nce, &iovs[1]);
	spoof_prepare_pi("fd00::", 64, &pi, &iovs[2]);

	/* Prepare message */
	bzero(&msg6, sizeof (struct msghdr));
	msg6.msg_name = multicast;
	msg6.msg_namelen = sizeof (sin6_t);
	msg6.msg_iov = iovs;
	msg6.msg_iovlen = 3;

	old_pi_len = pi.nd_opt_pi_len;

	/*
	 * Length is now smaller than the option is, so this should
	 * be rejected.
	 */
	pi.nd_opt_pi_len = 0;
	if (sendmsg(s, &msg6, 0) < 0) {
		warn("Failed to send ICMPv6 message");
		return (-1);
	}

	/*
	 * Length is smaller than a PI option should be.
	 */
	pi.nd_opt_pi_len = 3;
	if (sendmsg(s, &msg6, 0) < 0) {
		warn("Failed to send ICMPv6 message");
		return (-1);
	}

	/*
	 * Length is bigger than the option, so the following prefix
	 * will be offset.
	 */
	pi.nd_opt_pi_len = 5;
	if (sendmsg(s, &msg6, 0) < 0) {
		warn("Failed to send ICMPv6 message");
		return (-1);
	}

	/*
	 * Restore the length, but shorten the amount of data to send, so we're
	 * sending truncated packets. (Stop before 0, so that we still send part
	 * of the option.)
	 */
	pi.nd_opt_pi_len = old_pi_len;
	for (iovs[2].iov_len--; iovs[2].iov_len > 0; iovs[2].iov_len--) {
		if (sendmsg(s, &msg6, 0) < 0) {
			warn("Failed to send ICMPv6 message");
			return (-1);
		}
	}

	return (0);
}

/*
 * Advertise a prefix with a prefix length greater than 128.
 */
static int
spoof_bad_plen_test(int s, struct lif_nd_req *nce, sin6_t *multicast)
{
	struct msghdr msg6;
	struct iovec iovs[3];
	struct nd_router_advert ichdr;
	struct nd_opt_lla lla;
	struct nd_opt_prefix_info pi;

	spoof_prepare_header(&ichdr, &iovs[0]);
	spoof_prepare_lla(&lla, nce, &iovs[1]);
	spoof_prepare_pi("fd00::", 130, &pi, &iovs[2]);

	/* Prepare message */
	bzero(&msg6, sizeof (struct msghdr));
	msg6.msg_name = multicast;
	msg6.msg_namelen = sizeof (sin6_t);
	msg6.msg_iov = iovs;
	msg6.msg_iovlen = 3;

	if (sendmsg(s, &msg6, 0) < 0) {
		warn("Failed to send ICMPv6 message");
		return (-1);
	}

	return (0);
}

/*
 * Advertise a link-local prefix, which should be disallowed and ignored.
 */
static int
spoof_link_local_test(int s, struct lif_nd_req *nce, sin6_t *multicast)
{
	struct msghdr msg6;
	struct iovec iovs[3];
	struct nd_router_advert ichdr;
	struct nd_opt_lla lla;
	struct nd_opt_prefix_info pi;

	spoof_prepare_header(&ichdr, &iovs[0]);
	spoof_prepare_lla(&lla, nce, &iovs[1]);
	spoof_prepare_pi("fe80::", 64, &pi, &iovs[2]);

	/* Prepare message */
	bzero(&msg6, sizeof (struct msghdr));
	msg6.msg_name = multicast;
	msg6.msg_namelen = sizeof (sin6_t);
	msg6.msg_iov = iovs;
	msg6.msg_iovlen = 3;

	if (sendmsg(s, &msg6, 0) < 0) {
		warn("Failed to send ICMPv6 message");
		return (-1);
	}

	return (0);
}

static int
spoof_good_test(int s, struct lif_nd_req *nce, sin6_t *multicast)
{
	struct msghdr msg6;
	struct iovec iovs[3];
	struct nd_router_advert ichdr;
	struct nd_opt_lla lla;
	struct nd_opt_prefix_info pi;

	spoof_prepare_header(&ichdr, &iovs[0]);
	spoof_prepare_lla(&lla, nce, &iovs[1]);
	spoof_prepare_pi("fd00::", 64, &pi, &iovs[2]);

	/* Prepare message */
	bzero(&msg6, sizeof (struct msghdr));
	msg6.msg_name = multicast;
	msg6.msg_namelen = sizeof (sin6_t);
	msg6.msg_iov = iovs;
	msg6.msg_iovlen = 3;

	if (sendmsg(s, &msg6, 0) < 0) {
		warn("Failed to send ICMPv6 message");
		return (-1);
	}

	return (0);
}

static spoof_test_f *test_cases[] = {
	spoof_bad_lla_optlen_test,
	spoof_bad_pi_optlen_test,
	spoof_bad_plen_test,
	spoof_link_local_test
};

static int test_cases_count = sizeof (test_cases) / sizeof (spoof_test_f *);

static pid_t
spoof_dtrace_launch(void)
{
	pid_t child_pid = fork();
	if (child_pid == (pid_t)-1) {
		err(EXIT_FAILURE, "Failed to fork to execute dtrace");
	} else if (child_pid == (pid_t)0) {
		(void) execl("/usr/sbin/dtrace", "dtrace", "-q",
		    "-n", "sdt:mac:insert_slaac_ip:generated-addr { exit(10) }",
		    NULL);
		err(EXIT_FAILURE, "Failed to execute dtrace");
	}

	return (child_pid);
}

static pid_t
spoof_dtrace_wait(pid_t dtrace, int *stat)
{
	int retpid;

	/* Give time for probe to fire before checking status */
	(void) sleep(5);

	while ((retpid = waitpid(dtrace, stat, WNOHANG)) == -1) {
		if (errno == EINTR)
			continue;

		err(EXIT_FAILURE, "Failed to wait on child");
	}

	return (retpid);
}

/*
 * Run a function that's going to exec in a child process, and don't return
 * until it exits.
 */
static int
spoof_run_proc(char *path, char *args[])
{
	pid_t child_pid;
	int childstat = 0, status = 0;

	child_pid = fork();
	if (child_pid == (pid_t)-1) {
		err(EXIT_FAILURE, "Unable to fork to execute %s", path);
	} else if (child_pid == (pid_t)0) {
		(void) execv(path, args);
		err(EXIT_FAILURE, "Failed to execute %s", path);
	}

	while (waitpid(child_pid, &childstat, 0) == -1) {
		if (errno == EINTR)
			continue;

		warn("Failed to wait on child");
		return (-1);
	}

	status = WEXITSTATUS(childstat);
	if (status != 0) {
		warnx("Child process %s exited with %d", path, status);
		return (-1);
	}

	return (0);
}

static void
spoof_network_teardown(char *testether, char *testvnic0, char *testvnic1)
{
	// Delete dest vnic
	(void) IFCONFIG(testvnic1, "inet6", "unplumb");
	(void) DLADM("delete-vnic", testvnic1);

	// Delete source vnic
	(void) IFCONFIG(testvnic0, "inet6", "unplumb");
	(void) DLADM("delete-vnic", testvnic0);

	// Delete etherstub
	(void) DLADM("delete-etherstub", testether);
}

static int
spoof_network_setup(char *testether, char *testvnic0, char *testvnic1)
{
	// Create etherstub
	if (DLADM("create-etherstub", "-t", testether) != 0) {
		warnx("Failed to create etherstub for test network");
		return (-1);
	}

	// Create source vnic
	if (DLADM("create-vnic", "-t", "-l", testether, testvnic0) != 0) {
		warnx("Failed to create source VNIC for test network");
		return (-1);
	}

	if (IFCONFIG(testvnic0, "inet6", "plumb", "up") != 0) {
		warnx("Failed to plumb source VNIC for test network");
		return (-1);
	}

	// Create dest vnic
	if (DLADM("create-vnic", "-t", "-l", testether,
	    "-p", "protection=mac-nospoof,restricted,ip-nospoof,dhcp-nospoof",
	    testvnic1) != 0) {
		warnx("Failed to create destination VNIC for test network");
		return (-1);
	}

	if (IFCONFIG(testvnic1, "inet6", "plumb", "up") != 0) {
		warnx("Failed to plumb destination VNIC for test network");
		return (-1);
	}

	return (0);
}

static void
spoof_run_test(spoof_test_f *func, int s, struct lif_nd_req *nce,
    sin6_t *multicast)
{
	static int cas = 1;
	(void) printf("Executing test case #%d...", cas++);
	if (func(s, nce, multicast) == 0) {
		(void) printf(" Done.\n");
	} else {
		(void) printf(" Error while running!\n");
	}
}

static int
spoof_run_tests(int s, struct lif_nd_req *nce)
{
	int cas, stat;
	pid_t dtrace;
	sin6_t multicast;

	/* Prepare all-nodes multicast address */
	bzero(&multicast, sizeof (multicast));
	multicast.sin6_family = AF_INET6;
	(void) inet_pton(AF_INET6, "ff02::1", &multicast.sin6_addr);

	dtrace = spoof_dtrace_launch();

	/* Wait an adequate amount of time for the probes to be installed */
	(void) sleep(5);

	/*
	 * We send a packet where everything is good, except for the hop limit.
	 * This packet should be rejected.
	 */
	spoof_run_test(spoof_good_test, s, nce, &multicast);

	if (spoof_set_max_hops(s) != 0) {
		warnx("Failed to set hop limit on socket");
		return (EXIT_FAILURE);
	}

	for (cas = 0; cas < test_cases_count; cas++) {
		spoof_run_test(test_cases[cas], s, nce, &multicast);
	}


	if (spoof_dtrace_wait(dtrace, &stat) != 0) {
		(void) printf("One or more tests of bad behaviour failed!\n");
		return (EXIT_FAILURE);
	}

	/*
	 * Now that we've executed all of the test cases that should fail, we
	 * can execute the test that should succeed, to make sure the normal
	 * case works properly. This should trip the dtrace probe.
	 */
	spoof_run_test(spoof_good_test, s, nce, &multicast);

	if (spoof_dtrace_wait(dtrace, &stat) != 0 && WIFEXITED(stat) &&
	    WEXITSTATUS(stat) == 10) {
		(void) printf("Tests completed successfully!\n");
	} else {
		if (kill(dtrace, SIGKILL) != 0)  {
			warn("Failed to kill dtrace child (pid %d)", dtrace);
		}
		(void) printf("Test of normal behaviour didn't succeed!\n");
		return (EXIT_FAILURE);
	}

	return (0);
}

/*
 * Make sure that we have all of the privileges we need to execute these tests,
 * so that we can error out before we would fail.
 */
void
spoof_check_privs(void)
{
	priv_set_t *privset = priv_allocset();

	if (privset == NULL) {
		err(EXIT_FAILURE, "Failed to allocate memory for "
		    "checking privileges");
	}

	if (getppriv(PRIV_EFFECTIVE, privset) != 0) {
		err(EXIT_FAILURE, "Failed to get current privileges");
	}

	if (!priv_ismember(privset, PRIV_DTRACE_KERNEL)) {
		errx(EXIT_FAILURE, "These tests need to be run as a user "
		    "capable of tracing the kernel.");
	}

	if (!priv_ismember(privset, PRIV_SYS_NET_CONFIG)) {
		errx(EXIT_FAILURE, "These tests need to be run as a user "
		    "capable of creating and configuring network interfaces.");
	}

	if (!priv_ismember(privset, PRIV_NET_ICMPACCESS)) {
		errx(EXIT_FAILURE, "These tests need to be run as a user "
		    "capable of sending ICMP packets.");
	}

	priv_freeset(privset);
}

int
main(void)
{
	struct lifreq addr, llar;
	int error, s;
	char testether[LIFNAMSIZ];
	char testvnic0[LIFNAMSIZ];
	char testvnic1[LIFNAMSIZ];
	pid_t curpid = getpid();

	spoof_check_privs();

	/*
	 * Set up the socket and test network for sending
	 */
	s = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (s < 0) {
		err(EXIT_FAILURE, "Failed to open ICMPv6 socket");
	}

	(void) snprintf(testether, sizeof (testether), "testether%d", curpid);
	(void) snprintf(testvnic0, sizeof (testvnic0), "testvnic%d_0", curpid);
	(void) snprintf(testvnic1, sizeof (testvnic1), "testvnic%d_1", curpid);

	if (spoof_network_setup(testether, testvnic0, testvnic1) != 0) {
		warnx("Failed to set up test network");
		error = EXIT_FAILURE;
		goto cleanup;
	}

	if (spoof_get_lla(s, testvnic0, &addr, &llar) != 0) {
		warnx("Failed to get link-layer address");
		error = EXIT_FAILURE;
		goto cleanup;
	}

	if (setsockopt(s, IPPROTO_IPV6, IPV6_BOUND_IF,
	    (char *)&((sin6_t *)&addr.lifr_addr)->sin6_scope_id,
	    sizeof (int)) < 0) {
		warn("Failed to set IPV6_UNICAST_HOPS socket option");
		return (-1);
	}

	if (bind(s, (struct sockaddr *)&addr.lifr_addr, sizeof (sin6_t)) != 0) {
		warnx("Failed to bind to link-local address");
		error = EXIT_FAILURE;
		goto cleanup;
	}

	error = spoof_run_tests(s, &llar.lifr_nd);

cleanup:
	if (close(s) != 0) {
		warnx("Failed to close ICMPv6 socket");
	}
	spoof_network_teardown(testether, testvnic0, testvnic1);
	return (error);
}
