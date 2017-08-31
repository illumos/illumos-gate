/*
 * Copyright 2017 Gary Mills
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Licensed under the Academic Free License version 2.1
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <libhal.h>
#include <logger.h>

#include <glib.h>

#include "network-discovery.h"
#define	NP(x)	(x?x:"NULL")

extern int snmp_printer_info(char *hostname, char *community,
		char **manufacturer, char **model, char **description,
		char **serial_no, char ***command_set, char **uri);

void
network_device_name_to_udi(char *udi, size_t size, ...)
{
	va_list ap;
	char *element;
	int i;

	udi[0] = '\0';
	va_start(ap, size);
	while ((element = va_arg(ap, char *)) != NULL) {
		if (element[0] != '/')
			strlcat(udi, "/", size);
		strlcat(udi, element, size);
	}
	va_end(ap);

	for (i = 0; udi[i] != NULL; i++)
		if (udi[i] == '.')
			udi[i] = '_';
}

static void nop(int sig) {}

static int
test_socket_access(struct in6_addr *addr, int port)
{
	int sd, rc;
	struct sockaddr_in6 sin6;
	void (*hndlr)(int);

	memset(&sin6, 0, sizeof (sin6));
	sin6.sin6_family = AF_INET6;
	memcpy(&sin6.sin6_addr, addr, sizeof (*addr));
	sin6.sin6_port = htons(port);

	sd = socket(AF_INET6, SOCK_STREAM, 0);
	hndlr = signal(SIGALRM, nop);
	alarm(1);
	rc = connect(sd, (struct sockaddr *)&sin6, sizeof (sin6));
	alarm(0);
	if (hndlr != NULL)
		signal(SIGALRM, hndlr);
	close(sd);

	return ((rc < 0) ? 1 : 0);
}

int
is_listening(char *hostname, int port)
{
	char *uri = NULL, addr_string[INET6_ADDRSTRLEN];
	struct in6_addr ipv6addr[1];
	int errnum;
	struct hostent *hp;

	hp = getipnodebyname(hostname, AF_INET6,
			AI_ALL | AI_ADDRCONFIG | AI_V4MAPPED, &errnum);
	if (hp != NULL) {
		(void) memcpy(&ipv6addr, hp->h_addr_list[0], hp->h_length);
	} else
		return (-1);

	return (test_socket_access(ipv6addr, port));
}

static char *
addr_to_string(char *prefix, uchar_t *mac, int mac_len, char *buf, int buf_len)
{
	int i, n = 0;

	buf[0] = '\0';
	if (prefix != NULL)
		n = sprintf(buf, prefix);
	for (i = 0; ((i < (mac_len)) && (n < buf_len)); i++)
		n += sprintf(buf + n, "%2.2X", *mac++);

	return (buf);
}

static char *
pseudo_serialno_from_addr(char *name)
{
	int sd, errnum;
	char buf[128];
	struct hostent *hp;
	struct xarpreq ar;

	if (name == NULL)
		return (NULL);

	memset(&ar, 0, sizeof (ar));

	hp = getipnodebyname(name, AF_INET6, AI_ADDRCONFIG, &errnum);
	if (hp != NULL) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ar.xarp_pa;

		sin6->sin6_family = AF_INET6;
		(void) memcpy(&sin6->sin6_addr, hp->h_addr_list[0],
				hp->h_length);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ar.xarp_pa;

		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = inet_addr(name);
	}

	sd = socket(AF_INET, SOCK_DGRAM, 0);

	ar.xarp_ha.sdl_family = AF_LINK;
	(void) ioctl(sd, SIOCGXARP, (caddr_t)&ar);

	close(sd);

	if (ar.xarp_flags & ATF_COM) {  /* use the MAC address */
		uchar_t *ea = (uchar_t *)LLADDR(&ar.xarp_ha);

		addr_to_string("LLADDR-", ea, ar.xarp_ha.sdl_alen,
					buf, sizeof (buf));

	} else if (hp != NULL) {	  /* use the IPv6 address */
		addr_to_string("IPV6ADDR-", (uchar_t *)&hp->h_addr_list[0],
					hp->h_length, buf, sizeof (buf));
	} else {			  /* use the IPv4 address */
		struct sockaddr_in *sin = (struct sockaddr_in *)&ar.xarp_pa;

		addr_to_string("IPV4ADDR-", (uchar_t *)&sin->sin_addr.s_addr, 4,
					buf, sizeof (buf));
	}

	return (strdup(buf));
}

int
add_network_printer(LibHalContext *ctx, char *base, char *hostaddr,
		char *device, char *community)
{
	DBusError error;
	int rc = -1;
	char udi[128];
	char *tmp_udi = NULL;
	static char *parent = NULL;
	char *manufacturer = NULL, *model = NULL, *description = NULL,
	     *uri = NULL, *sn, *serial;

	sn = serial = pseudo_serialno_from_addr(hostaddr);

	if (parent == NULL)
		parent = getenv("UDI");

	dbus_error_init(&error);

	network_device_name_to_udi(udi, sizeof (udi), base, serial, NULL);

	if (libhal_device_exists(ctx, udi, &error) == TRUE)
		goto out;

	if ((tmp_udi = libhal_new_device(ctx, &error)) == NULL)
		goto out;

	snmp_printer_info(hostaddr, community, &manufacturer, &model,
			&description, &serial, NULL, &uri);

	libhal_device_set_property_string(ctx, tmp_udi,
			"info.parent", parent, &error);

	libhal_device_set_property_string(ctx, tmp_udi,
			"info.category", "printer", &error);

	libhal_device_property_strlist_append(ctx, tmp_udi,
				"info.capabilities", "printer", &error);
	libhal_device_property_strlist_append(ctx, tmp_udi,
				"info.capabilities", "network_device", &error);

	libhal_device_set_property_string(ctx, tmp_udi,
			"network_device.address", hostaddr, &error);

	if ((community != NULL) && (strcasecmp(community, "public") != 0))
		libhal_device_set_property_string(ctx, tmp_udi,
			"network_device.snmp_community", community, &error);

	if ((uri != NULL) || (device != NULL))
		libhal_device_set_property_string(ctx, tmp_udi,
			"printer.device", (uri ? uri : device), &error);

	if (serial != NULL)
		libhal_device_set_property_string(ctx, tmp_udi,
			"printer.serial", serial, &error);

	if (manufacturer != NULL)
		libhal_device_set_property_string(ctx, tmp_udi,
			"printer.vendor", manufacturer, &error);

	if (model != NULL)
		libhal_device_set_property_string(ctx, tmp_udi,
			"printer.product", model, &error);

	if (description != NULL)
		libhal_device_set_property_string(ctx, tmp_udi,
			"printer.description", description, &error);

	/* commit the changes to the new UDI */
	rc = libhal_device_commit_to_gdl(ctx, tmp_udi, udi, &error);

out:
	HAL_DEBUG(("result: %s (%s): %s, %s, %s, %s, %s", hostaddr, udi,
		NP(manufacturer), NP(model), NP(description), NP(serial),
		NP(uri)));

	if (tmp_udi != NULL)
		free(tmp_udi);
	if (manufacturer != NULL)
		free(manufacturer);
	if (model != NULL)
		free(model);
	if (description != NULL)
		free(description);
	if (uri != NULL)
		free(uri);
	if (sn != NULL)
		free(sn);

	if (dbus_error_is_set(&error)) {
		HAL_WARNING(("%s: %s", error.name, error.message));
		dbus_error_free(&error);
	}

	HAL_DEBUG(("add: %s (%s)", hostaddr, udi));

	return (rc);
}

static int
number_of_interfaces(int s)
{
	int rc = -1;
	struct lifnum n;

	memset(&n, 0 , sizeof (n));
	n.lifn_family = AF_INET;
	if (ioctl(s, SIOCGLIFNUM, (char *)&n) == 0)
		rc = n.lifn_count;

	return (rc);
}

static char *
broadcast_address(int s, char *ifname)
{
	char *result = NULL;
	struct lifreq r;

	memset(&r, 0, sizeof (r));
	strlcpy(r.lifr_name, ifname, sizeof (r.lifr_name));
	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&r) < 0) {
		HAL_DEBUG(("broadcast_address: ioctl(SIOCGLIFFLAGS) failed."));
		return (NULL);
	}
	if ((r.lifr_flags & (IFF_UP | IFF_LOOPBACK)) != IFF_UP) {
		return (NULL);
	}
	if (ioctl(s, SIOCGLIFBRDADDR, (char *)&r) >= 0) {
		char buf[INET_ADDRSTRLEN];
		struct sockaddr_in *s =
		    (struct sockaddr_in *)&r.lifr_broadaddr;
		result = (char *)inet_ntop(AF_INET,
		    &s->sin_addr, buf, sizeof (buf));
		if (result != NULL)
			result = strdup(result);
	}

	return (result);
}

GList *
broadcast_addresses()
{
	GList *result = NULL;
	int s;
	struct lifconf c;
	int count;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return (NULL);

	count = number_of_interfaces(s);

	memset(&c, 0, sizeof (c));
	c.lifc_family = AF_INET;
	c.lifc_flags = 0;
	c.lifc_buf = calloc(count, sizeof (struct lifreq));
	c.lifc_len = (count * sizeof (struct lifreq));

	if (ioctl(s, SIOCGLIFCONF, (char *)&c) == 0) {
		struct lifreq *r = c.lifc_req;

		for (count = c.lifc_len / sizeof (struct lifreq);
		     count > 0; count--, r++) {
			char *address = broadcast_address(s, r->lifr_name);

			if (address != NULL) /* add it to the list */
				result = g_list_append(result, address);
		}
	}
	free(c.lifc_buf);
	close(s);

	return (result);
}
