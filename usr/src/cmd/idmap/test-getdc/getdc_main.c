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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */


#include <sys/note.h>
#include <stdarg.h>
#include <stdio.h>
#include <addisc.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int debug;
char *domainname = NULL;

void print_ds(ad_disc_ds_t *);
void mylogger(int pri, const char *format, ...);

int
main(int argc, char *argv[])
{
	ad_disc_t ad_ctx = NULL;
	boolean_t autodisc;
	ad_disc_ds_t *dc, *gc;
	char *s;
	int c;

	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
		case '?':
			(void) fprintf(stderr, "bad option: -%c\n", optopt);
			return (1);
		case 'd':
			debug++;
			break;
		}
	}

	if (optind < argc)
		domainname = argv[optind];

	adutils_set_logger(mylogger);
	adutils_set_debug(AD_DEBUG_ALL, debug);

	ad_ctx = ad_disc_init();
	ad_disc_set_StatusFP(ad_ctx, stdout);

	if (domainname)
		(void) ad_disc_set_DomainName(ad_ctx, domainname);

	ad_disc_refresh(ad_ctx);

	dc = ad_disc_get_DomainController(ad_ctx,
	    AD_DISC_PREFER_SITE, &autodisc);
	if (dc == NULL) {
		(void) printf("getdc failed\n");
		return (1);
	}
	(void) printf("Found a DC:\n");
	print_ds(dc);
	free(dc);

	s = ad_disc_get_ForestName(ad_ctx, NULL);
	(void) printf("Forest: %s\n", s);
	free(s);

	s = ad_disc_get_SiteName(ad_ctx, NULL);
	(void) printf("Site: %s\n", s);
	free(s);

	gc = ad_disc_get_GlobalCatalog(ad_ctx,
	    AD_DISC_PREFER_SITE, &autodisc);
	if (gc != NULL) {
		(void) printf("Found a GC:\n");
		print_ds(gc);
		free(gc);
	}

	ad_disc_done(ad_ctx);
	ad_disc_fini(ad_ctx);
	ad_ctx = NULL;

	return (0);
}

void
print_ds(ad_disc_ds_t *ds)
{
	char buf[64];

	for (; ds->host[0] != '\0'; ds++) {
		const char *p;

		(void) printf("Name: %s\n", ds->host);
		(void) printf(" flags: 0x%X\n", ds->flags);
		if (ds->addr.ss_family == AF_INET) {
			struct sockaddr_in *sin;
			sin = (struct sockaddr_in *)&ds->addr;
			p = inet_ntop(AF_INET, &sin->sin_addr,
			    buf, sizeof (buf));
			if (p == NULL)
				p = "?";
			(void) printf(" A %s %d\n", p, ds->port);
		}
		if (ds->addr.ss_family == AF_INET6) {
			struct sockaddr_in6 *sin6;
			sin6 = (struct sockaddr_in6 *)&ds->addr;
			p = inet_ntop(AF_INET6, &sin6->sin6_addr,
			    buf, sizeof (buf));
			if (p == NULL)
				p = "?";
			(void) printf(" AAAA %s %d\n", p, ds->port);
		}
	}
}

/* printflike */
void
mylogger(int pri, const char *format, ...)
{
	_NOTE(ARGUNUSED(pri))
	va_list args;

	va_start(args, format);
	(void) vfprintf(stderr, format, args);
	(void) fprintf(stderr, "\n");
	va_end(args);
}

/*
 * This is a unit-test program.  Always enable libumem debugging.
 */
const char *
_umem_debug_init(void)
{
	return ("default,verbose"); /* $UMEM_DEBUG setting */
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents"); /* $UMEM_LOGGING setting */
}
