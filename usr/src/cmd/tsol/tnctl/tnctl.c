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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * tnctl.c -
 *          Trusted Network control utility
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <locale.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <libtsnet.h>
#include <zone.h>
#include <nss_dbdefs.h>

static void process_rh(const char *);
static void process_rhl(const char *);
static void process_mlp(const char *);
static void process_tp(const char *);
static void process_tpl(const char *);
static void process_tnzone(const char *);
static void usage(void);
static void translate_inet_addr(tsol_rhent_t *, int *, char [], int);

static boolean_t verbose_mode;
static boolean_t delete_mode;
static boolean_t flush_mode;

int
main(int argc, char **argv)
{
	extern char *optarg;
	int chr;

	/* Don't do anything if labeling is not active. */
	if (!is_system_labeled())
		return (0);

	/* set the locale for only the messages system (all else is clean) */
	(void) setlocale(LC_ALL, "");
#ifndef TEXT_DOMAIN		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif

	(void) textdomain(TEXT_DOMAIN);

	while ((chr = getopt(argc, argv, "dfh:H:m:t:T:vz:")) != EOF) {
		switch (chr) {
		case 'd':
			delete_mode = B_TRUE;
			break;
		case 'f':
			flush_mode = B_TRUE;
			break;
		case 'h':
			process_rh(optarg);
			break;
		case 'H':
			process_rhl(optarg);
			break;
		case 'm':
			process_mlp(optarg);
			break;
		case 't':
			process_tp(optarg);
			break;
		case 'T':
			process_tpl(optarg);
			break;
		case 'v':
			verbose_mode = B_TRUE;
			break;
		case 'z':
			process_tnzone(optarg);
			break;
		case '?':
			usage();
		}
	}
	return (0);
}

static void
print_error(int linenum, int err, const char *errstr)
{
	if (linenum > 0)
		(void) fprintf(stderr, gettext("line %1$d: %2$s:\n"), linenum,
		    tsol_strerror(err, errno));
	else
		(void) fprintf(stderr, gettext("tnctl: parsing error: %s\n"),
		    tsol_strerror(err, errno));
	(void) fprintf(stderr, "%.32s\n", errstr);
}

/*
 * Produce ascii format of address and prefix length
 */
static void
translate_inet_addr(tsol_rhent_t *rhentp, int *alen, char abuf[], int abuflen)
{
	void *aptr;
	tsol_rhent_t rhent;
	struct in6_addr ipv6addr;
	char tmpbuf[20];

	(void) snprintf(tmpbuf, sizeof (tmpbuf), "/%d", rhentp->rh_prefix);

	if (rhentp->rh_address.ta_family == AF_INET6) {
		aptr = &(rhentp->rh_address.ta_addr_v6);
		(void) inet_ntop(rhentp->rh_address.ta_family, aptr, abuf,
		    abuflen);
		if (rhentp->rh_prefix != 128) {
			if (strlcat(abuf, tmpbuf, abuflen) >= abuflen)
				(void) fprintf(stderr, gettext(
				    "tnctl: buffer overflow detected: %s\n"),
				    abuf);
		}
		*alen = strlen(abuf);
	} else {
		aptr = &(rhentp->rh_address.ta_addr_v4);
		(void) inet_ntop(rhentp->rh_address.ta_family, aptr, abuf,
		    abuflen);
		if (rhentp->rh_prefix != 32) {
			if (strlcat(abuf, tmpbuf, abuflen) >= abuflen)
				(void) fprintf(stderr, gettext(
				    "tnctl: buffer overflow detected: %s\n"),
				    abuf);
		}
		*alen = strlen(abuf);
	}
}

/*
 * Load remote host entries from the designated file.
 */
static void
process_rhl(const char *file)
{
	boolean_t	error = B_FALSE;
	boolean_t	success = B_FALSE;
	tsol_rhent_t	*rhentp = NULL;
	FILE		*fp;
	int alen;
	/* abuf holds: <numeric-ip-addr>'/'<prefix-length>'\0' */
	char abuf[INET6_ADDRSTRLEN+5];

	if ((fp = fopen(file, "r")) == NULL) {
		(void) fprintf(stderr,
		    gettext("tnctl: failed to open %1$s: %2$s\n"),
		    file, strerror(errno));
		exit(1);
	}

	tsol_setrhent(1);
	while (rhentp = tsol_fgetrhent(fp, &error)) {
		/* First time through the loop, flush it all */
		if (!success && flush_mode)
			(void) tnrh(TNDB_FLUSH, NULL);
		success = B_TRUE;

		if (verbose_mode)
			(void) printf("loading rh entry...\n");

		if (tnrh(TNDB_LOAD, rhentp) != 0) {
			(void) fclose(fp);
			if (errno == EFAULT) {
				perror("tnrh");
			} else {
				translate_inet_addr(rhentp, &alen, abuf,
				    sizeof (abuf));
				(void) fprintf(stderr,
				    gettext("tnctl: load of remote-host entry "
				    "%1$s into kernel cache failed: %2$s\n"),
				    abuf, strerror(errno));
			}
			tsol_endrhent();
			exit(1);
		}
		tsol_freerhent(rhentp);
	}
	if (!success) {
		(void) fprintf(stderr,
		    gettext("tnctl: No valid tnrhdb entries found in %s\n"),
		    file);
	}
	(void) fclose(fp);
	tsol_endrhent();

	if (error)
		exit(1);
}

/*
 * The argument can be either a host name, an address
 * in tnrhdb address format, or a complete tnrhdb entry.
 */
static void
process_rh(const char *hostname)
{
	tsol_rhstr_t rhstr;
	tsol_rhent_t rhent;
	tsol_rhent_t *rhentp;
	int err;
	int alen;
	char *errstr;
	/* abuf holds: <numeric-ip-addr>'/'<prefix-length>'\0' */
	char abuf[INET6_ADDRSTRLEN+5];
	const char *cp;
	char *cp1;
	char *cp2;
	void *aptr;
	char buf[NSS_BUFLEN_TSOL_RH];
	struct in6_addr ipv6addr;

	/* was a template name provided on the command line? */
	if ((cp = strrchr(hostname, ':')) != NULL && cp != hostname &&
	    cp[-1] != '\\') {
		/* use common tnrhdb line conversion function */
		(void) str_to_rhstr(hostname, strlen(hostname), &rhstr, buf,
		    sizeof (buf));
		rhentp = rhstr_to_ent(&rhstr, &err, &errstr);
		if (rhentp == NULL) {
			print_error(0, err, errstr);
			exit(1);
		}
	} else {
		char *hostname_p;
		char *prefix_p;
		struct hostent *hp;

		/* Check for a subnet prefix length */
		if ((prefix_p = strchr(hostname, '/')) != NULL) {
			cp1 = prefix_p + 1;
			errno = 0;
			rhent.rh_prefix = strtol(cp1, &cp2, 0);
			if (*cp2 != '\0' || errno != 0 || rhent.rh_prefix < 0) {
				(void) fprintf(stderr, gettext("tnct: invalid "
				    "prefix length: %s\n"), cp);
				exit(2);
			}
		} else {
			rhent.rh_prefix = -1;
		}

		/* Strip any backslashes from numeric address */
		hostname_p = malloc(strlen(hostname)+1);
		if (hostname_p == NULL) {
			perror("tnctl");
			exit(2);
		}
		cp1 = hostname_p;
		while (*hostname != '\0' && *hostname != '/') {
			*cp1 = *hostname++;
			if (*cp1 != '\\')
				cp1++;
		}
		*cp1 = '\0';

		/* Convert address or hostname to binary af_inet6 format */
		hp = getipnodebyname(hostname_p, AF_INET6,
		    AI_ALL | AI_ADDRCONFIG | AI_V4MAPPED, &err);
		if (hp == NULL) {
			(void) fprintf(stderr, gettext("tnctl: unknown host "
			    "or invalid literal address: %s\n"), hostname_p);
			if (err == TRY_AGAIN)
				(void) fprintf(stderr,
				    gettext("\t(try again later)\n"));
			exit(2);
		}
		free(hostname_p);
		(void) memcpy(&ipv6addr, hp->h_addr, hp->h_length);

		/* if ipv4 address, convert to af_inet format */
		if (IN6_IS_ADDR_V4MAPPED(&ipv6addr)) {
			rhent.rh_address.ta_family = AF_INET;
			IN6_V4MAPPED_TO_INADDR(&ipv6addr,
			    &rhent.rh_address.ta_addr_v4);
			if (rhent.rh_prefix == -1)
				rhent.rh_prefix = 32;
		} else {
			rhent.rh_address.ta_family = AF_INET6;
			rhent.rh_address.ta_addr_v6 = ipv6addr;
			if (rhent.rh_prefix == -1)
				rhent.rh_prefix = 128;
		}
		rhent.rh_template[0] = '\0';
		rhentp = &rhent;
	}

	/* produce ascii format of address and prefix length */
	translate_inet_addr(rhentp, &alen, abuf, sizeof (abuf));

	/*
	 * look up the entry from ldap or tnrhdb if this is a load
	 * request and a template name was not provided.
	 */
	if (!delete_mode &&
	    rhentp->rh_template[0] == '\0' &&
	    (rhentp = tsol_getrhbyaddr(abuf, alen+1,
	    rhent.rh_address.ta_family)) == NULL) {
		(void) fprintf(stderr,
		    gettext("tnctl: database lookup failed for %s\n"),
		    abuf);
		exit(1);
	}

	if (verbose_mode)
		(void) printf("%s rh entry %s\n", delete_mode ? "deleting" :
		    "loading", abuf);

	/* update the tnrhdb entry in the kernel */
	if (tnrh(delete_mode ? TNDB_DELETE : TNDB_LOAD, rhentp) != 0) {
		if (errno == EFAULT)
			perror("tnrh");
		else if (errno == ENOENT)
			(void) fprintf(stderr,
			    gettext("tnctl: %1$s of remote-host kernel cache "
			    "entry %2$s failed: no such entry\n"),
			    delete_mode ? gettext("delete") : gettext("load"),
			    abuf);
		else
			(void) fprintf(stderr,
			    gettext("tnctl: %1$s of remote-host kernel cache "
			    "entry %2$s failed: %3$s\n"),
			    delete_mode ? gettext("delete") : gettext("load"),
			    abuf, strerror(errno));
		exit(1);
	}
	if (rhentp != &rhent)
		tsol_freerhent(rhentp);
}

static void
handle_mlps(zoneid_t zoneid, tsol_mlp_t *mlp, int flags, int cmd)
{
	tsol_mlpent_t tsme;

	tsme.tsme_zoneid = zoneid;
	tsme.tsme_flags = flags;
	while (!TSOL_MLP_END(mlp)) {
		tsme.tsme_mlp = *mlp;
		if (tnmlp(cmd, &tsme) != 0) {
			/*
			 * Usage of ?: here is ugly, but helps with
			 * localization.
			 */
			(void) fprintf(stderr,
			    flags & TSOL_MEF_SHARED ?
			    gettext("tnctl: cannot set "
			    "shared MLP on %1$d-%2$d/%3$d: %4$s\n") :
			    gettext("tnctl: cannot set "
			    "zone-specific MLP on %1$d-%2$d/%3$d: %4$s\n"),
			    mlp->mlp_port, mlp->mlp_port_upper, mlp->mlp_ipp,
			    strerror(errno));
			exit(1);
		}
		mlp++;
	}
}

/*
 * This reads the configuration for the global zone out of tnzonecfg
 * and sets it in the kernel.  The non-global zones are configured
 * by zoneadmd.
 */
static void
process_tnzone(const char *file)
{
	tsol_zcent_t *zc;
	tsol_mlpent_t tsme;
	int err;
	char *errstr;
	FILE *fp;
	char line[2048], *cp;
	int linenum, errors;

	if ((fp = fopen(file, "r")) == NULL) {
		(void) fprintf(stderr,
		    gettext("tnctl: failed to open %s: %s\n"), file,
		    strerror(errno));
		exit(1);
	}

	linenum = errors = 0;
	zc = NULL;
	while (fgets(line, sizeof (line), fp) != NULL) {
		if ((cp = strchr(line, '\n')) != NULL)
			*cp = '\0';

		linenum++;
		if ((zc = tsol_sgetzcent(line, &err, &errstr)) == NULL) {
			if (err == LTSNET_EMPTY)
				continue;
			if (errors == 0) {
				int errtmp = errno;

				(void) fprintf(stderr, gettext("tnctl: errors "
				    "parsing %s:\n"), file);
				errno = errtmp;
			}
			print_error(linenum, err, errstr);
			errors++;
			continue;
		}

		if (strcasecmp(zc->zc_name, "global") == 0)
			break;
		tsol_freezcent(zc);
	}
	(void) fclose(fp);

	if (zc == NULL) {
		(void) fprintf(stderr,
		    gettext("tnctl: cannot find global zone in %s\n"), file);
		exit(1);
	}

	tsme.tsme_zoneid = GLOBAL_ZONEID;
	tsme.tsme_flags = 0;
	if (flush_mode)
		(void) tnmlp(TNDB_FLUSH, &tsme);

	handle_mlps(GLOBAL_ZONEID, zc->zc_private_mlp, 0, TNDB_LOAD);
	handle_mlps(GLOBAL_ZONEID, zc->zc_shared_mlp, TSOL_MEF_SHARED,
	    TNDB_LOAD);

	tsol_freezcent(zc);
}

static void
process_tpl(const char *file)
{
	FILE		*fp;
	boolean_t	error = B_FALSE;
	boolean_t	success = B_FALSE;
	tsol_tpent_t	*tpentp;

	if ((fp = fopen(file, "r")) == NULL) {
		(void) fprintf(stderr,
		    gettext("tnctl: failed to open %s: %s\n"), file,
		    strerror(errno));
		exit(1);
	}

	tsol_settpent(1);
	while (tpentp = tsol_fgettpent(fp, &error)) {
		/* First time through the loop, flush it all */
		if (!success && flush_mode)
			(void) tnrhtp(TNDB_FLUSH, NULL);

		success = B_TRUE;

		if (verbose_mode)
			(void) printf("tnctl: loading rhtp entry ...\n");

		if (tnrhtp(TNDB_LOAD, tpentp) != 0) {
			(void) fclose(fp);
			if (errno == EFAULT)
				perror("tnrhtp");
			else
				(void) fprintf(stderr, gettext("tnctl: load "
				    "of remote-host template %1$s into kernel "
				    "cache failed: %2$s\n"), tpentp->name,
				    strerror(errno));
			tsol_endtpent();
			exit(1);
		}
		tsol_freetpent(tpentp);
	}
	if (!success) {
		(void) fprintf(stderr,
		    gettext("tnctl: No valid tnrhtp entries found in %s\n"),
		    file);
	}
	(void) fclose(fp);
	tsol_endtpent();

	if (error)
		exit(1);
}

static void
process_tp(const char *template)
{
	tsol_tpstr_t tpstr;
	tsol_tpent_t tpent;
	tsol_tpent_t *tpentp;
	int err;
	char *errstr;
	char buf[NSS_BUFLEN_TSOL_TP];

	if (strchr(template, ':') != NULL) {
		(void) str_to_tpstr(template, strlen(template), &tpstr, buf,
		    sizeof (buf));
		tpentp = tpstr_to_ent(&tpstr, &err, &errstr);
		if (tpentp == NULL) {
			print_error(0, err, errstr);
			exit(1);
		}
	} else if (delete_mode) {
		(void) memset(&tpent, 0, sizeof (tpent));
		tpentp = &tpent;
		(void) strlcpy(tpentp->name, template, sizeof (tpentp->name));
	} else if ((tpentp = tsol_gettpbyname(template)) == NULL) {
		(void) fprintf(stderr,
		    gettext("tnctl: template %s not found\n"), template);
		exit(1);
	}

	if (verbose_mode)
		(void) printf("%s rhtp entry ...\n", delete_mode ? "deleting" :
		    "loading");

	if (tnrhtp(delete_mode ? TNDB_DELETE : TNDB_LOAD, tpentp) != 0) {
		if (errno == EFAULT)
			perror("tnrhtp");
		else if (errno == ENOENT)
			(void) fprintf(stderr,
			    gettext("tnctl: %1$s of remote-host template "
			    "kernel cache entry %2$s failed: no such "
			    "entry\n"),
			    delete_mode ? gettext("delete") : gettext("load"),
			    tpentp->name);
		else
			(void) fprintf(stderr,
			    gettext("tnctl: %1$s of remote-host template "
			    "kernel cache entry %2$s failed: %3$s\n"),
			    delete_mode ? gettext("delete") : gettext("load"),
			    tpentp->name, strerror(errno));
		exit(1);
	}
	if (tpentp != &tpent)
		tsol_freetpent(tpentp);
}

static void
process_mlp(const char *str)
{
	const char *cp;
	char zonename[ZONENAME_MAX];
	zoneid_t zoneid;
	tsol_zcent_t *zc;
	int err;
	char *errstr;
	char *sbuf;

	if ((cp = strchr(str, ':')) == NULL) {
		if (!delete_mode) {
			(void) fprintf(stderr,
			    gettext("tnctl: need MLP list to insert\n"));
			exit(2);
		}
		(void) strlcpy(zonename, str, sizeof (zonename));
	} else if (cp - str >= ZONENAME_MAX) {
		(void) fprintf(stderr, gettext("tnctl: illegal zone name\n"));
		exit(2);
	} else {
		(void) memcpy(zonename, str, cp - str);
		zonename[cp - str] = '\0';
		str = cp + 1;
	}

	if ((zoneid = getzoneidbyname(zonename)) == -1) {
		(void) fprintf(stderr, gettext("tninfo: zone '%s' unknown\n"),
		    zonename);
		exit(1);
	}

	sbuf = malloc(strlen(zonename) + sizeof (":ADMIN_LOW:0:") +
	    strlen(str));
	if (sbuf == NULL) {
		perror("malloc");
		exit(1);
	}
	/* LINTED: sprintf is known not to be unbounded here */
	(void) sprintf(sbuf, "%s:ADMIN_LOW:0:%s", zonename, str);
	if ((zc = tsol_sgetzcent(sbuf, &err, &errstr)) == NULL) {
		(void) fprintf(stderr,
		    gettext("tnctl: unable to parse MLPs\n"));
		exit(1);
	}
	handle_mlps(zoneid, zc->zc_private_mlp, 0,
	    delete_mode ? TNDB_DELETE : TNDB_LOAD);
	handle_mlps(zoneid, zc->zc_shared_mlp, TSOL_MEF_SHARED,
	    delete_mode ? TNDB_DELETE : TNDB_LOAD);
	tsol_freezcent(zc);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage: tnctl [-dfv] "
	    "[-h host[/prefix][:tmpl]] [-m zone:priv:share]\n\t"
	    "[-t tmpl[:key=val[;key=val]]] [-[HTz] file]\n"));

	exit(1);
}
