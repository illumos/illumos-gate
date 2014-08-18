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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <zone.h>

#include <libvnd.h>

typedef int (*vndadm_print_t)(vnd_handle_t *, vnd_prop_t);
typedef int (*vndadm_parse_t)(char *, void **, size_t *);

typedef struct vndadm_proptbl {
	const char *vp_name;
	vndadm_print_t vp_print;
	vndadm_parse_t vp_parse;
} vndadm_proptbl_t;

/*
 * Forwards
 */
static int usage(const char *, ...);
static int vndadm_print_size(vnd_handle_t *, vnd_prop_t);
static int vndadm_print_number(vnd_handle_t *, vnd_prop_t);
static int vndadm_parse_size(char *, void **, size_t *);

/*
 * Globals
 */
static char *vnd_pname;

static void
vnd_vwarn(vnd_errno_t verr, int syserr, const char *format, va_list alist)
{
	(void) fprintf(stderr, "%s: ", vnd_pname);
	(void) vfprintf(stderr, format, alist);
	if (strchr(format, '\n') == NULL) {
		(void) fprintf(stderr, ": %s\n", verr != VND_E_SYS ?
		    vnd_strerror(verr) : vnd_strsyserror(syserr));
	}
}

static void
vnd_libwarn(vnd_errno_t verr, int syserr, const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	vnd_vwarn(verr, syserr, format, alist);
	va_end(alist);
}

static void
vnd_warn(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	vnd_vwarn(0, 0, format, alist);
	va_end(alist);
}

static vndadm_proptbl_t vndadm_propname_tbl[] = {
	{ "rxbuf", vndadm_print_size,
		vndadm_parse_size },		/* VND_PROP_RXBUF */
	{ "txbuf", vndadm_print_size,
		vndadm_parse_size },		/* VND_PROP_TXBUF */
	{ "maxsize", vndadm_print_size, NULL },	/* VND_PROP_MAXBUF */
	{ "mintu", vndadm_print_number, NULL },	/* VND_PROP_MINTU */
	{ "maxtu", vndadm_print_number, NULL },	/* VND_PROP_MAXTU */
	NULL					/* VND_PROP_MAX */
};

static const char *
vndadm_prop_to_name(vnd_prop_t prop)
{
	if (prop > VND_PROP_MAX)
		return (NULL);

	return (vndadm_propname_tbl[prop].vp_name);
}

static vnd_prop_t
vndadm_name_to_prop(const char *name)
{
	int i;

	for (i = 0; i < VND_PROP_MAX; i++) {
		if (strcmp(name, vndadm_propname_tbl[i].vp_name) == 0)
			return (i);
	}

	return (VND_PROP_MAX);
}

static int
vndadm_print_size(vnd_handle_t *vhp, vnd_prop_t prop)
{
	vnd_prop_buf_t buf;

	if (vnd_prop_get(vhp, prop, &buf, sizeof (buf)) != 0) {
		vnd_libwarn(vnd_errno(vhp), vnd_syserrno(vhp),
		    "failed to get property %s", vndadm_prop_to_name(prop));
		return (1);
	}

	(void) printf("%lld", buf.vpb_size);
	return (0);
}

static int
vndadm_print_number(vnd_handle_t *vhp, vnd_prop_t prop)
{
	vnd_prop_buf_t buf;

	if (vnd_prop_get(vhp, prop, &buf, sizeof (buf)) != 0) {
		vnd_libwarn(vnd_errno(vhp), vnd_syserrno(vhp),
		    "failed to get property %s", vndadm_prop_to_name(prop));
		return (1);
	}

	(void) printf("%lld", buf.vpb_size);
	return (0);
}

static int
vndadm_parse_size(char *str, void **bufp, size_t *sizep)
{
	char *end;
	unsigned long long val, orig;
	vnd_prop_buf_t *buf;

	errno = 0;
	val = strtoull(str, &end, 10);
	if (errno != 0) {
		vnd_warn("%s: not a number\n", str);
		return (1);
	}

	orig = val;
	switch (*end) {
	case 'g':
	case 'G':
		val *= 1024;
		if (val < orig)
			goto overflow;
		/*FALLTHRU*/
	case 'm':
	case 'M':
		val *= 1024;
		if (val < orig)
			goto overflow;
		/*FALLTHRU*/
	case 'k':
	case 'K':
		val *= 1024;
		if (val < orig)
			goto overflow;
		end++;
		break;
	default:
		break;
	}

	if (*end == 'b' || *end == 'B')
		end++;
	if (*end != '\0') {
		vnd_warn("%s: not a number", str);
		return (1);
	}

	buf = malloc(sizeof (vnd_prop_buf_t));
	if (buf == NULL) {
		vnd_warn("failed to allocate memory for setting a property");
		return (1);
	}

	buf->vpb_size = val;
	*bufp = buf;
	*sizep = sizeof (vnd_prop_buf_t);

	return (0);

overflow:
	vnd_warn("value overflowed: %s\n", str);
	return (1);
}

static void
vndadm_create_usage(FILE *out)
{
	(void) fprintf(out, "\tcreate:\t\t[-z zonename] -l datalink name\n");
}

static int
vndadm_create(int argc, char *argv[])
{
	int c, syserr;
	vnd_errno_t vnderr;
	const char *datalink = NULL;
	const char *linkname = NULL;
	const char *zonename = NULL;
	vnd_handle_t *vhp;

	optind = 0;
	while ((c = getopt(argc, argv, ":z:l:")) != -1) {
		switch (c) {
		case 'l':
			datalink = optarg;
			break;
		case 'z':
			zonename = optarg;
			break;
		case ':':
			return (usage("-%c requires an operand\n", optopt));
		case '?':
			return (usage("unknown option: -%c\n", optopt));
		default:
			abort();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		return (usage("missing required link name\n"));
	} else if (argc > 1) {
		return (usage("create: too many arguments for link name, "
		    "pick one\n"));
	}
	linkname = argv[0];
	if (datalink == NULL)
		datalink = linkname;

	vhp = vnd_create(zonename, datalink, linkname, &vnderr, &syserr);
	if (vhp == NULL) {
		vnd_libwarn(vnderr, syserr,
		    "failed to create datapath link %s", linkname);
		return (1);
	}

	vnd_close(vhp);
	return (0);
}

static void
vndadm_destroy_usage(FILE *out)
{
	(void) fprintf(out, "\tdestroy:\t[-z zonename] [link]...\n");
}

static int
vndadm_destroy(int argc, char *argv[])
{
	vnd_handle_t *vhp;
	int c, syserr;
	vnd_errno_t vnderr;
	const char *zonename = NULL;

	optind = 0;
	while ((c = getopt(argc, argv, ":z:")) != -1) {
		switch (c) {
		case 'z':
			zonename = optarg;
			break;
		case ':':
			return (usage("-%c requires an operand\n", optopt));
		case '?':
			return (usage("unknown option: -%c\n", optopt));
		default:
			abort();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		return (usage("extraneous arguments\n"));
	}

	vhp = vnd_open(zonename, argv[0], &vnderr, &syserr);
	if (vhp == NULL) {
		vnd_libwarn(vnderr, syserr, "failed to open link: %s", argv[0]);
		return (1);
	}

	if (vnd_unlink(vhp) != 0) {
		vnd_libwarn(vnd_errno(vhp), vnd_syserrno(vhp),
		    "failed to destroy link %s", argv[0]);
		return (1);
	}

	vnd_close(vhp);
	return (0);
}

static void
vndadm_list_usage(FILE *out)
{
	(void) fprintf(out, "\tlist:\t\t[-p] [-d delim] [-o field,...] "
	    "[-z zonename] [link]...\n");
}

#define	VNDADM_LIST_NFIELDS	3

typedef struct vndadm_list_cb {
	int vsc_argc;
	char **vsc_argv;
	int vsc_found;
	boolean_t vsc_parse;
	const char *vsc_delim;
	int vsc_order[VNDADM_LIST_NFIELDS];
	int vsc_last;
	zoneid_t vsc_zid;
} vndadm_list_cb_t;

typedef struct vndadm_list_field {
	const char *vlf_name;
	const char *vlf_header;
	int vlf_size;
	void (*vlf_print)(struct vndadm_list_field *, vnd_info_t *, boolean_t);
	void (*vlf_parse)(struct vndadm_list_field *, vnd_info_t *, boolean_t);
} vndadm_list_field_t;

static void
vlf_print_link(vndadm_list_field_t *vlfp, vnd_info_t *viip,
    boolean_t last)
{
	if (last == B_TRUE) {
		(void) printf("%s", viip->vi_name);
	} else {
		(void) printf("%-*s", vlfp->vlf_size, viip->vi_name);
	}
}

/* ARGSUSED */
static void
vlf_parse_link(vndadm_list_field_t *vlfp, vnd_info_t *viip,
    boolean_t last)
{
	(void) printf("%s", viip->vi_name);
}

static void
vlf_print_datalink(vndadm_list_field_t *vlfp, vnd_info_t *viip,
    boolean_t last)
{
	if (last == B_TRUE) {
		(void) printf("%s", viip->vi_datalink);
	} else {
		(void) printf("%-*s", vlfp->vlf_size, viip->vi_datalink);
	}
}

/* ARGSUSED */
static void
vlf_parse_datalink(vndadm_list_field_t *vlfp, vnd_info_t *viip,
    boolean_t last)
{
	(void) printf("%s", viip->vi_datalink);
}

static void
vlf_print_zone(vndadm_list_field_t *vlfp, vnd_info_t *viip,
    boolean_t last)
{
	char buf[ZONENAME_MAX];

	if (getzonenamebyid(viip->vi_zone, buf, sizeof (buf)) <= 0)
		(void) strlcpy(buf, "<unknown>", sizeof (buf));

	if (last == B_TRUE) {
		(void) printf("%s", buf);
	} else {
		(void) printf("%-*s", vlfp->vlf_size, buf);
	}
}

/* ARGSUSED */
static void
vlf_parse_zone(vndadm_list_field_t *vlfp, vnd_info_t *viip,
    boolean_t last)
{
	char buf[ZONENAME_MAX];

	if (getzonenamebyid(viip->vi_zone, buf, sizeof (buf)) <= 0)
		(void) strlcpy(buf, "<unknown>", sizeof (buf));

	(void) printf("%s", buf);
}

static vndadm_list_field_t vlf_tbl[] = {
	{ "name", "NAME", 16, vlf_print_link, vlf_parse_link },
	{ "datalink", "DATALINK", 16, vlf_print_datalink, vlf_parse_datalink },
	{ "zone", "ZONENAME", 32, vlf_print_zone, vlf_parse_zone },
	{ NULL }
};


static int
vndadm_list_f(vnd_info_t *viip, void *arg)
{
	int i;
	boolean_t found;
	vndadm_list_cb_t *vscp = arg;

	if (vscp->vsc_zid != ALL_ZONES && vscp->vsc_zid != viip->vi_zone)
		return (0);

	if (vscp->vsc_argc != 0) {
		found = B_FALSE;
		for (i = 0; i < vscp->vsc_argc; i++) {
			if (strcmp(viip->vi_name, vscp->vsc_argv[i]) == 0) {
				found = B_TRUE;
				break;
			}
		}
		if (found == B_FALSE)
			return (0);
		vscp->vsc_found++;
	}

	for (i = 0; i < VNDADM_LIST_NFIELDS && vscp->vsc_order[i] != -1; i++) {
		boolean_t last = i == vscp->vsc_last;
		if (vscp->vsc_parse == B_TRUE)
			vlf_tbl[vscp->vsc_order[i]].vlf_parse(
			    &vlf_tbl[vscp->vsc_order[i]], viip, last);
		else
			vlf_tbl[vscp->vsc_order[i]].vlf_print(
			    &vlf_tbl[vscp->vsc_order[i]], viip, last);

		if (last == B_FALSE)
			(void) printf("%s", vscp->vsc_delim);
	}
	(void) printf("\n");

	return (0);
}

static int
vndadm_list(int argc, char *argv[])
{
	int c, i, syserr;
	vnd_errno_t vnderr;
	boolean_t parse = B_FALSE;
	const char *zonename = NULL, *delim = NULL;
	char *fields = NULL;
	vndadm_list_cb_t vsc;

	optind = 0;
	while ((c = getopt(argc, argv, ":pd:o:z:")) != -1) {
		switch (c) {
		case 'p':
			parse = B_TRUE;
			break;
		case 'd':
			delim = optarg;
			break;
		case 'o':
			fields = optarg;
			break;
		case 'z':
			zonename = optarg;
			break;
		case ':':
			return (usage("-%c requires an operand\n", optopt));
		case '?':
			return (usage("unknown option: -%c\n", optopt));
		default:
			abort();
		}
	}

	argc -= optind;
	argv += optind;

	vsc.vsc_argc = argc;
	vsc.vsc_argv = argv;
	vsc.vsc_found = 0;
	if (zonename != NULL) {
		vsc.vsc_zid = getzoneidbyname(zonename);
		if (vsc.vsc_zid == -1) {
			vnd_warn("no such zone: %s\n", zonename);
			return (1);
		}
	} else {
		vsc.vsc_zid = ALL_ZONES;
	}

	/* Sanity check parseable related stuff */
	if (delim != NULL && parse == B_FALSE) {
		return (usage("-d cannot be used without -p\n"));
	}

	if (parse == B_TRUE && fields == NULL) {
		return (usage("-p cannot be used without -o\n"));
	}

	/* validate our fields, if any */
	if (fields != NULL) {
		char *c, *n;
		int floc = 0;

		c = fields;
		for (;;) {
			if (floc >= VNDADM_LIST_NFIELDS) {
				return (usage("too many fields specified "
				    "for -o\n"));
			}

			n = strchr(c, ',');
			if (n != NULL)
				*n = '\0';

			for (i = 0; i < VNDADM_LIST_NFIELDS; i++) {
				if (strcasecmp(c, vlf_tbl[i].vlf_name) == 0)
					break;
			}
			if (i == VNDADM_LIST_NFIELDS) {
				vnd_warn("invalid field for -o: %s\nvalid "
				    "fields are:", c);
				for (i = 0; i < VNDADM_LIST_NFIELDS; i++)
					vnd_warn(" %s", vlf_tbl[i].vlf_name);
				vnd_warn("\n");
				return (usage(NULL));
			}
			vsc.vsc_order[floc] = i;
			floc++;

			if (n == NULL)
				break;
			c = n + 1;
		}

		vsc.vsc_last = floc - 1;
		while (floc < VNDADM_LIST_NFIELDS)
			vsc.vsc_order[floc++] = -1;
	} else {
		vsc.vsc_order[0] = 0;
		vsc.vsc_order[1] = 1;
		vsc.vsc_order[2] = 2;
	}

	vsc.vsc_parse = parse;
	vsc.vsc_delim = delim;
	if (vsc.vsc_delim == NULL)
		vsc.vsc_delim = " ";

	if (vsc.vsc_parse != B_TRUE)  {
		for (i = 0; i < VNDADM_LIST_NFIELDS && vsc.vsc_order[i] != -1;
		    i++) {
			if (i + 1 == VNDADM_LIST_NFIELDS) {
				(void) printf("%s\n",
				    vlf_tbl[vsc.vsc_order[i]].vlf_header);
				continue;
			}
			(void) printf("%-*s ",
			    vlf_tbl[vsc.vsc_order[i]].vlf_size,
			    vlf_tbl[vsc.vsc_order[i]].vlf_header);
		}
	}

	if (vnd_walk(vndadm_list_f, &vsc, &vnderr, &syserr) != 0) {
		vnd_libwarn(vnderr, syserr, "failed to walk vnd links");
		return (1);
	}

	if (argc > 0 && vsc.vsc_found == 0) {
		vnd_warn("no links matched requested names\n");
		return (1);
	}

	return (0);
}

typedef struct vndadm_get {
	boolean_t vg_parse;
	const char *vg_delim;
	const char *vg_link;
	int vg_argc;
	char **vg_argv;
} vndadm_get_t;

static int
vndadm_get_cb(vnd_handle_t *vhp, vnd_prop_t prop, void *arg)
{
	boolean_t writeable;
	const char *perm;
	vndadm_get_t *vgp = arg;
	const char *name = vndadm_prop_to_name(prop);

	/* Verify if this is a prop we're supposed to print */
	if (vgp->vg_argc > 0) {
		int i;
		boolean_t found = B_FALSE;
		for (i = 0; i < vgp->vg_argc; i++) {
			if (strcmp(name, vgp->vg_argv[i]) == 0) {
				found = B_TRUE;
				break;
			}
		}
		if (found == B_FALSE)
			return (0);
	}

	if (vnd_prop_writeable(prop, &writeable) != 0)
		abort();

	perm = writeable ? "rw" : "r-";

	if (vgp->vg_parse == B_TRUE) {
		(void) printf("%s%s%s%s%s%s", vgp->vg_link, vgp->vg_delim,
		    name, vgp->vg_delim, perm, vgp->vg_delim);
	} else {
		(void) printf("%-13s %-16s %-5s ", vgp->vg_link, name, perm);
	}

	if (vndadm_propname_tbl[prop].vp_print != NULL) {
		if (vndadm_propname_tbl[prop].vp_print(vhp, prop) != 0)
			return (1);
	} else {
		(void) printf("-");
	}
	(void) printf("\n");
	return (0);
}

static int
vndadm_get(int argc, char *argv[])
{
	vnd_handle_t *vhp;
	boolean_t parse = B_FALSE;
	vndadm_get_t vg;
	int c, syserr;
	vnd_errno_t vnderr;
	const char *zonename = NULL, *delim = NULL;

	if (argc <= 0) {
		return (usage("get requires a link name\n"));
	}

	optind = 0;
	while ((c = getopt(argc, argv, ":pd:z:")) != -1) {
		switch (c) {
		case 'p':
			parse = B_TRUE;
			break;
		case 'd':
			delim = optarg;
			break;
		case 'z':
			zonename = optarg;
			break;
		case ':':
			return (usage("-%c requires an operand\n", optopt));
		case '?':
			return (usage("unknown option: -%c\n", optopt));
		default:
			abort();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		return (usage("missing required link\n"));
	}

	vhp = vnd_open(zonename, argv[0], &vnderr, &syserr);
	if (vhp == NULL) {
		vnd_libwarn(vnderr, syserr, "failed to open link: %s", argv[0]);
		return (1);
	}

	vg.vg_argc = argc - 1;
	vg.vg_argv = argv + 1;
	vg.vg_link = argv[0];
	vg.vg_parse = parse;
	vg.vg_delim = delim != NULL ? delim : " ";
	if (vg.vg_parse == B_FALSE)
		(void) printf("%-13s %-16s %-5s %s\n", "LINK", "PROPERTY",
		    "PERM", "VALUE");

	if (vnd_prop_iter(vhp, vndadm_get_cb, &vg) != 0)
		return (1);

	return (0);
}

static void
vndadm_get_usage(FILE *out)
{
	(void) fprintf(out,
	    "\tget:\t\t[-p] [-d delim] [-z zonename] link [prop]...\n");
}

static int
vndadm_set(int argc, char *argv[])
{
	vnd_handle_t *vhp;
	int c, i, syserr;
	vnd_errno_t vnderr;
	const char *zonename = NULL;

	optind = 0;
	while ((c = getopt(argc, argv, ":z:")) != -1) {
		switch (c) {
		case 'z':
			zonename = optarg;
			break;
		case ':':
			return (usage("-%c requires an operand\n", optopt));
		case '?':
			return (usage("unknown option: -%c\n", optopt));
		default:
			abort();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 2) {
		return (usage("missing arguments to set\n"));
	}

	vhp = vnd_open(zonename, argv[0], &vnderr, &syserr);
	if (vhp == NULL) {
		vnd_libwarn(vnderr, syserr, "failed to open link: %s", argv[0]);
		return (1);
	}

	for (i = 1; i < argc; i++) {
		char *eq, *key, *value;
		boolean_t writeable;
		vnd_prop_t prop;
		void *buf;
		size_t psize;
		int ret;

		key = argv[i];
		eq = strchr(key, '=');
		if (eq == NULL) {
			vnd_warn("invalid property name=value: %s\n", key);
			return (1);
		}
		*eq = '\0';
		value = eq + 1;
		if (*value == '\0') {
			vnd_warn("property value required for %s\n", key);
			return (1);
		}
		prop = vndadm_name_to_prop(key);
		if (prop == VND_PROP_MAX) {
			vnd_warn("unknown property: %s\n", key);
			return (1);
		}

		if (vnd_prop_writeable(prop, &writeable) != 0)
			abort();
		if (writeable != B_TRUE) {
			vnd_warn("property %s is read-only\n", key);
			return (1);
		}
		assert(vndadm_propname_tbl[prop].vp_parse != NULL);

		/*
		 * vp_parse functions should say what explicitly is invalid. We
		 * should indicate that the property failed.
		 */
		ret = vndadm_propname_tbl[prop].vp_parse(value, &buf, &psize);
		if (ret != 0) {
			vnd_warn("failed to set property %s\n", key);
			return (1);
		}

		ret = vnd_prop_set(vhp, prop, buf, psize);
		free(buf);
		if (ret != 0) {
			vnd_libwarn(vnd_errno(vhp), vnd_syserrno(vhp),
			    "failed to set property %s", key);
			return (1);
		}
	}

	return (0);
}

static void
vndadm_set_usage(FILE *out)
{
	(void) fprintf(out, "\tset:\t\t[-z zonename] link prop=val...\n");
}

typedef struct vnd_cmdtab {
	const char *vc_name;
	int (*vc_op)(int, char *[]);
	void (*vc_usage)(FILE *);
} vnd_cmdtab_t;

static vnd_cmdtab_t vnd_tab[] = {
	{ "create", vndadm_create, vndadm_create_usage },
	{ "destroy", vndadm_destroy, vndadm_destroy_usage },
	{ "list", vndadm_list, vndadm_list_usage },
	{ "get", vndadm_get, vndadm_get_usage },
	{ "set", vndadm_set, vndadm_set_usage },
	{ NULL, NULL }
};

static int
usage(const char *format, ...)
{
	vnd_cmdtab_t *tab;
	const char *help = "usage:  %s <subcommand> <args> ...\n";

	if (format != NULL) {
		va_list alist;

		va_start(alist, format);
		(void) fprintf(stderr, "%s: ", vnd_pname);
		(void) vfprintf(stderr, format, alist);
		va_end(alist);
	}
	(void) fprintf(stderr, help, vnd_pname);
	for (tab = vnd_tab; tab->vc_name != NULL; tab++)
		tab->vc_usage(stderr);

	return (2);
}

int
main(int argc, char *argv[])
{
	vnd_cmdtab_t *tab;

	vnd_pname = basename(argv[0]);
	if (argc < 2) {
		return (usage(NULL));
	}

	for (tab = vnd_tab; tab->vc_name != NULL; tab++) {
		if (strcmp(argv[1], tab->vc_name) == 0) {
			argc -= 2; argv += 2;
			assert(argc >= 0);
			return (tab->vc_op(argc, argv));
		}
	}

	return (usage("unknown sub-command '%s'\n", argv[1]));
}
