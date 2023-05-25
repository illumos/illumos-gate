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
 * Copyright 2022 RackTop Systems, Inc.
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <smbsrv/libsmb.h>
#include <ofmt.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <time.h>
#include <upanic.h>
#include "smbadm.h"

/*
 * Share types for shiX_type fields - duplicated from smb.h
 * Don't want to pull that in, and these are "carved in stone"
 * (from the SMB protocol definitions)
 */
#ifndef _SHARE_TYPES_DEFINED_
#define	_SHARE_TYPES_DEFINED_
#define	STYPE_DISKTREE		0x00000000
#define	STYPE_PRINTQ		0x00000001
#define	STYPE_DEVICE		0x00000002
#define	STYPE_IPC		0x00000003
#define	STYPE_MASK		0x0000000F
#endif /* _SHARE_TYPES_DEFINED_ */

#define	MINS		(60U)
#define	HRS		(60 * MINS)
#define	DAYS		(24 * HRS)
#define	TIME_FMT	"%F %T %Z"

#define	_(x) gettext(x)

struct flag_tbl {
	uint32_t	flag;
	const char	*name;
};

typedef enum user_field {
	UF_SESS_ID,
	UF_DOMAIN,
	UF_ACCOUNT,
	UF_USER,
	UF_UID,
	UF_WORKSTATION,
	UF_IP,
	UF_OS,
	UF_LOGON_TIME,
	UF_AGE,
	UF_NUMOPEN,
	UF_FLAGS,
} user_field_t;

typedef enum tree_field {
	TF_ID,
	TF_TYPE,
	TF_NUMOPEN,
	TF_NUMUSERS,
	TF_TIME,
	TF_AGE,
	TF_USERNAME,
	TF_SHARE,
} tree_field_t;

typedef enum netfileinfo_field {
	NFIF_FID,
	NFIF_UNIQID,
	NFIF_PERMS,
	NFIF_NUMLOCKS,
	NFIF_PATH,
	NFIF_USERNAME,
} netfileinfo_field_t;

static ofmt_handle_t cmd_create_handle(int, char **, const char *,
    ofmt_field_t *);

static boolean_t fmt_user(ofmt_arg_t *, char *, uint_t);
static boolean_t fmt_tree(ofmt_arg_t *, char *, uint_t);
static boolean_t fmt_netfileinfo(ofmt_arg_t *, char *, uint_t);

static void print_str(const char *restrict, char *restrict, uint_t);
static void print_u32(uint32_t, char *, uint_t);
static void print_age(time_t, char *, uint_t);
static void print_time(time_t, const char *, char *, uint_t);
static void print_flags(struct flag_tbl *, size_t, uint32_t, char *, uint_t);
static void print_perms(struct flag_tbl *, size_t, uint32_t, char *, uint_t);

static ofmt_field_t smb_user_fields[] = {
	{ "ID",		4,	UF_SESS_ID,	fmt_user },
	{ "DOMAIN",	32,	UF_DOMAIN,	fmt_user },
	{ "ACCT",	16,	UF_ACCOUNT,	fmt_user },
	{ "USER",	32,	UF_USER,	fmt_user },
	{ "UID",	12,	UF_UID,		fmt_user },
	{ "COMPUTER",	16,	UF_WORKSTATION,	fmt_user },
	{ "IP",		15,	UF_IP,		fmt_user },
	{ "OS",		8,	UF_OS,		fmt_user },
	{ "LOGON",	24,	UF_LOGON_TIME,	fmt_user },
	{ "AGE",	16,	UF_AGE,		fmt_user },
	{ "NOPEN",	5,	UF_NUMOPEN,	fmt_user },
	{ "FLAGS",	12,	UF_FLAGS,	fmt_user },
	{ NULL,		0,	0,		NULL }
};

static const char default_user_fields[] = "IP,USER,NOPEN,AGE,FLAGS";

struct flag_tbl user_flag_tbl[] = {
	{ SMB_ATF_GUEST, "GUEST" },
	{ SMB_ATF_ANON, "ANON" },
	{ SMB_ATF_ADMIN, "ADMIN" },
	{ SMB_ATF_POWERUSER, "POWERUSER" },
	{ SMB_ATF_BACKUPOP, "BACKUPOP" },
};

static ofmt_field_t smb_tree_fields[] = {
	{ "ID",		4,	TF_ID,		fmt_tree },
	{ "TYPE",	6,	TF_TYPE,	fmt_tree },
	{ "NOPEN",	6,	TF_NUMOPEN,	fmt_tree },
	{ "NUSER",	6,	TF_NUMUSERS,	fmt_tree },
	{ "TIME",	24,	TF_TIME,	fmt_tree },
	{ "AGE",	12,	TF_AGE,		fmt_tree },
	{ "USER",	32,	TF_USERNAME,	fmt_tree },
	{ "SHARE",	16,	TF_SHARE,	fmt_tree },
	{ NULL,		0,	0,		NULL }
};

static const char default_tree_fields[] = "TYPE,SHARE,USER,NOPEN,AGE";

static ofmt_field_t smb_netfileinfo_fields[] = {
	{ "ID",		4,	NFIF_FID,	fmt_netfileinfo },
	{ "UNIQID",	8,	NFIF_UNIQID,	fmt_netfileinfo },
	{ "PERM",	15,	NFIF_PERMS,	fmt_netfileinfo },
	{ "NLOCK",	6,	NFIF_NUMLOCKS,	fmt_netfileinfo },
	{ "PATH",	32,	NFIF_PATH,	fmt_netfileinfo },
	{ "USER",	16,	NFIF_USERNAME,	fmt_netfileinfo },
	{ NULL,		0,	0,		NULL }
};

static const char default_netfileinfo_fields[] = "UNIQID,PATH,USER,NLOCK,PERM";

/*
 * Flags are the same as "ls -V" and chmod ACLs:
 * eg:  everyone@:rwxpdDaARWcCos:fd----I:allow
 * See libsec:acltext.c
 */
static struct flag_tbl nfi_perm_tbl[] = {
	{ ACE_READ_DATA,		"r" },
	{ ACE_WRITE_DATA,		"w" },
	{ ACE_EXECUTE,			"x" },
	{ ACE_APPEND_DATA,		"p" },
	{ ACE_DELETE,			"d" },
	{ ACE_DELETE_CHILD,		"D" },
	{ ACE_READ_ATTRIBUTES,		"a" },
	{ ACE_WRITE_ATTRIBUTES,		"A" },
	{ ACE_READ_NAMED_ATTRS,		"R" },
	{ ACE_WRITE_NAMED_ATTRS,	"W" },
	{ ACE_READ_ACL,			"c" },
	{ ACE_WRITE_ACL,		"C" },
	{ ACE_WRITE_OWNER,		"o" },
	{ ACE_SYNCHRONIZE,		"s" },
};

static int do_enum(smb_svcenum_t *, ofmt_handle_t);
static void ofmt_fatal(ofmt_handle_t, ofmt_field_t *, ofmt_status_t)
    __NORETURN;
static void fatal(const char *, ...) __NORETURN;

time_t		now;
boolean_t	opt_p;
boolean_t	opt_x;

int
cmd_list_sess(int argc, char **argv)
{
	ofmt_handle_t	hdl;
	smb_svcenum_t	req = {
		.se_type = SMB_SVCENUM_TYPE_USER,
		.se_level = 1,
		.se_nlimit = UINT32_MAX,
	};
	int rc;

	hdl = cmd_create_handle(argc, argv, default_user_fields,
	    smb_user_fields);
	rc = do_enum(&req, hdl);
	ofmt_close(hdl);
	return (rc);
}

int
cmd_list_trees(int argc, char **argv)
{
	ofmt_handle_t	hdl;
	smb_svcenum_t	req = {
		.se_type = SMB_SVCENUM_TYPE_TREE,
		.se_level = 1,
		.se_nlimit = UINT32_MAX,
	};
	int rc;

	hdl = cmd_create_handle(argc, argv, default_tree_fields,
	    smb_tree_fields);
	rc = do_enum(&req, hdl);
	ofmt_close(hdl);
	return (rc);
}

int
cmd_list_ofiles(int argc, char **argv)
{
	ofmt_handle_t	hdl;
	smb_svcenum_t	req = {
		.se_type = SMB_SVCENUM_TYPE_FILE,
		.se_level = 1,
		.se_nlimit = UINT32_MAX,
	};
	int rc;

	hdl = cmd_create_handle(argc, argv, default_netfileinfo_fields,
	    smb_netfileinfo_fields);
	rc = do_enum(&req, hdl);
	ofmt_close(hdl);
	return (rc);
}

static ofmt_handle_t
cmd_create_handle(int argc, char **argv, const char *def, ofmt_field_t *templ)
{
	const char	*fields = def;
	ofmt_handle_t	hdl;
	ofmt_status_t	status;
	uint_t		flags = 0;
	int		c;

	while ((c = getopt(argc, argv, "Ho:px")) != -1) {
		switch (c) {
		case 'H':
			flags |= OFMT_NOHEADER;
			break;
		case 'o':
			fields = optarg;
			break;
		case 'p':
			opt_p = B_TRUE;
			flags |= OFMT_PARSABLE;
			break;
		case 'x':
			opt_x = B_TRUE;
			break;
		case '?':
			/* Note: getopt prints an error for us. */
			return (NULL);
		}
	}

	status = ofmt_open(fields, templ, flags, 0, &hdl);
	if (status != OFMT_SUCCESS)
		ofmt_fatal(hdl, templ, status);

	return (hdl);
}

int
cmd_close_ofile(int argc, char **argv)
{
	uint_t errs = 0;

	if (argc < 2) {
		fprintf(stderr, _("Missing file id\n"));
		return (2);
	}

	for (int i = 1; i < argc; i++) {
		unsigned long ul;
		int rc;

		errno = 0;
		ul = strtoul(argv[i], NULL, 0);
		if (errno != 0) {
			fprintf(stderr, _("Invalid file id '%s'"), argv[i]);
			return (2);
		}
#ifdef _LP64
		if (ul > UINT32_MAX) {
			fprintf(stderr, _("File id %lu too large"), ul);
			return (2);
		}
#endif

		/*
		 * See SMB_IOC_FILE_CLOSE (ioc.uniqid)
		 * and smb_server_file_close()
		 */
		rc = smb_kmod_file_close((uint32_t)ul);
		if (rc != 0) {
			/*
			 * Since the user can specify the fid as a decimal
			 * or hex value, we use the string they gave us so
			 * the value displayed matches what we were given.
			 */
			warnx(_("Closing fid %s failed: %s"), argv[i],
			    strerror(rc));
			errs++;
		}
	}

	if (errs > 0)
		return (1);
	return (0);
}

int
cmd_close_sess(int argc, char **argv)
{
	const char *client;
	const char *user = NULL;
	int rc;

	if (argc < 2) {
		fprintf(stderr, _("clientname and username missing\n"));
		return (2);
	}
	client = argv[1];
	if (argc > 2) {
		user = argv[2];
	}

	/*
	 * See SMB_IOC_SESSION_CLOSE (ioc.client, ioc.username)
	 * and smb_server_session_close().  The "client" part
	 * can be EITHER the "workstation" or the IP address,
	 * as shown in the "COMPUTER" and "IP" fields in the
	 * output of "list-sessions".   The (optional) "user"
	 * part is as shown in "USER" part of that output.
	 */
	rc = smb_kmod_session_close(client, user);
	if (rc != 0) {
		rc = 1;
	}
	return (rc);
}

static boolean_t
fmt_user(ofmt_arg_t *arg, char *buf, uint_t buflen)
{
	smb_netuserinfo_t	*ui = arg->ofmt_cbarg;
	user_field_t		field = (user_field_t)arg->ofmt_id;

	switch (field) {
	case UF_SESS_ID:
		(void) snprintf(buf, buflen, "%" PRIu64, ui->ui_session_id);
		break;
	case UF_DOMAIN:
		print_str(ui->ui_domain, buf, buflen);
		break;
	case UF_ACCOUNT:
		print_str(ui->ui_account, buf, buflen);
		break;
	case UF_USER:
		(void) snprintf(buf, buflen, "%s\\%s", ui->ui_domain,
		    ui->ui_account);
		break;
	case UF_UID:
		VERIFY3U(arg->ofmt_width, <, INT_MAX);
		(void) snprintf(buf, buflen, "%u", ui->ui_posix_uid);
		break;
	case UF_WORKSTATION:
		print_str(ui->ui_workstation, buf, buflen);
		break;
	case UF_IP:
		(void) smb_inet_ntop(&ui->ui_ipaddr, buf, buflen);
		break;
	case UF_OS:
		/* XXX: Lookup string value */
		(void) snprintf(buf, buflen, "%" PRId32, ui->ui_native_os);
		break;
	case UF_LOGON_TIME:
		print_time(ui->ui_logon_time, TIME_FMT, buf, buflen);
		break;
	case UF_AGE:
		print_age(now - ui->ui_logon_time, buf, buflen);
		break;
	case UF_NUMOPEN:
		print_u32(ui->ui_numopens, buf, buflen);
		break;
	case UF_FLAGS:
		print_flags(user_flag_tbl, ARRAY_SIZE(user_flag_tbl),
		    ui->ui_flags, buf, buflen);
		break;
	default:
		fatal("%s: invalid field %d", __func__, field);
	}

	return (B_TRUE);
}

static boolean_t
fmt_tree_type(uint32_t type, char *buf, uint_t buflen)
{
	switch (type & STYPE_MASK) {
	case STYPE_DISKTREE:
		(void) strlcpy(buf, "DISK", buflen);
		break;
	case STYPE_PRINTQ:
		(void) strlcpy(buf, "PRINTQ", buflen);
		break;
	case STYPE_DEVICE:
		(void) strlcpy(buf, "DEVICE", buflen);
		break;
	case STYPE_IPC:
		(void) strlcpy(buf, "IPC", buflen);
		break;
	default:
		(void) snprintf(buf, buflen, "%" PRIx32, type & STYPE_MASK);
		break;
	}

	return (B_TRUE);
}

static boolean_t
fmt_tree(ofmt_arg_t *arg, char *buf, uint_t buflen)
{
	smb_netconnectinfo_t	*nc = arg->ofmt_cbarg;
	tree_field_t		field = (tree_field_t)arg->ofmt_id;

	switch (field) {
	case TF_ID:
		(void) snprintf(buf, buflen, "%" PRIu32, nc->ci_id);
		break;
	case TF_TYPE:
		return (fmt_tree_type(nc->ci_type, buf, buflen));
	case TF_NUMOPEN:
		print_u32(nc->ci_numopens, buf, buflen);
		break;
	case TF_NUMUSERS:
		print_u32(nc->ci_numusers, buf, buflen);
		break;
	case TF_TIME:
		print_time(now - nc->ci_time, TIME_FMT, buf, buflen);
		break;
	case TF_AGE:
		print_age(nc->ci_time, buf, buflen);
		break;
	case TF_USERNAME:
		print_str(nc->ci_username, buf, buflen);
		break;
	case TF_SHARE:
		print_str(nc->ci_share, buf, buflen);
		break;
	default:
		fatal("%s: invalid field %d", __func__, field);
	}

	return (B_TRUE);
}

static boolean_t
fmt_netfileinfo(ofmt_arg_t *arg, char *buf, uint_t buflen)
{
	smb_netfileinfo_t	*fi = arg->ofmt_cbarg;
	netfileinfo_field_t	field = (netfileinfo_field_t)arg->ofmt_id;

	switch (field) {
	case NFIF_FID:
		(void) snprintf(buf, buflen, "%" PRIu16, fi->fi_fid);
		break;
	case NFIF_UNIQID:
		(void) snprintf(buf, buflen, "%" PRIu32, fi->fi_uniqid);
		break;
	case NFIF_PERMS:
		print_perms(nfi_perm_tbl, ARRAY_SIZE(nfi_perm_tbl),
		    fi->fi_permissions, buf, buflen);
		break;
	case NFIF_NUMLOCKS:
		print_u32(fi->fi_numlocks, buf, buflen);
		break;
	case NFIF_PATH:
		print_str(fi->fi_path, buf, buflen);
		break;
	case NFIF_USERNAME:
		print_str(fi->fi_username, buf, buflen);
		break;
	default:
		fatal("%s: invalid field %d", __func__, field);
	}

	return (B_TRUE);
}

static int
do_enum(smb_svcenum_t *req, ofmt_handle_t hdl)
{
	smb_netsvc_t		*ns;
	smb_netsvcitem_t	*item;
	uint32_t		n = 0;
	int rc;

	if (hdl == NULL)
		return (2);	/* exit (2) -- usage */
	now = time(NULL);

	for (;;) {
		req->se_nskip = n;

		ns = smb_kmod_enum_init(req);
		if (ns == NULL) {
			fprintf(stderr, _("SMB enum initialization failure"));
			return (1);
		}

		rc = smb_kmod_enum(ns);
		if (rc != 0) {
			/*
			 * When the SMB service is not running, expect ENXIO.
			 */
			if (rc == ENXIO) {
				fprintf(stderr,
				    _("Kernel SMB server not running"));
				return (1);
			}
			fprintf(stderr, _("SMB enumeration call failed: %s"),
			    strerror(rc));
			return (1);
		}

		if (list_is_empty(&ns->ns_list))
			break;

		for (item = list_head(&ns->ns_list); item != NULL;
		    item = list_next(&ns->ns_list, item)) {
			ofmt_print(hdl, &item->nsi_un);
			n++;
		}

		smb_kmod_enum_fini(ns);
	}
	return (0);
}

static void
print_str(const char *restrict src, char *restrict buf, uint_t buflen)
{
	if (src == NULL) {
		buf[0] = '\0';
		return;
	}
	(void) strlcpy(buf, src, buflen);
}

static void
print_u32(uint32_t val, char *buf, uint_t buflen)
{
	const char *fmt = opt_p ? "%" PRIu32 : "%'" PRIu32;

	(void) snprintf(buf, buflen, fmt, val);
}

static void
print_age(time_t amt, char *buf, uint_t buflen)
{
	uint32_t days = 0, hours = 0, mins = 0;

	if (opt_p) {
		(void) snprintf(buf, buflen, "%" PRId64, (int64_t)amt);
		return;
	}

	if (amt >= DAYS) {
		days = amt / DAYS;
		amt %= DAYS;
	}
	if (amt >= HRS) {
		hours = amt / HRS;
		amt %= HRS;
	}
	if (amt >= MINS) {
		mins = amt / MINS;
		amt %= MINS;
	}

	if (days > 0) {
		int n = snprintf(buf, buflen, "%" PRIu32 " days%s",
		    days, (hours > 0 || mins > 0 || amt > 0) ? ", " : "");

		VERIFY3U(buflen, >, n);

		buf += n;
		buflen -= n;
	}

	(void) snprintf(buf, buflen, "%02" PRIu32 ":%02" PRIu32 ":%02" PRIu32,
	    hours, mins, amt);
}

static void
print_time(time_t when, const char *fmt, char *buf, uint_t buflen)
{
	const struct tm *tm;

	if (opt_p) {
		(void) snprintf(buf, buflen, "%" PRId64, (int64_t)when);
		return;
	}

	tm = localtime(&when);
	(void) strftime(buf, buflen - 1, fmt, tm);
}

static void
print_flags(struct flag_tbl *tbl, size_t nent, uint32_t val, char *buf,
    uint_t buflen)
{
	uint_t n = 0;
	uint_t i;

	if (opt_x) {
		(void) snprintf(buf, buflen, "%" PRIx32, val);
		return;
	}

	for (i = 0; i < nent; i++) {
		if ((val & tbl[i].flag) == 0)
			continue;
		if (n > 0)
			(void) strlcat(buf, ",", buflen);
		(void) strlcat(buf, tbl[i].name, buflen);
		n++;
	}

	if (n == 0)
		(void) strlcat(buf, "-", buflen);
}

static void
print_perms(struct flag_tbl *tbl, size_t nent, uint32_t val, char *buf,
    uint_t buflen)
{
	uint_t n = 0;
	uint_t i;

	if (opt_x) {
		(void) snprintf(buf, buflen, "%" PRIx32, val);
		return;
	}

	for (i = 0; i < nent; i++) {
		if ((val & tbl[i].flag) == 0) {
			(void) strlcat(buf, "-", buflen);
		} else {
			(void) strlcat(buf, tbl[i].name, buflen);
		}
		n++;
	}
}

__NORETURN static void
ofmt_fatal(ofmt_handle_t hdl, ofmt_field_t *templ, ofmt_status_t status)
{
	char buf[OFMT_BUFSIZE];
	char *msg = ofmt_strerror(hdl, status, buf, sizeof (buf));

	fprintf(stderr, _("ofmt error: %s\n"), msg);

	if (status == OFMT_EBADFIELDS ||
	    status == OFMT_ENOFIELDS) {
		ofmt_field_t *f = templ;
		fprintf(stderr, _("Valid fields are: "));
		while (f->of_name != NULL) {
			fprintf(stderr, "%s", f->of_name);
			f++;
			if (f->of_name != NULL)
				fprintf(stderr, ",");
		}
		fprintf(stderr, "\n");
	}

	exit(EXIT_FAILURE);
}

__NORETURN static void
fatal(const char *msg, ...)
{
	char buf[128];
	va_list ap;
	size_t len;

	va_start(ap, msg);
	(void) vsnprintf(buf, sizeof (buf), msg, ap);
	va_end(ap);

	len = strlen(buf);
	upanic(buf, len);
}
