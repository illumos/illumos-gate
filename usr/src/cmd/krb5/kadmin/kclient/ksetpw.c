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
 * Portions Copyright 2021, Chris Fraire <cfraire@me.com>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <locale.h>
#include <netdb.h>
#include "k5-int.h"

#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

static char *whoami = NULL;

static void kt_add_entry(krb5_context ctx, krb5_keytab kt,
	const krb5_principal princ, const krb5_principal sprinc,
	krb5_enctype enctype, krb5_kvno kvno, const char *pw);

static krb5_error_code kt_remove_entries(krb5_context ctx, krb5_keytab kt,
	const krb5_principal princ);

static void usage();

int
main(int argc, char **argv)
{
	krb5_context ctx = NULL;
	krb5_error_code code = 0;
	krb5_enctype *enctypes = NULL;
	int enctype_count = 0;
	krb5_ccache cc = NULL;
	krb5_keytab kt = NULL;
	krb5_kvno kvno = 1;
	krb5_principal victim, salt = NULL;
	char *vprincstr, *ktname, *token, *lasts, *newpw;
	int c, result_code, i, len, nflag = 0;
	krb5_data result_code_string, result_string;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif /* TEXT_DOMAIN */

	(void) textdomain(TEXT_DOMAIN);

	/* Misc init stuff */
	(void) memset(&result_code_string, 0, sizeof (result_code_string));
	(void) memset(&result_string, 0, sizeof (result_string));

	whoami = argv[0];

	code = krb5_init_context(&ctx);
	if (code != 0) {
		com_err(whoami, code, gettext("krb5_init_context() failed"));
		exit(1);
	}

	while ((c = getopt(argc, argv, "v:c:k:e:ns:")) != -1) {
		switch (c) {
		case 'n':
			nflag++;
			break;
		case 'k':
			if (kt != NULL)
				usage();
			len = snprintf(NULL, 0, "WRFILE:%s", optarg) + 1;
			if ((ktname = malloc(len)) == NULL) {
				(void) fprintf(stderr,
				    gettext("Couldn't allocate memory\n"));
				exit(1);
			}
			(void) snprintf(ktname, len, "WRFILE:%s", optarg);
			if ((code = krb5_kt_resolve(ctx, ktname, &kt)) != 0) {
				com_err(whoami, code,
				    gettext("Couldn't open/create "
				    "keytab %s"), optarg);
				exit(1);
			}
			break;
		case 'c':
			if (cc != NULL)
				usage();
			if ((code = krb5_cc_resolve(ctx, optarg, &cc)) != 0) {
				com_err(whoami, code,
				    gettext("Couldn't open ccache %s"), optarg);
				exit(1);
			}
			break;
		case 'e':
			len = strlen(optarg);
			token = strtok_r(optarg, ",\t ", &lasts);

			if (token == NULL)
				usage();

			do {
				if (enctype_count++ == 0) {
					enctypes = malloc(sizeof (*enctypes));
				} else {
					enctypes = realloc(enctypes,
					    sizeof (*enctypes) * enctype_count);
				}
				if (enctypes == NULL) {
					(void) fprintf(stderr, gettext
					    ("Couldn't allocate memory"));
					exit(1);
				}
				code = krb5_string_to_enctype(token,
				    &enctypes[enctype_count - 1]);

				if (code != 0) {
					com_err(whoami, code, gettext("Unknown "
					    "or unsupported enctype %s"),
					    optarg);
					exit(1);
				}
			} while ((token = strtok_r(NULL, ",\t ", &lasts)) !=
			    NULL);
			break;
		case 'v':
			kvno = (krb5_kvno) atoi(optarg);
			break;
		case 's':
			vprincstr = optarg;
			code = krb5_parse_name(ctx, vprincstr, &salt);
			if (code != 0) {
				com_err(whoami, code,
				    gettext("krb5_parse_name(%s) failed"),
				    vprincstr);
				exit(1);
			}
			break;
		default:
			usage();
			break;
		}
	}

	if (nflag && enctype_count == 0)
		usage();

	if (nflag == 0 && cc == NULL &&
	    (code = krb5_cc_default(ctx, &cc)) != 0) {
		com_err(whoami, code, gettext("Could not find a ccache"));
		exit(1);
	}

	if (enctype_count > 0 && kt == NULL &&
	    (code = krb5_kt_default(ctx, &kt)) != 0) {
		com_err(whoami, code, gettext("No keytab specified"));
		exit(1);
	}

	if (argc != (optind + 1))
		usage();

	vprincstr = argv[optind];
	code = krb5_parse_name(ctx, vprincstr, &victim);
	if (code != 0) {
		com_err(whoami, code, gettext("krb5_parse_name(%s) failed"),
		    vprincstr);
		exit(1);
	}

	if (!isatty(fileno(stdin))) {
		char buf[PASS_MAX + 1];

		if (scanf("%" VAL2STR(PASS_MAX) "s", &buf) != 1) {
			(void) fprintf(stderr,
			    gettext("Couldn't read new password\n"));
			exit(1);
		}

		newpw = strdup(buf);
		if (newpw == NULL) {
			(void) fprintf(stderr,
			    gettext("Couldn't allocate memory\n"));
			exit(1);
		}
	} else {
		newpw = getpassphrase(gettext("Enter new password: "));
		if (newpw == NULL) {
			(void) fprintf(stderr,
			    gettext("Couldn't read new password\n"));
			exit(1);
		}

		newpw = strdup(newpw);
		if (newpw == NULL) {
			(void) fprintf(stderr,
			    gettext("Couldn't allocate memory\n"));
			exit(1);
		}
	}

	if (nflag == 0) {
		code = krb5_set_password_using_ccache(ctx, cc, newpw, victim,
		    &result_code, &result_code_string, &result_string);
		if (code != 0) {
			com_err(whoami, code,
			    gettext("krb5_set_password() failed"));
			exit(1);
		}
		krb5_cc_close(ctx, cc);

		(void) printf("Result: %.*s (%d) %.*s\n",
		    result_code == 0 ?
		    strlen("success") : result_code_string.length,
		    result_code == 0 ? "success" : result_code_string.data,
		    result_code,
		    result_string.length, result_string.data);

		if (result_code != 0) {
			(void) fprintf(stderr, gettext("Exiting...\n"));
			exit(result_code);
		}
	}

	if (enctype_count && (code = kt_remove_entries(ctx, kt, victim)))
		goto error;

	if (salt == NULL)
		salt = victim;

	for (i = 0; i < enctype_count; i++)
		kt_add_entry(ctx, kt, victim, salt, enctypes[i], kvno, newpw);

error:
	if (kt != NULL)
		krb5_kt_close(ctx, kt);

	return (code ? 1 : 0);
}

static
krb5_error_code
kt_remove_entries(krb5_context ctx, krb5_keytab kt, const krb5_principal princ)
{
	krb5_error_code code;
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;

	/*
	 * This is not a fatal error, we expect this to fail in the majority
	 * of cases (when clients are first initialized).
	 */
	code = krb5_kt_get_entry(ctx, kt, princ, 0, 0, &entry);
	if (code != 0) {
		com_err(whoami, code,
		    gettext("Could not retrieve entry in keytab"));
		return (0);
	}

	krb5_kt_free_entry(ctx, &entry);

	code = krb5_kt_start_seq_get(ctx, kt, &cursor);
	if (code != 0) {
		com_err(whoami, code, gettext("While starting keytab scan"));
		return (code);
	}

	while ((code = krb5_kt_next_entry(ctx, kt, &entry, &cursor)) == 0) {
		if (krb5_principal_compare(ctx, princ, entry.principal)) {

			code = krb5_kt_end_seq_get(ctx, kt, &cursor);
			if (code != 0) {
				com_err(whoami, code,
				    gettext("While temporarily "
				    "ending keytab scan"));
				return (code);
			}

			code = krb5_kt_remove_entry(ctx, kt, &entry);
			if (code != 0) {
				com_err(whoami, code,
				    gettext("While deleting entry "
				    "from keytab"));
				return (code);
			}

			code = krb5_kt_start_seq_get(ctx, kt, &cursor);
			if (code != 0) {
				com_err(whoami, code,
				    gettext("While restarting keytab scan"));
				return (code);
			}
		}

		krb5_kt_free_entry(ctx, &entry);
	}

	if (code && code != KRB5_KT_END) {
		com_err(whoami, code, gettext("While scanning keytab"));
		return (code);
	}

	if ((code = krb5_kt_end_seq_get(ctx, kt, &cursor))) {
		com_err(whoami, code, gettext("While ending keytab scan"));
		return (code);
	}

	return (0);
}

static
void
kt_add_entry(krb5_context ctx, krb5_keytab kt, const krb5_principal princ,
    const krb5_principal sprinc, krb5_enctype enctype, krb5_kvno kvno,
    const char *pw)
{
	krb5_keytab_entry *entry;
	krb5_data password, salt;
	krb5_keyblock key;
	krb5_error_code code;
	char enctype_name[100];

	if ((code = krb5_enctype_to_string(enctype, enctype_name,
	    sizeof (enctype_name)))) {
		com_err(whoami, code, gettext("Enctype %d has no name!"),
		    enctype);
		return;
	}
	if ((entry = (krb5_keytab_entry *) malloc(sizeof (*entry))) == NULL) {
		(void) fprintf(stderr, gettext("Couldn't allocate memory"));
		return;
	}

	(void) memset((char *)entry, 0, sizeof (*entry));

	password.length = strlen(pw);
	password.data = (char *)pw;

	if ((code = krb5_principal2salt(ctx, sprinc, &salt)) != 0) {
		com_err(whoami, code,
		    gettext("Could not compute salt for %s"), enctype_name);
		return;
	}

	code = krb5_c_string_to_key(ctx, enctype, &password, &salt, &key);

	if (code != 0) {
		com_err(whoami, code,
		    gettext("Could not convert to key for %s"), enctype_name);
		krb5_xfree(salt.data);
		return;
	}

	(void) memcpy(&entry->key, &key, sizeof (krb5_keyblock));
	entry->vno = kvno;
	entry->principal = princ;

	if ((code = krb5_kt_add_entry(ctx, kt, entry)) != 0) {
		com_err(whoami, code,
		    gettext("Could not add entry to keytab"));
	}
}

static
void
usage()
{
	(void) fprintf(stderr, gettext("Usage: %s [-c ccache] [-k keytab] "
	    "[-e enctype_list] [-s salt_name] [-n] princ\n"), whoami);
	(void) fprintf(stderr,
	    gettext("\t-n\tDon't set the principal's password\n"));
	(void) fprintf(stderr, gettext("\tenctype_list is a comma or whitespace"
	    " separated list\n"));
	(void) fprintf(stderr, gettext("\tIf -n is used then -k and -e must be "
	    "used\n"));

	exit(1);
}
