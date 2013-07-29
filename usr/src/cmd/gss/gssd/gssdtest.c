/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Test client for gssd.  This program is not shipped on the binary
 * release.
 */

#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include "gssd.h"
#include <rpc/rpc.h>

#define	_KERNEL
#include <gssapi/gssapi.h>
#undef	_KERNEL

int gss_major_code;
int gss_minor_code;

int init_sec_context_phase = 0;
int accept_sec_context_phase = 0;

gss_ctx_id_t    initiator_context_handle;
gss_ctx_id_t    acceptor_context_handle;
gss_cred_id_t   acceptor_credentials;
gss_buffer_desc init_token_buffer;
gss_buffer_desc accept_token_buffer;
gss_buffer_desc delete_token_buffer;
gss_buffer_desc message_buffer;
gss_buffer_desc msg_token;

#define	LOOP_COUNTER  100
#define	GSS_KRB5_MECH_OID "1.2.840.113554.1.2.2"
#define	GSS_DUMMY_MECH_OID "1.3.6.1.4.1.42.2.26.1.2"
#ifdef _KERNEL
#define	OCTAL_MACRO "%03o."
#define	MALLOC(n) kmem_alloc((n), KM_SLEEP)
#define	CALLOC(n, s) kmem_zalloc((n)*(s), KM_SLEEP)
#define	FREE(x, n) kmem_free((x), (n))
#define	memcpy(dst, src, n) bcopy((src), (dst), (n))
#define	fprintf(s, m) printf(m)
#define	isspace(s) ((s) == ' ' || (s) == '\t' || (s) == '\n' || \
		(s) == '\r' || (s) == '\v' || (s) == '\f')

static char *strdup(const char *s)
{
	int len = strlen(s);
	char *new = MALLOC(len+1);
	strcpy(new, s);
	return (new);
}

#else /* !_KERNEL */
#define	OCTAL_MACRO "%03.3o."
#define	MALLOC(n) malloc(n)
#define	CALLOC(n, s) calloc((n), (s))
#define	FREE(x, n) free(x)
#endif /* _KERNEL */

static gss_OID gss_str2oid(char *);
static char * gss_oid2str(gss_OID);
static void instructs();
static void usage();
static int parse_input_line(char *, int *, char ***);
extern uid_t getuid();

static void _gss_init_sec_context(int, char **);
static void _gss_acquire_cred(int, char **);
static void _gss_add_cred(int, char **);
static void _gss_sign(int, char **);
static void _gss_release_cred(int, char **);
static void _gss_accept_sec_context(int, char **);
static void _gss_process_context_token(int, char **);
static void _gss_delete_sec_context(int, char **);
static void _gss_context_time(int, char **);
static void _gss_verify(int, char **);
static void _gss_seal(int, char **);
static void _gss_unseal(int, char **);
static void _gss_display_status(int, char **);
static void _gss_indicate_mechs(int, char **);
static void _gss_inquire_cred(int, char **);
static void _gssd_expname_to_unix_cred(int, char **);
static void _gssd_name_to_unix_cred(int, char **);
static void _gssd_get_group_info(int, char **);

static int do_gssdtest(char *buf);


#ifndef _KERNEL
static int read_line(char *buf, int size)
{
	int len;

	/* read the next line. If cntl-d, return with zero char count */
	printf(gettext("\n> "));

	if (fgets(buf, size, stdin) == NULL)
		return (0);

	len = strlen(buf);
	buf[--len] = '\0';
	return (len);
}

int
main()
{
	char buf[512];
	int len, ret;

	/* Print out usage and instructions to start off the session */

	instructs();
	usage();

	/*
	 * Loop, repeatedly calling parse_input_line() to get the
	 * next line and parse it into argc and argv. Act on the
	 * arguements found on the line.
	 */

	do {
		len = read_line(buf, 512);
		if (len)
			ret = do_gssdtest(buf);
	} while (len && !ret);

	return (0);
}
#endif /* !_KERNEL */

static int
do_gssdtest(char *buf)
{
	int argc, seal_argc;
	int i;
	char **argv, **argv_array;

	char *cmd;
	char *seal_ini_array [] = { "initiator", " Hello"};
	char *seal_acc_array [] = { "acceptor", " Hello"};
	char *unseal_acc_array [] = {"acceptor"};
	char *unseal_ini_array [] = {"initiator"};
	char *delet_acc_array [] = {"acceptor"};
	char *delet_ini_array [] = {"initiator"};

	argv = 0;

	if (parse_input_line(buf, &argc, &argv) == 0) {
		printf(gettext("\n"));
		return (1);
	}

	if (argc == 0) {
		usage();
		/*LINTED*/
		FREE(argv_array, (argc+1)*sizeof (char *));
		return (0);
	}

	/*
	 * remember argv_array address, which is memory calloc'd by
	 * parse_input_line, so it can be free'd at the end of the loop.
	 */

	argv_array = argv;

	cmd = argv[0];

	argc--;
	argv++;

	if (strcmp(cmd, "gss_loop") == 0 ||
	    strcmp(cmd, "loop") == 0) {

		if (argc < 1) {
			usage();
			FREE(argv_array, (argc+2) * sizeof (char *));
			return (0);
		}
		for (i = 0; i < LOOP_COUNTER; i++) {
			printf(gettext("Loop Count is %d \n"), i);
			/*
			 * if (i > 53)
			 * 	printf ("Loop counter is greater than 55\n");
			 */
			_gss_acquire_cred(argc, argv);
			_gss_init_sec_context(argc, argv);
			_gss_accept_sec_context(0, argv);
			_gss_init_sec_context(argc, argv);

			seal_argc = 2;
			_gss_seal(seal_argc, seal_ini_array);
			seal_argc = 1;
			_gss_unseal(seal_argc, unseal_acc_array);
			seal_argc = 2;
			_gss_seal(seal_argc, seal_acc_array);
			seal_argc = 1;
			_gss_unseal(seal_argc, unseal_ini_array);
			seal_argc = 2;
			_gss_sign(seal_argc, seal_ini_array);
			seal_argc = 1;
			_gss_verify(seal_argc, unseal_acc_array);
			seal_argc = 2;
			_gss_sign(seal_argc, seal_acc_array);
			seal_argc = 1;
			_gss_verify(seal_argc, unseal_ini_array);
			_gss_delete_sec_context(argc, delet_acc_array);
			_gss_delete_sec_context(argc, delet_ini_array);
		}
	}
	if (strcmp(cmd, "gss_all") == 0 ||
	    strcmp(cmd, "all") == 0) {
		_gss_acquire_cred(argc, argv);
		_gss_init_sec_context(argc, argv);
		_gss_accept_sec_context(0, argv);
		_gss_init_sec_context(argc, argv);

		seal_argc = 2;
		_gss_seal(seal_argc, seal_acc_array);
		seal_argc = 1;
		_gss_unseal(seal_argc, unseal_ini_array);
		seal_argc = 2;
		_gss_seal(seal_argc, seal_ini_array);
		seal_argc = 1;
		_gss_unseal(seal_argc, unseal_acc_array);
		seal_argc = 2;
		_gss_sign(seal_argc, seal_ini_array);
		seal_argc = 1;
		_gss_verify(seal_argc, unseal_acc_array);
		seal_argc = 2;
		_gss_sign(seal_argc, seal_acc_array);
		seal_argc = 1;
		_gss_verify(seal_argc, unseal_ini_array);

	}
	if (strcmp(cmd, "gss_acquire_cred") == 0 ||
	    strcmp(cmd, "acquire") == 0) {
		_gss_acquire_cred(argc, argv);
		if (argc == 1)
			_gss_add_cred(argc, argv);
	}

	else if (strcmp(cmd, "gss_release_cred") == 0 ||
		strcmp(cmd, "release") == 0)
		_gss_release_cred(argc, argv);
	else if (strcmp(cmd, "gss_init_sec_context") == 0 ||
		strcmp(cmd, "init") == 0)
		_gss_init_sec_context(argc, argv);
	else if (strcmp(cmd, "gss_accept_sec_context") == 0 ||
		strcmp(cmd, "accept") == 0)
		_gss_accept_sec_context(argc, argv);
	else if (strcmp(cmd, "gss_process_context_token") == 0 ||
		strcmp(cmd, "process") == 0)
		_gss_process_context_token(argc, argv);
	else if (strcmp(cmd, "gss_delete_sec_context") == 0 ||
		strcmp(cmd, "delete") == 0)
		_gss_delete_sec_context(argc, argv);
	else if (strcmp(cmd, "gss_context_time") == 0 ||
		strcmp(cmd, "time") == 0)
		_gss_context_time(argc, argv);
	else if (strcmp(cmd, "gss_sign") == 0 ||
		strcmp(cmd, "sign") == 0)
		_gss_sign(argc, argv);
	else if (strcmp(cmd, "gss_verify") == 0 ||
		strcmp(cmd, "verify") == 0)
		_gss_verify(argc, argv);
	else if (strcmp(cmd, "gss_seal") == 0 ||
		strcmp(cmd, "seal") == 0)
		_gss_seal(argc, argv);
	else if (strcmp(cmd, "gss_unseal") == 0 ||
		strcmp(cmd, "unseal") == 0)
		_gss_unseal(argc, argv);
	else if (strcmp(cmd, "gss_display_status") == 0||
		strcmp(cmd, "status") == 0)
		_gss_display_status(argc, argv);
	else if (strcmp(cmd, "gss_indicate_mechs") == 0 ||
		strcmp(cmd, "indicate") == 0)
		_gss_indicate_mechs(argc, argv);
	else if (strcmp(cmd, "gss_inquire_cred") == 0 ||
		strcmp(cmd, "inquire") == 0)
		_gss_inquire_cred(argc, argv);
	else if (strcmp(cmd, "expname2unixcred") == 0 ||
		strcmp(cmd, "gsscred_expname_to_unix_cred") == 0)
		_gssd_expname_to_unix_cred(argc, argv);
	else if (strcmp(cmd, "name2unixcred") == 0 ||
		strcmp(cmd, "gsscred_name_to_unix_cred") == 0)
		_gssd_name_to_unix_cred(argc, argv);
	else if (strcmp(cmd, "grpinfo") == 0 ||
		strcmp(cmd, "gss_get_group_info") == 0)
		_gssd_get_group_info(argc, argv);
	else if (strcmp(cmd, "exit") == 0) {
		printf(gettext("\n"));
		FREE(argv_array, (argc+2) * sizeof (char *));
		return (1);
	} else
		usage();

	/* free argv array */

	FREE(argv_array, (argc+2) * sizeof (char *));
	return (0);
}

static void
_gss_acquire_cred(argc, argv)
int argc;
char **argv;
{

	OM_UINT32 status, minor_status;
	gss_buffer_desc name;
	gss_name_t desired_name = (gss_name_t) 0;
	OM_uint32 time_req;
	gss_OID_set_desc desired_mechs_desc;
	gss_OID_set desired_mechs = &desired_mechs_desc;
	int cred_usage;
	gss_OID_set actual_mechs = GSS_C_NULL_OID_SET;
	gss_OID_set inquire_mechs = GSS_C_NULL_OID_SET;
	OM_UINT32 time_rec;
	char * string;
	char * inq_string;
	uid_t uid;
	gss_OID mech_type;

	/*
	 * First set up the command line independent input arguments.
	 */

	time_req = (OM_uint32) 0;
	cred_usage = GSS_C_ACCEPT;
	uid = getuid();

	/* Parse the command line for the variable input arguments */

	if (argc == 0) {
		usage();
		return;
	}

	/*
	 * Get the name of the principal.
	 */

	name.length = strlen(argv[0])+1;
	name.value = argv[0];

	/*
	 * Now convert the string given by the first argument into internal
	 * form suitable for input to gss_acquire_cred()
	 */

	if ((status = gss_import_name(&minor_status, &name,
		(gss_OID)GSS_C_NT_HOSTBASED_SERVICE, &desired_name))
		!= GSS_S_COMPLETE) {
		printf(gettext(
			"could not parse desired name: err (octal) %o (%s)\n"),
			status, gettext("gss_acquire_cred error"));
		return;
	}

	argc--;
	argv++;

	/*
	 * The next argument is an OID in dotted decimal form.
	 */

	if (argc == 0) {
		printf(gettext("Assuming Kerberos V5 as the mechanism\n"));
		printf(gettext(
			"The mech OID 1.2.840.113554.1.2.2 will be used\n"));
		mech_type = gss_str2oid((char *)GSS_KRB5_MECH_OID);
	} else
		mech_type = gss_str2oid(argv[0]);

	if (mech_type == 0 || mech_type->length == 0) {
		printf(gettext("improperly formated mechanism OID\n"));
		return;
	}

	/*
	 * set up desired_mechs so it points to mech_type.
	 */

	desired_mechs = (gss_OID_set) MALLOC(sizeof (gss_OID_desc));

	desired_mechs->count = 1;
	desired_mechs->elements = mech_type;

	status = kgss_acquire_cred(
				&minor_status,
				desired_name,
				time_req,
				desired_mechs,
				cred_usage,
				&acceptor_credentials,
				&actual_mechs,
				&time_rec,
				uid);

	/* store major and minor status for gss_display_status() call */

	gss_major_code = status;
	gss_minor_code = minor_status;

	if (status == GSS_S_COMPLETE) {
		/* process returned values */

		printf(gettext("\nacquire succeeded\n\n"));

		/*
		 * print out the actual mechs returned  NB: Since only one
		 * mechanism is specified in desired_mechs, only one
		 * can be returned in actual_mechs. Consequently,
		 * actual_mechs->elements points to an array of only one
		 * element.
		 */

		if ((string = gss_oid2str(actual_mechs->elements)) == 0) {
			printf(gettext("actual mechs == NULL\n\n"));
		} else {
			printf(gettext("actual mechs  = %s\n\n"), string);
			FREE(string, (actual_mechs->elements->length+1)*4+1);
		}

		if (cred_usage == GSS_C_BOTH)
			printf(gettext("GSS_C_BOTH\n\n"));

		if (cred_usage == GSS_C_INITIATE)
			printf(gettext("GSS_C_INITIATE\n\n"));

		if (cred_usage == GSS_C_ACCEPT)
			printf(gettext("GSS_C_ACCEPT\n\n"));
		status = kgss_inquire_cred(
				&minor_status,
				acceptor_credentials,
				NULL,
				&time_req,
				&cred_usage,
				&inquire_mechs,
				uid);

		if (status != GSS_S_COMPLETE)
			printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_inquire_cred error"));
		else {
			if ((inq_string =
				gss_oid2str(inquire_mechs->elements)) == 0) {
				printf(gettext
					("mechs from inquire == NULL\n\n"));
			} else {
				printf(gettext
					("mechs from inquiry  = %s\n\n"),
					inq_string);
				FREE(inq_string,
				(inquire_mechs->elements->length+1)*4+1);
			}
			printf(gettext("inquire_cred successful \n\n"));
		}

	} else {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_acquire_cred error"));
	}

	/* free allocated memory */

	/* actual mechs is allocated by clnt_stubs. Release it here */
	if (actual_mechs != GSS_C_NULL_OID_SET)
		gss_release_oid_set_and_oids(&minor_status, &actual_mechs);
	if (inquire_mechs != GSS_C_NULL_OID_SET)
		gss_release_oid_set_and_oids(&minor_status, &inquire_mechs);

	gss_release_name(&minor_status, &desired_name);

	/* mech_type and desired_mechs are allocated above. Release it here */

	FREE(mech_type->elements, mech_type->length);
	FREE(mech_type, sizeof (gss_OID_desc));
	FREE(desired_mechs, sizeof (gss_OID_desc));
}

static void
_gss_add_cred(argc, argv)
int argc;
char **argv;
{

	OM_UINT32 status, minor_status;
	gss_buffer_desc name;
	gss_name_t desired_name = (gss_name_t) 0;
	OM_uint32 time_req;
	OM_uint32 initiator_time_req;
	OM_uint32 acceptor_time_req;
	int cred_usage;
	gss_OID_set actual_mechs = GSS_C_NULL_OID_SET;
	gss_OID_set inquire_mechs = GSS_C_NULL_OID_SET;
	char * string;
	uid_t uid;
	gss_OID mech_type;
	int i;

	/*
	 * First set up the command line independent input arguments.
	 */

	initiator_time_req = (OM_uint32) 0;
	acceptor_time_req = (OM_uint32) 0;
	cred_usage = GSS_C_ACCEPT;
	uid = getuid();

	/* Parse the command line for the variable input arguments */

	if (argc == 0) {
		usage();
		return;
	}

	/*
	 * Get the name of the principal.
	 */

	name.length = strlen(argv[0])+1;
	name.value = argv[0];

	/*
	 * Now convert the string given by the first argument into internal
	 * form suitable for input to gss_acquire_cred()
	 */

	if ((status = gss_import_name(&minor_status, &name,
		(gss_OID)GSS_C_NT_HOSTBASED_SERVICE, &desired_name))
		!= GSS_S_COMPLETE) {
		printf(gettext(
			"could not parse desired name: err (octal) %o (%s)\n"),
			status, gettext("gss_acquire_cred error"));
		return;
	}

	argc--;
	argv++;

	/*
	 * The next argument is an OID in dotted decimal form.
	 */

	if (argc == 0) {
		printf(gettext("Assuming dummy  as the mechanism\n"));
		printf(gettext(
			"The mech OID 1.3.6.1.4.1.42.2.26.1.2 will be used\n"));
		mech_type = gss_str2oid((char *)GSS_DUMMY_MECH_OID);
	} else
		mech_type = gss_str2oid(argv[0]);

	if (mech_type == 0 || mech_type->length == 0) {
		printf(gettext("improperly formated mechanism OID\n"));
		return;
	}

	/*
	 * set up desired_mechs so it points to mech_type.
	 */

	status = kgss_add_cred(
				&minor_status,
				acceptor_credentials,
				desired_name,
				mech_type,
				cred_usage,
				initiator_time_req,
				acceptor_time_req,
				&actual_mechs,
				NULL,
				NULL,
				uid);

	/* store major and minor status for gss_display_status() call */

	gss_major_code = status;
	gss_minor_code = minor_status;
	if (status == GSS_S_COMPLETE) {
		/* process returned values */

		printf(gettext("\nadd  succeeded\n\n"));
		if (actual_mechs) {
			for (i = 0; i < actual_mechs->count; i++) {
				if ((string =
					gss_oid2str
					(&actual_mechs->elements[i])) == 0) {
					printf(gettext
					("actual mechs == NULL\n\n"));
				} else {
					printf(gettext
					("actual mechs  = %s\n\n"), string);
					FREE(string,
					(actual_mechs->elements->length+1)*4+1);
				}
			}
		}
		/*
		 * Try adding the cred again for the same mech
		 * We should get GSS_S_DUPLICATE_ELEMENT
		 * if not return an error
		 */
		status = kgss_add_cred(
				&minor_status,
				acceptor_credentials,
				desired_name,
				mech_type,
				cred_usage,
				initiator_time_req,
				acceptor_time_req,
				NULL, /*  &actual_mechs, */
				NULL,
				NULL,
				uid);
		if (status != GSS_S_DUPLICATE_ELEMENT) {
			printf(gettext("Expected duplicate element, Got "
			" (octal) %o (%s)\n"),
			status, gettext("gss_add_cred error"));
		}
		status = kgss_inquire_cred(
				&minor_status,
				acceptor_credentials,
				NULL,
				&time_req,
				&cred_usage,
				&inquire_mechs,
				uid);

		if (status != GSS_S_COMPLETE)
			printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_inquire_cred error"));
		else {
			for (i = 0; i < inquire_mechs->count; i++) {
				if ((string =
					gss_oid2str
					(&inquire_mechs->elements[i])) == 0) {
					printf(gettext
					("inquire_mechs mechs == NULL\n\n"));
				} else {
					printf(gettext
					("inquire_cred mechs  = %s\n\n"),
						string);
					FREE(string,
					(inquire_mechs->elements->length+1)*4
					+1);
				}
			}
			printf(gettext("inquire_cred successful \n\n"));
		}

	} else {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_acquire_cred error"));
	}

	/* Let us do inquire_cred_by_mech for both mechanisms */
	status = kgss_inquire_cred_by_mech(
			&minor_status,
			acceptor_credentials,
			mech_type,
			uid);
	if (status != GSS_S_COMPLETE)
		printf(gettext("server ret err (octal) %o (%s)\n"),
		status, gettext("gss_inquire_cred_by_mech"));
	else
		printf(gettext("gss_inquire_cred_by_mech successful"));


	FREE(mech_type->elements, mech_type->length);
	FREE(mech_type, sizeof (gss_OID_desc));
	mech_type = gss_str2oid((char *)GSS_KRB5_MECH_OID);
	status = kgss_inquire_cred_by_mech(
			&minor_status,
			acceptor_credentials,
			mech_type,
			uid);
	if (status != GSS_S_COMPLETE)
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext
			("gss_inquire_cred_by_mech for dummy mech error"));

	/* free allocated memory */

	/* actual mechs is allocated by clnt_stubs. Release it here */
	if (actual_mechs != GSS_C_NULL_OID_SET)
		gss_release_oid_set_and_oids(&minor_status, &actual_mechs);
	if (inquire_mechs != GSS_C_NULL_OID_SET)
		gss_release_oid_set_and_oids(&minor_status, &inquire_mechs);

	gss_release_name(&minor_status, &desired_name);

	/* mech_type and desired_mechs are allocated above. Release it here */

	FREE(mech_type->elements, mech_type->length);
	FREE(mech_type, sizeof (gss_OID_desc));
}

/*ARGSUSED*/
static void
_gss_release_cred(argc, argv)
int argc;
char **argv;
{
	OM_UINT32 status;
	OM_UINT32 minor_status;
	uid_t uid;

	/* set up input arguments here */

	if (argc != 0) {
		usage();
		return;
	}

	uid = getuid();

	status = kgss_release_cred(
				&minor_status,
				&acceptor_credentials,
				uid);

	/* store major and minor status for gss_display_status() call */

	gss_major_code = status;
	gss_minor_code = minor_status;

	if (status == GSS_S_COMPLETE) {
		printf(gettext("\nrelease succeeded\n\n"));
	} else {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_release_cred error"));
	}
}

static void
_gss_init_sec_context(argc, argv)
int argc;
char **argv;
{

	OM_uint32 status;

	OM_uint32 minor_status;
	gss_cred_id_t claimant_cred_handle;
	gss_name_t target_name = (gss_name_t) 0;
	gss_OID mech_type = (gss_OID) 0;
	int req_flags;
	OM_uint32 time_req;
	gss_channel_bindings_t input_chan_bindings;
	gss_buffer_t input_token;
	gss_buffer_desc context_token;
	gss_OID actual_mech_type;
	int ret_flags;
	OM_uint32 time_rec;
	uid_t uid;
	char * string;
	gss_buffer_desc name;

	/*
	 * If this is the first phase of the context establishment,
	 * clear initiator_context_handle and indicate next phase.
	 */

	if (init_sec_context_phase == 0) {
		initiator_context_handle = GSS_C_NO_CONTEXT;
		input_token = GSS_C_NO_BUFFER;
		init_sec_context_phase = 1;
	} else
		input_token = &init_token_buffer;

	/*
	 * First set up the non-variable command line independent input
	 * arguments
	 */

	claimant_cred_handle = GSS_C_NO_CREDENTIAL;

	req_flags = GSS_C_MUTUAL_FLAG;
	time_req = (OM_uint32) 0;
	input_chan_bindings = GSS_C_NO_CHANNEL_BINDINGS;
	uid = getuid();

	/* Now parse the command line for the remaining input arguments */

	if (argc == 0) {
		usage();
		return;
	}

	/*
	 * Get the name of the target.
	 */

	name.length = strlen(argv[0])+1;
	name.value = argv[0];

	/*
	 * Now convert the string given by the first argument into a target
	 * name suitable for input to gss_init_sec_context()
	 */

	if ((status = gss_import_name(&minor_status, &name,
		/* GSS_C_NULL_OID, &target_name)) */
		(gss_OID)GSS_C_NT_HOSTBASED_SERVICE, &target_name))
		!= GSS_S_COMPLETE) {
		printf(gettext(
			"could not parse target name: err (octal) %o (%s)\n"),
			status,
			gettext("gss_init_sec_context error"));
		if (input_token != GSS_C_NO_BUFFER)
			gss_release_buffer(&minor_status, &init_token_buffer);
		init_sec_context_phase = 0;
		return;
	}

	argc--;
	argv++;

	if (argc == 0) {
		printf(gettext("Assuming Kerberos V5 as the mechanism\n"));
		printf(gettext(
			"The mech OID 1.2.840.113554.1.2.2 will be used\n"));
		mech_type = gss_str2oid((char *)GSS_KRB5_MECH_OID);
	} else {
		mech_type = gss_str2oid(argv[0]);
	}

	if (mech_type == 0 || mech_type->length == 0) {
		printf(gettext("improperly formated mechanism OID\n"));
		if (input_token != GSS_C_NO_BUFFER)
			gss_release_buffer(&minor_status, &init_token_buffer);
		init_sec_context_phase = 0;
		return;
	}

	/* call kgss_init_sec_context */

	status = kgss_init_sec_context(&minor_status,
				claimant_cred_handle,
				&initiator_context_handle,
				target_name,
				mech_type,
				req_flags,
				time_req,
				input_chan_bindings,
				input_token,
				&actual_mech_type,
				&accept_token_buffer,
				&ret_flags,
				&time_rec,
				uid);

	/* store major and minor status for gss_display_status() call */
	gss_major_code = status;
	gss_minor_code = minor_status;

	if (status != GSS_S_COMPLETE &&
	    status != GSS_S_CONTINUE_NEEDED) {

		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, "gss_init_sec_context error");
		init_sec_context_phase = 0;
		if (status == GSS_S_NO_CRED)
			printf(gettext(" : no credentials"));
		if (input_token != GSS_C_NO_BUFFER)
			gss_release_buffer(&minor_status, &init_token_buffer);
		if (status != GSS_S_FAILURE && minor_status != 0xffffffff)
			status = kgss_delete_sec_context(&minor_status,
					&initiator_context_handle,
					&msg_token);
		return;

	} else if (status == GSS_S_COMPLETE) {

		/* process returned values */

		printf(gettext("\ninit succeeded\n\n"));

		/* print out the actual mechanism type */

		if ((string = gss_oid2str(actual_mech_type)) == 0) {

			printf(gettext(
				"gssapi internal err : actual "
				"mech type null\n"));
			init_sec_context_phase = 0;
			if (input_token != GSS_C_NO_BUFFER)
				gss_release_buffer(&minor_status,
						&init_token_buffer);
			gss_release_buffer(&minor_status, &accept_token_buffer);
			status = kgss_delete_sec_context(&minor_status,
					&initiator_context_handle,
					&msg_token);
			return;
		} else {
			printf(gettext("actual mech type = %s\n\n"), string);
			FREE(string, (actual_mech_type->length+1)*4+1);
		}

		/* print out value of ret_flags and time_req */

		if (ret_flags & GSS_C_DELEG_FLAG)
			printf(gettext("GSS_C_DELEG_FLAG = True\n"));
		else
			printf(gettext("GSS_C_DELEG_FLAG = False\n"));

		if (ret_flags & GSS_C_MUTUAL_FLAG)
			printf(gettext("GSS_C_MUTUAL_FLAG = True\n"));
		else
			printf(gettext("GSS_C_MUTUAL_FLAG = False\n"));

		if (ret_flags & GSS_C_REPLAY_FLAG)
			printf(gettext("GSS_C_REPLAY_FLAG = True\n"));
		else
			printf(gettext("GSS_C_REPLAY_FLAG = False\n"));

		if (ret_flags & GSS_C_SEQUENCE_FLAG)
			printf(gettext("GSS_C_SEQUENCE_FLAG = True\n"));
		else
			printf(gettext("GSS_C_SEQUENCE_FLAG = False\n"));

		if (ret_flags & GSS_C_CONF_FLAG)
			printf(gettext("GSS_C_CONF_FLAG = True\n"));
		else
			printf(gettext("GSS_C_CONF_FLAG = False\n"));

		if (ret_flags & GSS_C_INTEG_FLAG)
			printf(gettext("GSS_C_INTEG_FLAG = True\n\n"));
		else
			printf(gettext("GSS_C_INTEG_FLAG = False\n\n"));

		printf(gettext("time_req = %u seconds\n\n"), time_rec);

		/* free allocated memory */

		FREE(mech_type->elements, mech_type->length);
		FREE(mech_type, sizeof (gss_OID_desc));

		/* these two were malloc'd by kgss_init_sec_context() */

		FREE(actual_mech_type->elements, actual_mech_type->length);
		FREE(actual_mech_type, sizeof (gss_OID_desc));

		gss_release_name(&minor_status, &target_name);

		if (input_token != GSS_C_NO_BUFFER)
			gss_release_buffer(&minor_status, &init_token_buffer);

		/*
		 * if status == GSS_S_COMPLETE, reset the phase to 0 and
		 * release token in accept_token_buffer
		 */

		init_sec_context_phase = 0;
	/* Save and restore the context */
	status = kgss_export_sec_context(&minor_status,
					&initiator_context_handle,
					&context_token);
	if (status != GSS_S_COMPLETE) {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_export_sec_context_error"));
		return;
	}
	status = kgss_import_sec_context(&minor_status,
					&context_token,
					&initiator_context_handle);
	if (status != GSS_S_COMPLETE) {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_import_sec_context_error"));
		return;
	}
	(void) gss_release_buffer(&minor_status, &context_token);

	/* gss_export & gss_import secxc_context worked, return */
	printf(gettext("\nexport and import of contexts succeeded\n"));
	printf(gettext("\ninit completed"));

	} else {
		printf(gettext("\nfirst phase of init succeeded"));
		printf(gettext("\ninit must be called again\n\n"));
	}

}

/*ARGSUSED*/
static void
_gss_accept_sec_context(argc, argv)
int argc;
char **argv;
{
	OM_UINT32 status;

	OM_uint32 minor_status;
	gss_channel_bindings_t input_chan_bindings;
	gss_OID mech_type;
	int ret_flags;
	OM_uint32 time_rec;
	gss_cred_id_t delegated_cred_handle;
	uid_t uid;
	char *string;
	gss_buffer_desc src_name, src_name_string;
	gss_buffer_desc output_token;
	gss_name_t gss_name;
	gss_buffer_desc context_token;

	/*
	 * If this is the first phase of the context establishment,
	 * clear acceptor_context_handle and indicate next phase.
	 */

	if (accept_sec_context_phase == 0) {
		acceptor_context_handle = GSS_C_NO_CONTEXT;
		accept_sec_context_phase = 1;
	}

	/* Now set up the other command line independent input arguments */

	input_chan_bindings = GSS_C_NO_CHANNEL_BINDINGS;

	uid = (uid_t) getuid();

	if (argc != 0) {
		usage();
		return;
	}

	status = kgss_accept_sec_context(&minor_status,
					&acceptor_context_handle,
					acceptor_credentials,
					&accept_token_buffer,
					input_chan_bindings,
					&src_name,
					&mech_type,
					&init_token_buffer,
					&ret_flags,
					&time_rec,
					&delegated_cred_handle,
					uid);

	/* store major and minor status for gss_display_status() call */

	gss_major_code = status;
	gss_minor_code = minor_status;

	if (status != GSS_S_COMPLETE && status != GSS_S_CONTINUE_NEEDED) {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_accept_sec_context error"));
		gss_release_buffer(&minor_status, &accept_token_buffer);
		return;
	} else if (status == GSS_S_COMPLETE) {

		/* process returned values */

		printf(gettext("\naccept succeeded\n\n"));

		/*
		 * convert the exported name returned in src_name into
		 * a string and print it.
		 */
		if ((status = gss_import_name(&minor_status, &src_name,
			(gss_OID) GSS_C_NT_EXPORT_NAME, &gss_name))
			!= GSS_S_COMPLETE) {
			printf(gettext(
				"could not import src name 0x%x\n"), status);
			accept_sec_context_phase = 0;
			status = kgss_delete_sec_context(&minor_status,
					&acceptor_context_handle,
					&output_token);
			gss_release_buffer(&minor_status, &accept_token_buffer);
			if (status == GSS_S_CONTINUE_NEEDED)
				gss_release_buffer(&minor_status,
						&init_token_buffer);
			gss_release_buffer(&minor_status, &src_name);
			return;
		}

		memset(&src_name_string, 0, sizeof (src_name_string));
		if ((status = gss_display_name(&minor_status, gss_name,
			&src_name_string, NULL)) != GSS_S_COMPLETE) {
			printf(gettext("could not display src name: "
				"err (octal) %o (%s)\n"), status,
				"gss_init_sec_context error");
			accept_sec_context_phase = 0;
			status = kgss_delete_sec_context(&minor_status,
					&acceptor_context_handle,
					&output_token);
			gss_release_buffer(&minor_status, &accept_token_buffer);
			if (status == GSS_S_CONTINUE_NEEDED)
				gss_release_buffer(&minor_status,
						&init_token_buffer);
			gss_release_buffer(&minor_status, &src_name);
			return;
		}
		printf(gettext("src name = %s\n"), src_name_string.value);
		gss_release_name(&minor_status, &gss_name);
		gss_release_buffer(&minor_status, &src_name_string);
		gss_release_buffer(&minor_status, &src_name);

		/* print out the mechanism type */

		if ((string = gss_oid2str(mech_type)) == 0) {

			printf(gettext(
				"gssapi internal err :"
				" actual mech type null\n"));
			accept_sec_context_phase = 0;
			status = kgss_delete_sec_context(&minor_status,
					&acceptor_context_handle,
					&output_token);
			gss_release_buffer(&minor_status, &accept_token_buffer);
			if (status == GSS_S_CONTINUE_NEEDED)
				gss_release_buffer(&minor_status,
						&init_token_buffer);
			return;
		} else {

			printf(gettext("actual mech type = %s\n\n"), string);
			FREE(string, (mech_type->length+1)*4+1);
		}

	/* Save and restore the context */
	status = kgss_export_sec_context(&minor_status,
					&initiator_context_handle,
					&context_token);
	if (status != GSS_S_COMPLETE) {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_export_sec_context_error"));
		return;
	}
	status = kgss_import_sec_context(&minor_status,
					&context_token,
					&initiator_context_handle);
	if (status != GSS_S_COMPLETE) {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_import_sec_context_error"));
		return;
	}
	(void) gss_release_buffer(&minor_status, &context_token);

	/* gss_export & gss_import secxc_context worked, return */

	/* print out value of ret_flags and time_req */

		if (ret_flags & GSS_C_DELEG_FLAG)
			printf(gettext("GSS_C_DELEG_FLAG = True\n"));
		else
			printf(gettext("GSS_C_DELEG_FLAG = False\n"));

		if (ret_flags & GSS_C_MUTUAL_FLAG)
			printf(gettext("GSS_C_MUTUAL_FLAG = True\n"));
		else
			printf(gettext("GSS_C_MUTUAL_FLAG = False\n"));

		if (ret_flags & GSS_C_REPLAY_FLAG)
			printf(gettext("GSS_C_REPLAY_FLAG = True\n"));
		else
			printf(gettext("GSS_C_REPLAY_FLAG = False\n"));

		if (ret_flags & GSS_C_SEQUENCE_FLAG)
			printf(gettext("GSS_C_SEQUENCE_FLAG = True\n"));
		else
			printf(gettext("GSS_C_SEQUENCE_FLAG = False\n"));

		if (ret_flags & GSS_C_CONF_FLAG)
			printf(gettext("GSS_C_CONF_FLAG = True\n"));
		else
			printf(gettext("GSS_C_CONF_FLAG = False\n"));

		if (ret_flags & GSS_C_INTEG_FLAG)
			printf(gettext("GSS_C_INTEG_FLAG = True\n\n"));
		else
			printf(gettext("GSS_C_INTEG_FLAG = False\n\n"));

		printf(gettext("time_rec = %d seconds\n\n"), time_rec);

		/* free allocated memory */

		printf(gettext("\nexport and import of contexts succeeded\n"));

		FREE(mech_type->elements, mech_type->length);
		FREE(mech_type, sizeof (gss_OID_desc));
	} else {
		printf(gettext("\nfirst phase of accept succeeded"));
		printf(gettext("\naccept must be called again\n\n"));
	}


	/* free the input token in accept_token_buffer */
	gss_release_buffer(&minor_status, &accept_token_buffer);

	/* if status == GSS_S_COMPLETE, reset the phase to 0 */

	if (status == GSS_S_COMPLETE)
		accept_sec_context_phase = 0;

	/* gss_accept_sec_context worked, return */
}

void
_gss_process_context_token(argc, argv)
int argc;
char **argv;
{
	OM_UINT32 status;

	gss_ctx_id_t context_handle;
	OM_uint32 minor_status;
	uid_t uid;

	uid = (uid_t) getuid();

	/* parse the command line to determine the variable input argument */

	if (argc == 0) {
		usage();
		return;
	}

	if (strcmp(argv[0], "initiator") == 0)
		context_handle = initiator_context_handle;
	else if (strcmp(argv[0], "acceptor") == 0)
		context_handle = acceptor_context_handle;
	else {
		printf(gettext(
			"must specify either \"initiator\" or \"acceptor\"\n"));
		return;
	}

	argc--;
	argv++;

	if (argc != 0) {
		usage();
		return;
	}

	status = kgss_process_context_token(&minor_status,
					    context_handle,
					    delete_token_buffer,
					    uid);

	/* store major and minor status for gss_display_status() call */

	gss_major_code = status;
	gss_minor_code = minor_status;

	if (status != GSS_S_COMPLETE) {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_process_context_token error"));
		return;

	} else {
		printf(gettext("\nprocess succeeded\n\n"));
		return;
	}
}

static void
_gss_delete_sec_context(argc, argv)
int argc;
char **argv;
{
	OM_UINT32 status;
	gss_ctx_id_t *context_handle;
	OM_uint32 minor_status;
	uid_t uid;

	uid = (uid_t) getuid();

	/* parse the command line to determine the variable input argument */

	if (argc == 0) {
		usage();
		return;
	}

	if (strcmp(argv[0], "initiator") == 0) {
		context_handle = &initiator_context_handle;
	} else if (strcmp(argv[0], "acceptor") == 0) {
		context_handle = &acceptor_context_handle;
	} else {
		printf(gettext(
			"must specify either \"initiator\" or \"acceptor\"\n"));
		return;
	}

	argc--;
	argv++;

	if (argc != 0) {
		usage();
		return;
	}


	status = kgss_delete_sec_context(&minor_status,
					context_handle,
					&delete_token_buffer);


	/* store major and minor status for gss_display_status() call */

	gss_major_code = status;
	gss_minor_code = minor_status;

	if (status != GSS_S_COMPLETE) {

		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_delete_sec_context error"));
		return;

	} else {
		printf(gettext("\ndelete succeeded\n\n"));
		return;
	}
}

/*ARGSUSED*/
static void
_gss_context_time(argc, argv)
int argc;
char **argv;
{
	/*
	 * set up input arguments here
	 * this function is unimplemented. Call usage() and return
	 */

	printf(gettext("\nunimplemented function"));
}

static void
_gss_sign(argc, argv)
int argc;
char **argv;
{
	OM_UINT32 status;
	OM_uint32 minor_status;
	gss_ctx_id_t context_handle;
	int qop_req;
	uid_t uid;

	uid = (uid_t) getuid();

	/* specify the default quality of protection */

	qop_req = GSS_C_QOP_DEFAULT;

	/* set up the arguments specified in the input parameters */

	if (argc == 0) {
		usage();
		return;
	}


	if (strcmp(argv[0], "initiator") == 0)
		context_handle = initiator_context_handle;
	else if (strcmp(argv[0], "acceptor") == 0)
		context_handle = acceptor_context_handle;
	else {
		printf(gettext(
			"must specify either \"initiator\" or \"acceptor\"\n"));
		return;
	}

	argc--;
	argv++;

	if (argc == 0) {
		usage();
		return;
	}

	message_buffer.length = strlen(argv[0])+1;
	message_buffer.value = (void *) MALLOC(message_buffer.length);
	strcpy(message_buffer.value, argv[0]);

	argc--;
	argv++;

	if (argc != 0) {
		usage();
		return;
	}

	status = kgss_sign(&minor_status,
			context_handle,
			qop_req,
			&message_buffer,
			&msg_token,
			uid);

	/* store major and minor status for gss_display_status() call */

	gss_major_code = status;
	gss_minor_code = minor_status;

	if (status != GSS_S_COMPLETE) {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_sign error"));
		return;

	} else {
		printf(gettext("\nsign succeeded\n\n"));
		return;
	}
}

static void
_gss_verify(argc, argv)
int argc;
char **argv;
{
	OM_UINT32 status, minor_status;
	gss_ctx_id_t context_handle;
	int qop_state;
	uid_t uid;

	uid = (uid_t) getuid();

	/* set up the arguments specified in the input parameters */

	if (argc == 0) {
		usage();
		return;
	}


	if (strcmp(argv[0], "initiator") == 0)
		context_handle = initiator_context_handle;
	else if (strcmp(argv[0], "acceptor") == 0)
		context_handle = acceptor_context_handle;
	else {
		printf(gettext(
			"must specify either \"initiator\" or \"acceptor\"\n"));
		return;
	}

	argc--;
	argv++;

	if (argc != 0) {
		usage();
		return;
	}

	status = kgss_verify(&minor_status,
			context_handle,
			&message_buffer,
			&msg_token,
			&qop_state,
			uid);

	/* store major and minor status for gss_display_status() call */

	gss_major_code = status;
	gss_minor_code = minor_status;

	if (status != GSS_S_COMPLETE) {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_verify error"));
		return;
	} else {

		/* print out the verified message */

		printf(gettext(
			"verified message = \"%s\"\n\n"), message_buffer.value);

		/* print out the quality of protection returned */

		printf(gettext("quality of protection = %d \n\n"), qop_state);

		/* free the message buffer and message token and return */

		gss_release_buffer(&minor_status, &message_buffer);
		gss_release_buffer(&minor_status, &msg_token);

		return;
	}
}

static void
_gss_seal(argc, argv)
int argc;
char **argv;
{
	OM_UINT32 status;

	OM_uint32 minor_status;
	gss_ctx_id_t context_handle;
	int conf_req_flag;
	int qop_req;
	gss_buffer_desc input_message_buffer;
	int conf_state;
	uid_t uid;

	uid = (uid_t) getuid();

	/*
	 * specify the default confidentiality requested (both integrity
	 * and confidentiality) and quality of protection
	 */

	conf_req_flag = 1;
	qop_req = GSS_C_QOP_DEFAULT;

	/* set up the arguments specified in the input parameters */

	if (argc == 0) {
		usage();
		return;
	}


	if (strcmp(argv[0], "initiator") == 0)
		context_handle = initiator_context_handle;
	else if (strcmp(argv[0], "acceptor") == 0)
		context_handle = acceptor_context_handle;
	else {
		printf(gettext(
			"must specify either \"initiator\" or \"acceptor\"\n"));
		return;
	}

	argc--;
	argv++;

	if (argc == 0) {
		usage();
		return;
	}


	input_message_buffer.length = strlen(argv[0])+1;
	input_message_buffer.value =
		(void *) MALLOC(input_message_buffer.length);
	strcpy(input_message_buffer.value, argv[0]);

	argc--;
	argv++;

	if (argc != 0) {
		usage();
		return;
	}

	status = kgss_seal(&minor_status,
			context_handle,
			conf_req_flag,
			qop_req,
			&input_message_buffer,
			&conf_state,
			&message_buffer,
			uid);

	/* store major and minor status for gss_display_status() call */

	gss_major_code = status;
	gss_minor_code = minor_status;

	/* free the inputmessage buffer */

	gss_release_buffer(&minor_status, &input_message_buffer);

	if (status != GSS_S_COMPLETE) {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_seal error"));
		return;
	} else {
		printf(gettext("\nseal succeeded\n\n"));
		return;
	}
}

static void
_gss_unseal(argc, argv)
int argc;
char **argv;
{
	OM_UINT32 status;

	OM_uint32 minor_status;
	gss_ctx_id_t context_handle;
	gss_buffer_desc output_message_buffer;
	int conf_state;
	int qop_state;
	uid_t uid;

	uid = (uid_t) getuid();

	/* set up the arguments specified in the input parameters */

	if (argc == 0) {
		usage();
		return;
	}


	if (strcmp(argv[0], "initiator") == 0)
		context_handle = initiator_context_handle;
	else if (strcmp(argv[0], "acceptor") == 0)
		context_handle = acceptor_context_handle;
	else {
		printf(gettext(
			"must specify either \"initiator\" or \"acceptor\"\n"));
		return;
	}

	argc--;
	argv++;

	if (argc != 0) {
		usage();
		return;
	}

	status = kgss_unseal(&minor_status,
			context_handle,
			&message_buffer,
			&output_message_buffer,
			&conf_state,
			&qop_state,
			uid);

	/* store major and minor status for gss_display_status() call */

	gss_major_code = status;
	gss_minor_code = minor_status;

	if (status == GSS_S_COMPLETE) {
		printf(gettext("\nunseal succeeded\n\n"));
		printf(gettext("unsealed message = \"%s\"\n\n"),
			output_message_buffer.value);
		if (conf_state)
			printf(gettext("confidentiality and integrity used\n"));
		else
			printf(gettext("only integrity used\n"));
		printf(gettext("quality of protection = %d\n\n"), qop_state);
		gss_release_buffer(&minor_status, &output_message_buffer);
	} else {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_unseal error"));
	}

	/* free the message buffer and return */

	gss_release_buffer(&minor_status, &message_buffer);
}

static void
_gss_display_status(argc, argv)
int argc;
char **argv;
{
	OM_UINT32 status;
	OM_uint32 minor_status;
	int status_type;
	int status_value;
	gss_OID mech_type = (gss_OID) 0;
	int message_context;
	gss_buffer_desc status_string;
	uid_t uid;

	uid = (uid_t) getuid();

	/* initialize message context to zero */

	message_context = 0;

	if (argc == 0) {
		printf(gettext("Assuming Kerberos V5 as the mechanism\n"));
		printf(gettext(
			"The mech OID 1.2.840.113554.1.2.2 will be used\n"));
		mech_type = gss_str2oid((char *)GSS_KRB5_MECH_OID);
	} else
		mech_type = gss_str2oid(argv[0]);

	if (mech_type == 0 || mech_type->length == 0) {
		printf(gettext("improperly formated mechanism OID\n"));
		return;
	}

	/* Is this call for the major or minor status? */

	if (strcmp(argv[0], "major") == 0) {
		status_type = GSS_C_GSS_CODE;
		status_value = gss_major_code;
	} else if (strcmp(argv[0], "minor") == 0) {
		status_type = GSS_C_MECH_CODE;
		status_value = gss_minor_code;
	} else {
		printf(gettext("must specify either \"major\" or \"minor\"\n"));
		return;
	}

	argc--;
	argv++;

	if (argc != 0) {
		usage();
		return;
	}

	status = kgss_display_status(&minor_status,
				status_value,
				status_type,
				mech_type,
				&message_context,
				&status_string,
				uid);

	if (status == GSS_S_COMPLETE) {
		printf(gettext("status =\n  %s\n\n"), status_string.value);
	} else if (status == GSS_S_BAD_MECH) {
		printf(gettext("invalide mechanism OID\n\n"));
	} else {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_display_status error"));
	}
}

/*ARGSUSED*/
static void
_gss_indicate_mechs(argc, argv)
int argc;
char **argv;
{
	OM_UINT32 status;
	OM_UINT32 minor_status;
	gss_OID_set oid_set = GSS_C_NULL_OID_SET;
	uid_t uid;

	uid = (uid_t) getuid();

	/* set up input arguments here */

	if (argc != 0) {
		usage();
		return;
	}

	status = kgss_indicate_mechs(&minor_status, &oid_set, uid);

	if (status == GSS_S_COMPLETE) {
		int i;
		char *string;

		printf(gettext("%d supported mechanism%s%s\n"), oid_set->count,
			(oid_set->count == 1) ? "" : "s",
			(oid_set->count > 0) ? ":" : "");

		for (i = 0; i < oid_set->count; i++) {
			string = gss_oid2str(&oid_set->elements[i]);
			printf(gettext("\t%s\n"), string);
			FREE(string, ((oid_set->elements[i].length+1)*4)+1);
		}
		printf("\n");

	} else {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			status, gettext("gss_indicate_mechs error"));
	}

	if (oid_set)
		gss_release_oid_set_and_oids(&minor_status, &oid_set);
}

/*ARGSUSED*/
static void
_gss_inquire_cred(argc, argv)
int argc;
char **argv;
{
	/* set up input arguments here */

	if (argc != 0) {
		usage();
		return;
	}


	/* this function is unimplemented. Call usage() and return */

	printf(gettext("\nUnsupported function"));
}

static char hexChars[] = "0123456789ABCDEF";

static void
_gssd_expname_to_unix_cred(argc, argv)
int argc;
char **argv;
{
	OM_uint32 major;
	gss_buffer_desc expName;
	char krb5_root_name[] = "040100092A864886F712010202000000"
		"25000A2A864886F71201020101726F6F744053554E534F46"
		"542E454E472E53554E2E434F4D00";
	unsigned char *byteStr, *hexStr;
	uid_t uidOut, uidIn;
	gid_t *gids, gidOut;
	int gidsLen, i, newLen;

	/* set up the arguments */
	uidIn = (uid_t) getuid();

	if (argc < 1) {
		printf(gettext(
			"Using principal name of root for krberos_v5\n"));
		expName.value = (void*)krb5_root_name;
		expName.length = strlen(krb5_root_name);
	} else {
		expName.value = (void*)argv[0];
		expName.length = strlen(argv[0]);
	}

	/* convert the name from hex to byte... */
	hexStr = (unsigned char *)expName.value;
	newLen = expName.length/2;
	byteStr = (unsigned char *)MALLOC(newLen+1);
	expName.value = (char *)byteStr;
	for (i = 0; i < expName.length; i += 2) {
		*byteStr = (strchr(hexChars, *hexStr++) - hexChars) << 4;
		*byteStr += (strchr(hexChars, *hexStr++) - hexChars);
		byteStr++;
	}
	expName.length = newLen;

	major = kgsscred_expname_to_unix_cred(&expName, &uidOut, &gidOut,
					&gids, &gidsLen, uidIn);

	FREE(expName.value, newLen);

	if (major == GSS_S_COMPLETE) {
		printf(gettext("uid = <%d>\tgid = <%d>\t"), uidOut, gidOut);
		if (gidsLen > 0)
			printf(gettext(" %d gids <"), gidsLen);
		else
			printf(gettext(
				" no supplementary group information\n"));
		for (i = 0; i < gidsLen; i++)
			printf(" %d ", gids[i]);
		if (gidsLen > 0) {
			printf(">\n");
			FREE(gids, gidsLen * sizeof (gid_t));
		}
	} else {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			major, gettext("gsscred_expname_to_unix_cred"));
	}
}

static void
_gssd_name_to_unix_cred(argc, argv)
int argc;
char **argv;
{
	OM_uint32 major, minor;
	gss_name_t gssName;
	gss_buffer_desc gssBuf = GSS_C_EMPTY_BUFFER;
	int gidsLen, i;
	gid_t *gids, gidOut;
	uid_t uidOut, uid;
	char defaultPrincipal[] = "root";
	gss_OID mechType, nameType;

	uid = getuid();

	/* optional argument 1 - contains principal name */
	if (argc > 0) {
		gssBuf.value = (void *)argv[0];
		gssBuf.length = strlen((char *)argv[0]);
	} else {
		gssBuf.value = (void *)defaultPrincipal;
		gssBuf.length = strlen(defaultPrincipal);
	}
	printf(gettext(
		"Using <%s> as the principal name.\n"), (char *)gssBuf.value);


	/* optional argument 2 - contains name oid */
	if (argc > 1)
		nameType = gss_str2oid((char *) argv[1]);
	else
		nameType = (gss_OID)GSS_C_NT_USER_NAME;

	if (nameType == NULL || nameType->length == 0) {
		printf(gettext("improperly formated name OID\n"));
		return;
	}
	printf(gettext("Principal name of type: <%s>.\n"),
		(argc > 1) ? argv[1] : "GSS_C_NT_USER_NAME");


	/* optional argument 3 - contains mech oid */
	if (argc > 2)
		mechType = gss_str2oid(argv[2]);
	else
		mechType = gss_str2oid((char *)GSS_KRB5_MECH_OID);

	if (mechType == NULL || mechType->length == NULL) {
		FREE(nameType->elements, nameType->length);
		FREE(nameType, sizeof (gss_OID_desc));
		printf(gettext("improperly formated mech OID\n"));
		return;
	}
	printf(gettext("Mechanism oid: <%s>.\n"),
		(argc > 2) ? argv[2] :
		(char *)GSS_KRB5_MECH_OID "(Kerberos v5)");


	/* convert the name to internal format */
	if ((major = gss_import_name(&minor, &gssBuf,
				nameType, &gssName)) != GSS_S_COMPLETE) {
		printf(gettext("could not parse name: err (octal) %o (%s)\n"),
			major, "gss_import_name");

		FREE(nameType->elements, nameType->length);
		FREE(nameType, sizeof (gss_OID_desc));
		return;
	}

	major = kgsscred_name_to_unix_cred(gssName, mechType, &uidOut,
					&gidOut, &gids, &gidsLen, uid);

	gss_release_name(&minor, &gssName);
	FREE(mechType->elements, mechType->length);
	FREE(mechType, sizeof (gss_OID_desc));
	if (argc > 1) {
		FREE(nameType->elements, nameType->length);
		FREE(nameType, sizeof (gss_OID_desc));
	}

	if (major == GSS_S_COMPLETE) {
		printf("uid = <%d>\tgid = <%d>\t", uidOut, gidOut);
		if (gidsLen > 0)
			printf(gettext(" %d gids <"), gidsLen);
		else
			printf(gettext(
				" no supplementary group information\n"));
		for (i = 0; i < gidsLen; i++)
			printf(" %d ", gids[i]);
		if (gidsLen > 0) {
			printf(">\n");
			FREE(gids, gidsLen * sizeof (gid_t));
		}
	} else {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			major, gettext("gsscred_name_to_unix_cred"));
	}
}

static void
_gssd_get_group_info(argc, argv)
int argc;
char **argv;
{
	OM_uint32 major;
	uid_t puid, uidIn;
	gid_t *gids, gidOut;
	int gidsLen, i;

	/* set up the arguments */
	uidIn = (uid_t) getuid();

	if (argc < 1)
		puid = 0;
	else
		puid = atol(argv[0]);

	printf(gettext("Retrieving group info for uid of <%d>\n"), puid);

	major = kgss_get_group_info(puid, &gidOut, &gids, &gidsLen, uidIn);

	if (major == GSS_S_COMPLETE) {
		printf(gettext("group id = <%d>\t"), gidOut);
		if (gidsLen > 0)
			printf(gettext(" %d gids <"), gidsLen);
		else
			printf(gettext(
				" no supplementary group information\n"));
		for (i = 0; i < gidsLen; i++)
			printf(" %d ", gids[i]);
		if (gidsLen > 0) {
			printf(">\n");
			FREE(gids, gidsLen * sizeof (gid_t));
		}
	} else {
		printf(gettext("server ret err (octal) %o (%s)\n"),
			major, "gss_get_group_info");
	}
}

static gss_OID
gss_str2oid(string)
char * string;
{
	/*
	 * a convenient wrapper routine for gss_str_to_oid
	 * this can handle all valid oid strings.
	 */
	OM_uint32 minor;
	gss_buffer_desc abuf;
	gss_OID oidOut;

	abuf.value = (void*)string;
	abuf.length = strlen(string);

	if (gss_str_to_oid(&minor, &abuf, &oidOut) != GSS_S_COMPLETE)
		return (NULL);

	return (oidOut);
}

static char *
gss_oid2str(oid)
gss_OID oid;
{
	/*
	 * a convenient wrapper for gss_oid_to_str
	 * this calls the GSS-API routine which should
	 * be able to handle all types of oids.
	 */
	OM_uint32 minor;
	gss_buffer_desc oidStr;

	if (gss_oid_to_str(&minor, oid, &oidStr) != GSS_S_COMPLETE)
		return (NULL);

	return ((char *)oidStr.value);
} /* gss_oid2str */

static void
instructs()
{
	fprintf(stderr,
		gettext(
"\nThis program must be run as root. Root must be installed on the KDC\n"
"and exist in srvtab as root/<hostname>, where <hostname> is the machine on\n"
"which the test runs. Before running gssdtest for Kerberos mechanism, the\n"
"operator running as root must kinit as some other principal, e.g., test.\n"
"There are two mechanisms avaialble: dummy and Kerberos(default).\n"
"The OID for dummy mechanism is 1.3.6.1.4.1.42.2.26.1.2.\n"
"The OID for Kerberos mechanism is 1.2.840.113554.1.2.2.\n"
"The order of context establishment calls is important. First, acquire must"
"\nbe called. This obtains the credentials used by accept. Acquire need\n"
"only be called once, since the credentials it returns are used each time\n"
"accept is called. Then init is called, followed by accept. Calling init\n"
"twice without calling accept or calling these in a different order gives\n"
"erroneous results and will cause memory leaks in the gssapi daemon. \n"
"Finally, after calling init and accept, init must be called again to\n"
"finish context establishment. So an example sequence (with data valid for\n"
"the Kerberos mechanism and running on the machine \"elrond\" in the realm\n"
"FOO.BAR.SUN.COM is :\n"));
	fprintf(stderr,
		gettext("\nacquire service@host 1.2.840.113554.1.2.2\n"
		"init service@host 1.2.840.113554.1.2.2\n"
		"accept\ninit service@host 1.2.840.113554.1.2.2\n"
		"\nAfter a context is established, sign, seal,\n"
		"verify and unseal may be called. Here are some examples\n"
		"for these routines : \n\n"
		"sign initiator ThisTestMessageIsForSigning\n"
		"verify acceptor\nseal initiator ThisTestMessageIsForSealing\n"
		"unseal acceptor\n\nEach input line is terminated by <cr>.\n"
		"The program is terminated by cntl-d\nor the command \"exit\""
		"\nfrom the prompt\n\n"));
}

static void
usage()
{
	fprintf(stderr,
		gettext(
		"\nusage:\t[acquire | gss_acquire_cred]"
		"desired_name mech_type\n"
		"\t[release | gss_release_cred]\n"
		"\t[init | gss_init_sec_context] target_name mech_type\n"
		"\t[accept | gss_accept_sec_context]\n"
		"\t[process | gss_process_context_token] initiator | acceptor\n"
		"\t[delete | gss_delete_sec_context] initiator | acceptor\n"
		"\t[time | gss_context_time] {not yet implemented}\n"
		"\t[sign | gss_sign] initiator | acceptor message-to-sign\n"
		"\t[verify | gss_verify] initiator | acceptor\n"
		"\t[seal | gss_seal] initiator | acceptor message-to-seal\n"
		"\t[unseal | gss_unseal] initiator | acceptor\n"
		"\t[status | gss_display_status] mech_type  [major | minor] \n"
		"\t[indicate | gss_indicate_mechs]\n"
		"\t[inquire | gss_inquire_cred] {not yet implemented}\n"
		"\t[expname2unixcred | gsscred_expname_to_unix_cred]"
		" export-name\n"
		"\t[name2unixcred | gsscred_name_to_unix_cred] "
		"pname [name_type mech_type]\n"
		"\t[grpinfo | gss_get_group_info] uid\n"
		"\t[gss_all | all] desired_name\n"
		"\t[gss_loop | loop] desired_name\n"
		"\texit\n\n"));
}

/* Copied from parse_argv(), then modified */

static int
parse_input_line(input_line, argc, argv)
char *input_line;
int * argc;
char ***argv;
{
	const char nil = '\0';
	char * chptr;
	int chr_cnt;
	int arg_cnt = 0;
	int ch_was_space = 1;
	int ch_is_space;

	chr_cnt = strlen(input_line);

	/* Count the arguments in the input_line string */

	*argc = 1;

	for (chptr = &input_line[0]; *chptr != nil; chptr++) {
		ch_is_space = isspace(*chptr);
		if (ch_is_space && !ch_was_space) {
			(*argc)++;
		}
		ch_was_space = ch_is_space;
	}

	if (ch_was_space) {
		(*argc)--;
	}	/* minus trailing spaces */

	/* Now that we know how many args calloc the argv array */

	*argv = (char **) CALLOC((*argc)+1, sizeof (char *));
	chptr = (char *) (&input_line[0]);

	for (ch_was_space = 1; *chptr != nil; chptr++) {
		ch_is_space = isspace(*chptr);
		if (ch_is_space) {
			*chptr = nil;	/* replace each space with nil	*/
		} else if (ch_was_space) {	/* begining of word? */
			(*argv)[arg_cnt++] = chptr;	/* new argument ? */
		}

		ch_was_space = ch_is_space;
	}

	return (chr_cnt);
}
