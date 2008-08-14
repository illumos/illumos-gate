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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <libgen.h>
#include <stdio.h>
#include <libnvpair.h>
#include <fcntl.h>
#include <sys/types.h>

#include "mms_mgmt.h"
#include "mgmt_util.h"
#include "mms_cfg.h"
#include "net_cfg_service.h"

static char *_SrcFile = __FILE__;
#define	HERE _SrcFile, __LINE__

typedef struct {
	char		*name;
	char		*cfgnam;
	int		svc;
} mms_mgmt_cfgopt_t;

static mms_mgmt_cfgopt_t  mmscfgopts[] = {
	{O_MMHOST,	MMS_CFG_MGR_HOST,	WCR|MM},
	{O_MMPORT,	MMS_CFG_MGR_PORT,	WCR|MM},
	{O_OBJTYPE,	MMS_CFG_CONFIG_TYPE,	0},
	{O_SSLENABLED,	MMS_CFG_SSL_ENABLED,	WCR|MM},
	{O_CERTFILE,	MMS_CFG_SSL_CERT_FILE,	WCR|MM},
	{O_SSLPASSFILE,	MMS_CFG_SSL_PASS_FILE,	WCR|MM},
	{O_CRLFILE,	MMS_CFG_SSL_CRL_FILE,	WCR|MM},
	{O_PEERFILE,	MMS_CFG_SSL_PEER_FILE,	WCR|MM},
	{O_DHFILE,	MMS_CFG_SSL_DH_FILE,	WCR|MM},
	{"ssl_cipher",	MMS_CFG_SSL_CIPHER,	WCR|MM},
	{O_VERIFY,	MMS_CFG_SSL_VERIFY,	WCR|MM},
	{O_DBHOST,	MMS_CFG_MM_DB_HOST,	MM},
	{O_DBPORT,	MMS_CFG_MM_DB_PORT,	DB|MM},
	{O_DBDIR,	MMS_CFG_DB_DATA,	DB},
	{O_DBLOG,	MMS_CFG_DB_LOG,		DB},
	{"db-user",	MMS_CFG_MM_DB_USER,	MM},
	{O_DBNAME,	MMS_CFG_MM_DB_NAME,	DB},
	{O_TRACELEVEL,	MMS_CFG_MM_TRACE,	MM},
	{O_ACSLSDIR,	MMS_CFG_SSI_PATH,	WCR},
	{NULL,		NULL,			0}
};

#ifdef	MMS_VAR_CFG
/* MMS Client Options */
static mms_mgmt_setopt_t mms_client_opts[] = {
	{O_MMHOST,	NULL,	NULL,			B_TRUE,	NULL},
	{O_MMPORT,	NULL,	MMS_DEF_MMPORT,		B_TRUE,	val_numonly},
	{O_MMPASS,	NULL,	NULL,			B_TRUE,	val_passwd},
	{O_OBJTYPE,	NULL,	"client", 		B_TRUE,	val_objtype},
	{O_SECURECOMM,	NULL,	"off",			B_TRUE,	NULL},
	{O_SSLENABLED,	NULL,	"false",		B_TRUE, NULL},
	{O_CERTFILE,	NULL,	MMSSSLDIR"/mms.pem",	B_FALSE, val_path},
	{O_SSLPASSFILE,	NULL,	MMSSSLDIR"/mms_pass",	B_FALSE, val_path},
	{O_CRLFILE,	NULL,	MMSSSLDIR"/mms_crl.pem", B_FALSE, val_path},
	{O_PEERFILE,	NULL,	MMSSSLDIR"/mms_cert.pem", B_FALSE, val_path},
	{O_ACSLSDIR,	NULL,	NULL,			B_FALSE, val_path},
	{NULL,	NULL, NULL, B_FALSE, NULL}
};
#define	NUM_CLIENT_OPTS (sizeof (mms_client_opts) / sizeof (mms_mgmt_setopt_t))
#endif	/* MMS_VAR_CFG */

/* MMS Server Options */
static mms_mgmt_setopt_t mms_server_opts[] = {
	{O_MMHOST,	NULL,	NULL,			B_TRUE,	NULL},
	{O_MMPORT,	NULL,	MMS_DEF_MMPORT,		B_TRUE,	val_numonly},
	{O_MMPASS,	NULL,	NULL,			B_TRUE,	val_passwd},
	{O_OBJTYPE,	NULL,	"server", 		B_TRUE,	val_objtype},
	{O_ACSLSDIR,	NULL,	NULL,			B_TRUE, val_path},
	{O_SECURECOMM,	NULL,	"off",			B_TRUE,	NULL},
	{O_SSLENABLED,	NULL,	"false",		B_TRUE, NULL},
	{O_CERTFILE,	NULL,	MMSSSLDIR"/mms.pem",	B_FALSE, val_path},
	{O_SSLPASSFILE,	NULL,	MMSSSLDIR"/mms_pass",	B_FALSE, val_path},
	{O_CRLFILE,	NULL,	MMSSSLDIR"/mms_crl.pem", B_FALSE, val_path},
	{O_PEERFILE,	NULL,	MMSSSLDIR"/mms_cert.pem", B_FALSE, val_path},
	{O_DHFILE,	NULL,	MMSSSLDIR"/mms_dh1024.pem", B_FALSE, NULL},
	{O_VERIFY,	NULL,	"false",		B_FALSE, NULL},
	{O_LOGLEVEL,	"SystemLogLevel", MMS_DEF_LOGLVL, B_FALSE, val_level},
	{O_LOGFILE,	"SystemLogFile",  MMSLOGDIR"/mm.log", B_FALSE,
	    val_path},
	{O_DBDIR,	NULL,	MMS_DEF_DBDIR,		B_TRUE, val_path},
	{O_DBHOST,	NULL,	"localhost",		B_TRUE, NULL},
	{O_DBPORT,	NULL,	MMS_DEF_DBPORT,		B_TRUE, val_numonly},
	{O_DBLOG,	NULL,	NULL,			B_FALSE, val_path},
	{O_DBNAME,	NULL,	"mms",			B_TRUE, NULL},
	{O_NUMRESTART,	"WatcherStartsLimit", "3",	B_FALSE, val_numonly},
	{O_ATTENDED,	"AttendanceMode", "yes",	B_FALSE, val_yesno},
	{O_NUMSOCKET,	"SocketFdLimit", "-1",		B_FALSE, val_numonly},
	{O_DKTIMEOUT,	"SystemDiskMountTimeout", "0",	B_FALSE, val_numonly},
	{O_TRACELEVEL,	"TraceLevel", NULL,		B_FALSE, val_level},
	{O_TRACESZ,	"TraceFileSize", NULL,		B_FALSE, val_mms_size},
	{O_MSGLEVEL,	"MessageLevel", NULL,		B_FALSE, val_level},
	{NULL, NULL, NULL, B_FALSE, NULL}
};
#define	NUM_SERVER_OPTS (sizeof (mms_server_opts) / sizeof (mms_mgmt_setopt_t))

static mms_mgmt_setopt_t application_opts[] = {
	{O_NAME,	NULL,	NULL,	B_TRUE, NULL},
	{O_RETENTION,	"Retention",	NULL, B_FALSE, val_numonly},
	{O_VALIDATEEXP,	"ValidateExpirationDate", NULL, B_FALSE, val_truefalse},
	{O_VALIDATEVOL,	"ValidateVolumeID", NULL, B_FALSE, val_truefalse},
	{O_VALIDATEFN,	"ValidateFileName", NULL, B_FALSE, val_truefalse},
	{O_OVERWRITEEXT, "WriteOverExistingData", NULL, B_FALSE, val_truefalse},
	{NULL, NULL, NULL, B_FALSE, NULL}
};

static int mgmt_set_pass(char *inpw);
#ifdef	MMS_VAR_CFG
static int mgmt_set_ssl(nvlist_t *opts);
#endif	/* MMS_VAR_CFG */

/*
 * The create_mm_clnt() function establishes a session with
 * MM.  If "app" is not MMS and "inst" is not "admin", the password must
 * also be provided.  "tag" is an optional identifier to be used
 * in the session API.
 */
int
create_mm_clnt(char *app, char *inst, char *pass, char *tag, void **session)
{

	int			version;
	int			st;
	mms_network_cfg_t	cfg;
	void			*ssl_data = NULL;
	void			*sess = NULL;
	char			*tagp = "";
#ifdef	MMS_OPENSSL
	mms_err_t		err;
	char			ebuf[1024];
#endif	/* MMS_OPENSSL */

	if (!session) {
		return (MMS_MGMT_NOARG);
	}

	*session = NULL;

	(void) memset(&cfg, 0, sizeof (mms_network_cfg_t));

	/*
	 * mms_net_cfg_service() expects to fetch information
	 * for MMS admin only.  However, we can use this to
	 * fetch the non-auth information for any app.
	 */
	st = mms_net_cfg_service(&cfg, "admin", "MMP", "1.0");
	if (st == 2) {
		/* password not available */
		if (!pass) {
			st = MMS_MGMT_PASSWORD_REQUIRED;
		} else {
			st = 0;
		}
	} else if (st == 1) {
		st = MMS_MGMT_MMS_NOT_INIT;
	}

	if (st != 0) {
		mms_trace(MMS_ERR, "Could not get MM connection info");
		return (st);
	}

	if (app) {
		if (strcasecmp(cfg.cli_name, app) != 0) {
			free(cfg.cli_name);
			cfg.cli_name = strdup(app);
			if (cfg.cli_name == NULL) {
				mms_trace(MMS_ERR, "Out of memory");
				mms_net_cfg_free(&cfg);
				return (ENOMEM);
			}
		}
	}

	if (inst) {
		if (strcasecmp(cfg.cli_inst, inst) != 0) {
			free(cfg.cli_inst);
			cfg.cli_inst = strdup(app);
			if (cfg.cli_inst == NULL) {
				mms_trace(MMS_ERR, "Out of memory");
				mms_net_cfg_free(&cfg);
				return (ENOMEM);
			}
		}
	}

	if (pass) {
		if (cfg.cli_pass) {
			free(cfg.cli_pass);
		}
		cfg.cli_pass = strdup(pass);
		if (cfg.cli_pass == NULL) {
			mms_trace(MMS_ERR, "Out of memory");
			mms_net_cfg_free(&cfg);
			return (ENOMEM);
		}
	}

	if (tag) {
		tagp = tag;
	}

	if ((st = mms_init(&sess, &version)) != MMS_API_OK) {
		mms_trace(MMS_ERR, "Unable to create a session with MM");
		mms_net_cfg_free(&cfg);
		return (st);
	}

	mms_trace(MMS_DEBUG, "MM version = %d, expected version = %d",
	    version, MMS_API_VERSION);

#ifdef	MMS_OPENSSL
	if (cfg.ssl_enabled != 0) {
		st = mms_ssl_client(&cfg, &ssl_data, &err);
		if (st != 0) {
			mms_get_error_string(&err, ebuf, MMS_EBUF_LEN);
			mms_trace(MMS_ERR, "error ssl init - %s", ebuf);
			mms_net_cfg_free(&cfg);
			return (st);
		}
	}
#endif	/* MMS_OPENSSL */

	st = mms_hello(sess, cfg.cli_host, cfg.cli_port, cfg.cli_name,
	    cfg.cli_inst, tagp, cfg.cli_pass, cfg.mm_pass, ssl_data);

	if (st != MMS_API_OK) {
		mms_trace(MMS_ERR,
		    "Unable to create a session with MM, ret = %d [%s]",
		    st, mms_sym_code_to_str(st));
		mms_net_cfg_free(&cfg);

		return (st);
	}

	*session = sess;

	mms_trace(MMS_DEBUG, "Created a connection with MM");
	mms_net_cfg_free(&cfg);

	return (0);
}

/*
 * mms_mgmt_init_host()
 *
 *  DESCRIPTION:
 *
 *  Sets all required MMS options, and starts required services.
 *
 *  On an MMS client system,
 *	sets MM host, port and administrative password
 *	sets SSL options, if desired
 *	starts the Watcher daemon
 *
 *  On on MMS server system,
 *	creates MMS database admin user
 *	initializes MMS database and starts database server
 *	sets MM options [TBD:  list these with explanation]
 *	starts MM daemon and Watcher daemon
 *
 *  ARGUMENTS:
 *	nvlist_t *opts		key/value pairs for requested options
 *	nvlist_t **errs		optional - used to return detailed errors
 *				about invalid/missing options, and other
 *				operational failures during initialization.
 *				If 'errs' is non-NULL, a new nvlist will be
 *				allocated.  The caller should free this list
 *				with nvlist_free().
 *
 *  RETURN VALUES:
 *
 *	0		Success
 *	MMS_MGMT_NOARG	'opts' argument missing
 *	EINVAL		One or more requested options is invalid
 *	EALREADY	Host has already been initialized for MMS
 *	ENOMEM		Out of memory
 *	[others TBD]
 */

int
mms_mgmt_init_host(nvlist_t *opts, nvlist_t **errs)
{
	int			st = 0;
	mms_mgmt_setopt_t	*optp = NULL;
	int			nst = 0;
	char			*val;
	char			*pass = NULL;
	char			*hosttype = NULL;
	int			scf_size = MMS_CFG_MAX_VALUE;
	char			cfgvar[scf_size];
	char			*bufp;
	char			buf[scf_size];
	int			i;
	nvlist_t		*init_errs = NULL;

	if (!opts) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

#ifdef	MMS_VAR_CFG
	/* make sure we've not already been initialized */
	st = mms_cfg_getvar(MMS_CFG_CONFIG_TYPE, buf);
	if (st != 0) {
		st = mgmt_xlate_cfgerr(st);
		if (st != ENOENT) {
			return (st);
		}
	} else {
		/* host already configured */
		return (EALREADY);
	}
#endif	/* MMS_VAR_CFG */

	if (errs) {
		*errs = NULL;
		st = nvlist_alloc(&init_errs, NV_UNIQUE_NAME, 0);
		if (st != 0) {
			return (st);
		}
	}

	st = nvlist_lookup_string(opts, O_OBJTYPE, &hosttype);
	if (st == 0) {
		if (*hosttype == 's') {
			optp = mms_server_opts;
#ifdef	MMS_VAR_CFG
		} else if (*hosttype == 'c') {
			optp = mms_client_opts;
#endif	/* MMS_VAR_CFG */
		} else {
			st = EINVAL;
		}
	}

	if (st != 0) {
		MGMT_ADD_OPTERR(init_errs, O_OBJTYPE, st);
		*errs = init_errs;
		return (st);
	}

	st = nvlist_lookup_string(opts, O_MMPASS, &pass);
	if (st != 0) {
		MGMT_ADD_OPTERR(init_errs, O_MMPASS, st);
		*errs = init_errs;
		return (st);
	}

	st = mms_cfg_getvar(MMS_CFG_MM_DB_USER, buf);
	if (st != 0) {
		st = mgmt_xlate_cfgerr(st);
		if (st == ENOENT) {
			st = mms_cfg_getvar(MMS_CFG_DB_INST
			    "/:properties/method_context/user", buf);
		}
	}
	if (st != 0) {
		/* major configuration error */
		MGMT_ADD_OPTERR(init_errs,
		    "mmsdb method_context/user",
		    st);
		goto done;
	}
	(void) nvlist_add_string(opts, "db-user", buf);

	for (i = 0; optp[i].name != NULL; i++) {
#ifndef	MMS_VAR_CFG
		/* We can only set opts in MMP until SMF gets sorted */
		if (optp[i].mmpopt == NULL) {
			continue;
		}
#endif	/* MMS_VAR_CFG */
		nst = nvlist_lookup_string(opts, optp[i].name, &val);
		if (nst == 0) {
			if (optp[i].validate_func) {
				nst = (optp[i].validate_func)(val);
			}
		} else if (nst == ENOENT) {
			if (!(optp[i].required)) {
				nst = 0;
			} else if (optp[i].defval) {
				nst = nvlist_add_string(opts,
				    optp[i].name, optp[i].defval);
			}
		}

		if (nst != 0) {
			st = nst;

			if (errs) {
				(void) nvlist_add_int32(init_errs, optp[i].name,
				    nst);
			} else {
				/* fail on first error */
				break;
			}
		}
	}

	if (st != 0) {
		goto done;
	}

#ifdef	MMS_VAR_CFG
	/*
	 * special case for DB logdir.  If not specified, should be set to
	 * DBDIR/log
	 */
	if (*hosttype == 's') {
		st = nvlist_lookup_string(opts, O_DBLOG, &val);
		if (st == ENOENT) {
			st = nvlist_lookup_string(opts, O_DBDIR, &val);
			if (st == 0) {
				(void) snprintf(buf, sizeof (buf), "%s/%s",
				    val, "log");
				st = nvlist_add_string(opts, O_DBLOG, buf);
			}
		}
		if (st != 0) {
			MGMT_ADD_OPTERR(init_errs, O_DBDIR, st);
			goto done;
		}
	}

	/* TODO:  support ssl enabled */

	/* have the full complement of required options - set SMF config  */
	for (i = 0; mmscfgopts[i].name != NULL; i++) {
		nst = nvlist_lookup_string(opts,  mmscfgopts[i].name, &val);
		if (nst == 0) {
			mms_cfg_setvar(mmscfgopts[i].cfgnam, val);
		}
	}
#endif	/* MMS_VAR_CFG */

	/* Set the MMS Admin password */
	st = mgmt_set_pass(pass);
	if (st != 0) {
		goto done;
	}

	/* If we're setting up the server, configure the DB and start MM */
	if (*hosttype == 's') {
#ifndef	MMS_VAR_CFG
		/*
		 * TEMPORARY:  Fetch variables from SMF, rather than
		 * require them to be passed in.
		 */
		st = mms_cfg_getvar(MMS_CFG_DB_DATA, cfgvar);
		if (st != 0) {
			MGMT_ADD_OPTERR(init_errs, O_DBDIR, st);
			goto done;
		} else {
			/*
			 * currently storing up to data in SMF.
			 * Change to parent dir for creating subdirs.
			 */
			bufp = strrchr(cfgvar, '/');
			if (bufp != NULL) {
				if (strcmp(bufp, "/data") == 0) {
					*bufp = '\0';
				}
			}
			(void) nvlist_add_string(opts, O_DBDIR, cfgvar);

			/* fixed path for log dir */
			(void) strlcat(cfgvar, "/log", sizeof (cfgvar));
			(void) nvlist_add_string(opts, O_DBLOG, cfgvar);
		}
		st = mms_cfg_getvar(MMS_CFG_MM_DB_PORT, cfgvar);
		if (st == 0) {
			(void) nvlist_add_string(opts, O_DBPORT, cfgvar);
		} else {
			MGMT_ADD_OPTERR(init_errs, O_DBPORT, st);
			goto done;
		}

		st = mms_cfg_getvar(MMS_CFG_MM_DB_NAME, cfgvar);
		if (st == 0) {
			(void) nvlist_add_string(opts, O_DBNAME, cfgvar);
		} else {
			MGMT_ADD_OPTERR(init_errs, O_DBNAME, st);
			goto done;
		}

		st = mms_cfg_getvar(MMS_CFG_MM_DB_HOST, cfgvar);
		if (st == 0) {
			(void) nvlist_add_string(opts, O_DBHOST, cfgvar);
		} else {
			MGMT_ADD_OPTERR(init_errs, O_DBHOST, st);
			goto done;
		}

#endif	/* !MMS_VAR_CFG */
		st = mgmt_set_db_opts(opts, init_errs);
		if (st == 0) {
			/* Database will be functional after this call */
			st = mgmt_db_create(1, 1, opts);
		}

		if (st != 0) {
			goto done;
		}

		st = mgmt_set_svc_state(MMSVC, ENABLE, NULL);
	}

	/* Watcher needs to be started for both host types */
	if (st == 0) {
		st = mgmt_set_svc_state(WCRSVC, ENABLE, NULL);
	}

done:
	if (st != 0) {
		if (errs) {
			*errs = init_errs;
		}
		/* don't stop services if we haven't changed anything */
		if (st != EALREADY) {
			(void) mms_mgmt_uninitialize();
		}
	} else if (init_errs) {
		nvlist_free(init_errs);
	}

	return (st);
}

/*
 * mms_mgmt_get_opts()
 */
int
mms_mgmt_get_opts(char *type, nvlist_t **opts)
{
	int			st;
	int			i;
	int			scf_size = MMS_CFG_MAX_VALUE;
	char			buf[scf_size];
	void			*session = NULL;
	void			*response = NULL;
	char			tid[64];
	nvlist_t		*sysattrs = NULL;
	nvpair_t		*nvp;
	nvlist_t		*nva;

	if ((type == NULL) || (opts == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	/* get MM system vals */
	(void) mms_gen_taskid(tid);
	(void) snprintf(buf, sizeof (buf),
	    "show task['%s'] report[SYSTEM] reportmode[namevalue];", tid);

	st = create_mm_clnt(NULL, NULL, NULL, NULL, &session);
	if (st != 0) {
		goto done;
	}

	st = mms_mgmt_send_cmd(session, tid, buf, "get system attrs",
	    &response);

	(void) mms_goodbye(session, 0);

	if (st != 0) {
		goto done;
	}
	st = mmp_get_nvattrs(O_NAME, B_TRUE, response, &sysattrs);
	if (st != 0) {
		goto done;
	}

	nvp = nvlist_next_nvpair(sysattrs, NULL);
	if (nvp == NULL) {
		/* should never happen */
		goto done;
	}

	st = nvpair_value_nvlist(nvp, &nva);
	if (st != 0) {
		goto done;
	}

	/* add the SMF variables */
	for (i = 0; mmscfgopts[i].name != NULL; i++) {
		st = mms_cfg_getvar(mmscfgopts[i].cfgnam, buf);
		if (st != 0) {
			/* probably unset, keep going */
			st = 0;
			continue;
		}
		if (!nvlist_exists(nva, mmscfgopts[i].name)) {
			(void) nvlist_add_string(nva, mmscfgopts[i].name, buf);
		}
	}

	if (st != 0) {
		goto done;
	}

	if (*opts == NULL) {
		st = nvlist_alloc(opts, NV_UNIQUE_NAME, 0);
		if (st != 0) {
			goto done;
		}
	}

	/* don't want a proper name for this list */
	(void) nvlist_add_nvlist(*opts, "", nva);


done:

	if (sysattrs) {
		nvlist_free(sysattrs);
	}

	if (st != 0) {
		nvlist_free(*opts);
		*opts = NULL;
	}

	return (st);
}

/*
 *  Required opts that are not in inopts, and options with invalid values
 *  are added to the argument nvlist "errlist".
 */
int
mms_mgmt_set_opts(nvlist_t *optlist, nvlist_t *errlist)
{
	int			st;
	int			i;
	int			errs = 0;
	char			*opt;
	char			*val;
	mms_mgmt_setopt_t	*optp = mms_server_opts;
	nvpair_t		*nvp;
	int			refresh_svcs = 0;
#ifdef	MMS_VAR_CFG
	int			svc_to_check = 0;
#endif	/* MMS_VAR_CFG */
	int			scf_size = MMS_CFG_MAX_VALUE;
	char			mmtype[scf_size];
	char			buf[scf_size];
	char			cmd[8192];
	char			tid[64];
	void			*session = NULL;
	void			*response = NULL;
	int			count = 0;

	if (optlist == NULL) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	/* check the type of system we're on */
	st = mms_cfg_getvar(MMS_CFG_CONFIG_TYPE, mmtype);
	if (st != 0) {
		return (ENOTSUP);
	}

#ifdef	MMS_VAR_CFG
	if (*mmtype == 'c') {
		svc_to_check = WCR;
	} else {
		svc_to_check = MM|DB;
	}
#endif	/* MMS_VAR_CFG */

	nvp = NULL;
	while ((nvp = nvlist_next_nvpair(optlist, nvp)) != NULL) {

		opt = nvpair_name(nvp);

		if (strcmp(opt, O_OBJTYPE) == 0) {
			/* ignore type on 'set' */
			continue;
		}

		st = nvpair_value_string(nvp, &val);
		if (st != 0) {
			break;
		}

		/* unrecognized options are ignored */
		for (i = 0; optp[i].name != NULL; i++) {
			if (strcmp(opt, optp[i].name) != 0) {
				continue;
			}

			st = 0;

			if (optp[i].validate_func) {
				st = (optp[i].validate_func)(val);
			}
			if (st != 0) {
				errs++;
				if (errlist) {
					(void) nvlist_add_int32(errlist, opt,
					    st);
				}
			}
			break;
		}

		if ((errs) && (!errlist)) {
			st = EINVAL;
			break;
		}
	}

	if (st != 0) {
		goto done;
	}

#ifdef	MMS_VAR_CFG
	/* set SMF config  */
	for (i = 0; mmscfgopts[i].name != NULL; i++) {
		if (strcmp(mmscfgopts[i].name, O_OBJTYPE) == 0) {
			/* again, skip for set */
			continue;
		}
		st = nvlist_lookup_string(optlist,  mmscfgopts[i].name, &val);
		if (st == 0) {
			if (!(svc_to_check & mmscfgopts[i].svc)) {
				st = MMS_MGMT_ERR_SVRONLY;
				MGMT_ADD_ERR(errlist, mmscfgopts[i].name, st);
				continue;
			}
			mms_cfg_setvar(mmscfgopts[i].cfgnam, val);
			refresh_svcs |= mmscfgopts[i].svc;
		}
	}
	st = 0;

	/* set DB opts, if any were specified */
	if (refresh_svcs & DB) {
		st = mgmt_set_db_opts(optlist, errlist);

		if (st != 0) {
			goto done;
		}
	}
#endif	/* MMS_VAR_CFG */

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd), "attribute task['%s'] ", tid);

	for (i = 0; mms_server_opts[i].name != NULL; i++) {
		if (mms_server_opts[i].mmpopt == NULL) {
			continue;
		}
		st = nvlist_lookup_string(optlist, mms_server_opts[i].name,
		    &val);
		if (st != 0) {
			continue;
		}
		if (strcmp(val, "") != 0) {
			/* set */
			(void) snprintf(buf, sizeof (buf),
			    " set[SYSTEM.'%s' '%s']",
			    mms_server_opts[i].mmpopt, val);
		} else {
			/* unset */
			(void) snprintf(buf, sizeof (buf),
			    " unset[SYSTEM.'%s']",
			    mms_server_opts[i].mmpopt);
		}

		(void) strlcat(cmd, buf, sizeof (cmd));
		count++;
	}
	(void) strlcat(cmd, ";", sizeof (cmd));

	/* if no MM opts specified, nothing to set */
	if (count > 0) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &session);
		if (st != 0) {
			goto done;
		}

		st = mms_mgmt_send_cmd(session, tid, cmd, "set system attrs",
		    &response);

		(void) mms_goodbye(session, 0);

		if (st != 0) {
			goto done;
		}
	}

#ifdef	MMS_VAR_CFG
	/* TODO:  set SSL opts */
	st = mgmt_set_ssl(optlist);
	if (st != 0) {
		goto done;
	}
#endif	/* MMS_VAR_CFG */

	/* refresh services */
	if (*mmtype == 's') {
		if (refresh_svcs & DB) {
			(void) mgmt_set_svc_state(DBSVC, REFRESH, NULL);
		}
		if (refresh_svcs & MM) {
			(void) mgmt_set_svc_state(MMSVC, REFRESH, NULL);
		}
	}

	if (refresh_svcs & WCR) {
		(void) mgmt_set_svc_state(WCRSVC, REFRESH, NULL);
	}

done:
	return (st);
}

int
mms_mgmt_uninitialize(void)
{
	int		st = 0;
	char		*mmsvcs[] = {WCRSVC, MMSVC, DBSVC, NULL};
	int		i;

	if (!mgmt_chk_auth("solaris.mms.delete")) {
		return (EACCES);
	}

	/* stop all running services */
	for (i = 0; mmsvcs[i] != NULL; i++) {
		st = mgmt_set_svc_state(mmsvcs[i], DISABLE, NULL);
		if (st != 0) {
			break;
		}
	}

#ifdef	MMS_VAR_CFG
	/* get rid of all the configuration information */
	if (st == 0) {
		mgmt_unsetall_cfgvar();
	}
#endif	/* MMS_VAR_CFG */

	return (st);
}

static int
mgmt_set_pass(char *inpw)
{
	int	st = 0;
	int	fd = -1;
	size_t	sz;
	size_t	szi;
	char	*pf = MMSETCDIR"/passwd/hello.new";
	char	*of = MMSETCDIR"/passwd/hello";

	if (!inpw) {
		return (EINVAL);
	}

	fd = open64(pf, O_CREAT|O_WRONLY|O_NOFOLLOW|O_NOLINKS|O_SYNC|O_TRUNC,
	    0600);

	if (fd == -1) {
		return (errno);
	}

	szi = strlen(inpw) + 1;
	sz = write(fd, inpw, szi);
	if (szi != sz) {
		st = errno;
	}

	(void) close(fd);

	if (st == 0) {
		st = rename(pf, of);
	} else {
		(void) unlink(pf);
	}

	return (st);
}

#ifdef	MMS_VAR_CFG
static int
mgmt_set_ssl(nvlist_t *opts)
{
	char		*val = NULL;


	if (!opts) {
		return (EINVAL);
	}

	nvlist_lookup_string(opts, O_SSLENABLED, &val);
	if ((!val) || (strcmp(val, "false") == 0)) {
		mms_cfg_setvar(MMS_CFG_SSL_ENABLED, "false");
		mms_cfg_unsetvar(MMS_CFG_SSL_CERT_FILE);
		mms_cfg_unsetvar(MMS_CFG_SSL_PASS_FILE);
		mms_cfg_unsetvar(MMS_CFG_SSL_CRL_FILE);
		mms_cfg_unsetvar(MMS_CFG_SSL_PEER_FILE);
		mms_cfg_unsetvar(MMS_CFG_SSL_DH_FILE);
		mms_cfg_unsetvar(MMS_CFG_SSL_VERIFY);
#if TODO
	} else  {
		/* TODO:  Create the certs, etc. for SSL */
		/* leave existng cfg alone for now  */
#endif
	}

	return (0);
}
#endif	/* MMS_VAR_CFG */

int
mms_mgmt_add_application(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	int		nst;
	void		*sess = NULL;
	void		*sessp = session;
	char		tid[64];
	char		cmd[8192];
	char		buf[1024];
	void		*response;
	char		*name;
	char		*val;
	char		*pass;
	int		i;
	mms_mgmt_setopt_t *optp = application_opts;

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &name);
	if (st != 0) {
		if (errs) {
			(void) nvlist_add_int32(errs, O_NAME, st);
		}
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_MMPASS, &pass);
	if (st != 0) {
		if (errs) {
			(void) nvlist_add_int32(errs, O_MMPASS, st);
		}
		return (st);
	}

	(void) mms_gen_taskid(tid);

	(void) snprintf(cmd, sizeof (cmd),
	    "create task['%s'] type[APPLICATION]"
	    " set[APPLICATION.'ApplicationName' '%s']", tid, name);

	for (i = 0; optp[i].name != NULL; i++) {
		if (strcmp(optp[i].name, O_NAME) == 0) {
			continue;
		}
		nst = nvlist_lookup_string(nvl, optp[i].name, &val);
		if (nst == 0) {
			if (optp[i].validate_func) {
				nst = (optp[i].validate_func)(val);
			}
		} else if (nst == ENOENT) {
			if (!(optp[i].required)) {
				nst = 0;
				continue;
			} else if (optp[i].defval) {
				val = optp[i].defval;
			}
		}

		if (nst != 0) {
			st = nst;

			if (errs) {
				(void) nvlist_add_int32(errs, optp[i].name,
				    nst);
			} else {
				/* fail on first error */
				break;
			}
		} else {
			(void) snprintf(buf, sizeof (buf),
			    " set[APPLICATION.'%s' '%s']",
			    optp[i].mmpopt, val);
			(void) strlcat(cmd, buf, sizeof (cmd));
		}
	}
	(void) strlcat(cmd, ";", sizeof (cmd));

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "add application", &response);

	if (st == 0) {
		/* add an application instance for administrative purposes */
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "create task['%s'] type[AI] "
		    "set[AI.'ApplicationName' '%s'] "
		    "set[AI.'AIName' 'admin'] "
		    "set[AI.'SessionsAllowed' 'multiple'];",
		    tid, name);

		st = mms_mgmt_send_cmd(sessp, tid, cmd,
		    "add application instance", &response);
	}

	if (st == 0) {
		st = mms_mgmt_set_pass(sessp, nvl, errs);
	}

	if (st != 0) {
		MGMT_ADD_ERR(errs, name, st);
		(void) mms_mgmt_remove_application(sessp, nvl, errs);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_mgmt_remove_application(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	char		tid[64];
	char		cmd[8192];
	void		*response;
	char		*name;
	uint32_t	volcnt = 0;

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.delete")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &name);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/*
	 * See if there are any volumes in use by this application
	 * before removing it.  Fail the op so we don't lose any
	 * customer data.
	 */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] report[VOLUME] reportmode[number] "
	    "match[streq(VOLUME.'ApplicationName' '%s')];",
	    tid, name);

	st = mms_mgmt_send_cmd(sessp, tid, cmd,
	    "find volumes for app", &response);
	if (st == 0) {
		st = mms_mgmt_mmp_count(response, &volcnt);
		mms_free_rsp(response);
	}

	if (volcnt != 0) {
		st = MMS_MGMT_APP_VOLS_EXIST;
	}

	if (st != 0) {
		goto done;
	}

	/* delete any CARTRIDGEGROUPAPPLICATIONS */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "delete task['%s'] type[CARTRIDGEGROUPAPPLICATION] "
	    "match[streq(CARTRIDGEGROUPAPPLICATION.'ApplicationName' '%s')];",
	    tid, name);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "delete mpool app",
	    &response);

	if (st != 0) {
		goto done;
	}

	/* delete any DRIVEGROUPAPPLICATIONS */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "delete task['%s'] type[DRIVEGROUPAPPLICATION] "
	    "match[streq(DRIVEGROUPAPPLICATION.'ApplicationName' '%s')];",
	    tid, name);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "delete drive app",
	    &response);

	if (st != 0) {
		goto done;
	}

	/* next, delete the application instances. */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "delete task['%s'] type[AI] "
	    "match[streq(AI.'ApplicationName' '%s')];", tid, name);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "delete app instance",
	    &response);
	if (st == 0) {

		/* Finally, the application itself */
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "delete task['%s'] type[APPLICATION]"
		    " match[streq(APPLICATION.'ApplicationName' '%s')];",
		    tid, name);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "delete application",
		    &response);
	}

done:

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_mgmt_modify_application(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	char		tid[64];
	char		cmd[8192];
	char		buf[1024];
	void		*response;
	char		*name;
	char		*val;
	char		*val2;
	nvlist_t	*attrs;
	nvlist_t	*nva;
	nvpair_t	*nvp;
	mms_mgmt_setopt_t *optp = application_opts;
	int		i;
	int		changed = 0;
	int		nst;

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &name);
	if (st != 0) {
		if (errs) {
			(void) nvlist_add_int32(errs, O_NAME, st);
		}
		return (st);
	}

	(void) mms_gen_taskid(tid);

	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] report[APPLICATION] reportmode[namevalue]"
	    " match[streq(APPLICATION.'ApplicationName' '%s')];", tid, name);

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "add application", &response);

	if (st != 0) {
		goto done;
	}

	st = mmp_get_nvattrs("ApplicationName", B_FALSE, response, &attrs);
	if (st != 0) {
		goto done;
	}

	nvp = nvlist_next_nvpair(attrs, NULL);
	if (nvp == NULL) {
		st = EINVAL;
		goto done;
	}
	st = nvpair_value_nvlist(nvp, &nva);
	if (st != 0) {
		goto done;
	}

	(void) mms_gen_taskid(tid);

	(void) snprintf(cmd, sizeof (cmd),
	    "attribute task['%s'] "
	    "match[streq(APPLICATION.'ApplicationName' '%s')] ",
	    tid, name);

	for (i = 0; optp[i].name != NULL; i++) {
		if (strcmp(optp[i].name, O_NAME) == 0) {
			continue;
		}
		if ((nvlist_lookup_string(nvl, optp[i].name, &val)) != 0) {
			continue;
		}

		if (strcmp(val, "") == 0) {
			(void) snprintf(buf, sizeof (buf),
			    " unset[APPLICATION.'%s']", optp[i].mmpopt);
			(void) strlcat(cmd, buf, sizeof (cmd));
			changed++;
		} else {
			nst = nvlist_lookup_string(nva, optp[i].mmpopt, &val2);
			if (nst == 0) {
				if (strcmp(val, val2) == 0) {
					continue;
				}
			}
			(void) snprintf(buf, sizeof (buf),
			    " set[APPLICATION.'%s' '%s']",
			    optp[i].mmpopt, val);
			(void) strlcat(cmd, buf, sizeof (cmd));
			changed++;
		}
	}
	(void) strlcat(cmd, ";", sizeof (cmd));

	if (changed == 0) {
		goto done;
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "modify application",
	    &response);

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_mgmt_set_pass(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*passp = NULL;
	char		*namep = NULL;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &namep);
	if (st != 0) {
		if (errs) {
			(void) nvlist_add_int32(errs, O_NAME, st);
		}
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_MMPASS, &passp);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_MMPASS, st);
		return (st);
	}

	if (strcasecmp(namep, "admin") == 0) {
		namep = "MMS";
	} else if (strcasecmp(namep, "dbadmin") == 0) {
		/* special case - doesn't modify MM at all */
		st = mgmt_set_db_pass(passp, errs);
		return (st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "setpassword task['%s'] password['%s'] name['%s'];",
	    tid, passp, namep);

	st = mms_mgmt_send_cmd(sessp, tid, cmd,
	    "set password", &response);

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (st != 0) {
		MGMT_ADD_ERR(errs, O_MMPASS, st);
	}

	return (st);
}

int
mms_mgmt_list_supported_types(void *session, nvlist_t **supported)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	nvlist_t	*nvl = NULL;


	if (!supported) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_alloc(supported, NV_UNIQUE_NAME, 0);
	if (st != 0) {
		return (st);
	}

	if (!sessp) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] reportmode[namevalue] report[LIBRARYLIST];", tid);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "list supported", &response);
	if (st == 0) {
		st = mmp_get_nvattrs("LibraryString", B_FALSE, response, &nvl);
		mms_free_rsp(response);
		if (st == 0) {
			(void) nvlist_add_nvlist(*supported, "LIBRARY", nvl);
		}
		nvlist_free(nvl);
		nvl = NULL;
	}
	if (st != 0) {
		goto done;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] reportmode[namevalue] report[DRIVELIST];", tid);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "list supported", &response);
	if (st == 0) {
		st = mmp_get_nvattrs("DriveString", B_FALSE, response, &nvl);
		mms_free_rsp(response);
		if (st == 0) {
			(void) nvlist_add_nvlist(*supported, "DRIVE", nvl);
		}
		nvlist_free(nvl);
		nvl = NULL;
	}
	if (st != 0) {
		goto done;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] reportmode[namevalue] "
	    "report[CARTRIDGELIST];", tid);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "list supported", &response);
	if (st == 0) {
		st = mmp_get_nvattrs("CartridgeString", B_FALSE, response,
		    &nvl);
		mms_free_rsp(response);
		if (st == 0) {
			(void) nvlist_add_nvlist(*supported, "CARTRIDGE", nvl);
		}
		nvlist_free(nvl);
		nvl = NULL;
	}

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_mgmt_show_apps(void *session, nvlist_t *nvl, nvlist_t **apps)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	char		buf[2048];
	char		**names = NULL;
	int		count = 0;
	int		i;
	char		*key = O_NAME;

	if (!nvl || !apps) {
		return (MMS_MGMT_NOARG);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	names = var_to_array(nvl, O_NAME, &count);

	(void) mms_gen_taskid(tid);
	if (count == 0) {
		/* show all, filtering out the MMS Admin application */
		(void) snprintf(cmd, sizeof (cmd),
		    "show task['%s'] reportmode[namevalue] "
		    "match[strne(APPLICATION.'ApplicationName' 'MMS')] "
		    "report[APPLICATION];",
		    tid);
	} else {
		(void) snprintf(cmd, sizeof (cmd),
		    "show task['%s'] reportmode[namevalue] "
		    "report[APPLICATION] ",
		    tid);

		if (count > 1) {
			(void) strlcat(cmd, "match[or", sizeof (cmd));
		} else {
			(void) strlcat(cmd, "match[", sizeof (cmd));
		}
		for (i = 0; i < count; i++) {
			(void) snprintf(buf, sizeof (buf),
			    " streq (APPLICATION.'ApplicationName' '%s')",
			    names[i]);
			(void) strlcat(cmd, buf, sizeof (cmd));
		}
		(void) strlcat(cmd, "];", sizeof (cmd));
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "show application",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs(key, B_TRUE, response, apps);
		mms_free_rsp(response);
	}

	if (st != 0) {
		goto done;
	}

	mgmt_filter_results(nvl, *apps);

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (names) {
		mgmt_free_str_arr(names, count);
	}

	return (st);
}

int
mms_mgmt_show_requests(void *session, nvlist_t *nvl, nvlist_t **reqs)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	char		buf[2048];
	char		**names = NULL;
	int		count = 0;
	int		i;
	nvpair_t	*nvp;
	nvlist_t	*nva;
	char		*val;
	char		*key = "request-id";
	char		*tkey = "requestor-type";

	if (!nvl || !reqs) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.request")) {
		return (EACCES);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	names = var_to_array(nvl, O_NAME, &count);

	(void) mms_gen_taskid(tid);
	if (count == 0) {
		/* show all */
		(void) snprintf(cmd, sizeof (cmd),
		    "show task['%s'] reportmode[namevalue] report[REQUEST];",
		    tid);
	} else {
		(void) snprintf(cmd, sizeof (cmd),
		    "show task['%s'] reportmode[namevalue] report[REQUEST] ",
		    tid);

		if (count > 1) {
			(void) strlcat(cmd, "match[or", sizeof (cmd));
		} else {
			(void) strlcat(cmd, "match[", sizeof (cmd));
		}
		for (i = 0; i < count; i++) {
			(void) snprintf(buf, sizeof (buf),
			    " streq (REQUEST.'RequestingClient' '%s')",
			    names[i]);
			(void) strlcat(cmd, buf, sizeof (cmd));
		}
		(void) strlcat(cmd, "];", sizeof (cmd));
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "show oper requests",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs(key, B_TRUE, response,
		    reqs);
		mms_free_rsp(response);
	}

	if (st != 0) {
		goto done;
	}

	nvp = NULL;

	while ((nvp = nvlist_next_nvpair(*reqs, nvp)) != NULL) {
		st = nvpair_value_nvlist(nvp, &nva);
		if (st != 0) {
			continue;
		}
		st = nvlist_lookup_string(nva, tkey, &val);
		if (st == 0) {
			if (strcmp(val, "LM") == 0) {
				val = "library";
			} else if (strcmp(val, "DM") == 0) {
				val = "drive";
			} else if (strcmp(val, "MM") == 0) {
				val = "system";
			}
			(void) nvlist_add_string(nva, tkey, val);
		}
	}

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (names) {
		mgmt_free_str_arr(names, count);
	}

	return (st);
}

int
mms_mgmt_accept_request(void *session, char *reqID, char *text)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	char		*textp = text;

	if (!reqID) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.request")) {
		return (EACCES);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	if (!textp) {
		textp = "ok";
	}

	/* accept responsibility for this request, then respond to it */

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "accept task['%s'] reqid['%s'];",
	    tid, reqID);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "accept oper request",
	    &response);

	if (st == 0) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "respond task['%s'] reqid['%s'] "
		    "message[id ['SUNW' 'MMS' '1000'] loctext ['EN' '%s']];",
		    tid, reqID, textp);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "accept oper request",
		    &response);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_mgmt_reject_request(void *session, char *reqID, char *text)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	char		*textp = text;

	if (!reqID) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.request")) {
		return (EACCES);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	if (!textp) {
		textp = "rejected";
	}

	/* accept responsibility for this request, then respond to it */

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "accept task['%s'] reqid['%s'];",
	    tid, reqID);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "reject oper request",
	    &response);

	if (st == 0) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "respond task['%s'] reqid['%s'] "
		    "message[id ['SUNW' 'MMS' '1000'] loctext ['EN' '%s']];",
		    tid, reqID, textp);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "accept oper request",
		    &response);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}
