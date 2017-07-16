/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h> /* getenv, exit */
#include <signal.h>
#include <sys/types.h>
#include <memory.h>
#include <stropts.h>
#include <netconfig.h>
#include <sys/resource.h> /* rlimit */
#include <syslog.h>

#include <kadm5/admin.h>
#include <kadm5/kadm_rpc.h>
#include <kadm5/server_internal.h>
#include <server_acl.h>
#include <krb5/adm_proto.h>
#include <string.h>
#include <gssapi_krb5.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <libintl.h>
#include <kdb/kdb_log.h>
#include "misc.h"

extern int setup_gss_names(struct svc_req *, char **, char **);
extern gss_name_t get_clnt_name(struct svc_req *);
extern char *client_addr(struct svc_req *, char *);
extern void *global_server_handle;
extern int nofork;
extern short l_port;
static char abuf[33];

static char *reply_ok_str	= "UPDATE_OK";
static char *reply_err_str	= "UPDATE_ERROR";
static char *reply_fr_str	= "UPDATE_FULL_RESYNC_NEEDED";
static char *reply_busy_str	= "UPDATE_BUSY";
static char *reply_nil_str	= "UPDATE_NIL";
static char *reply_perm_str	= "UPDATE_PERM_DENIED";
static char *reply_unknown_str	= "<UNKNOWN_CODE>";

#define	LOG_UNAUTH  gettext("Unauthorized request: %s, %s, " \
			"client=%s, service=%s, addr=%s")
#define	LOG_DONE    gettext("Request: %s, %s, %s, client=%s, " \
			"service=%s, addr=%s")

#define	KDB5_UTIL_DUMP_STR "/usr/sbin/kdb5_util dump -i "

#ifdef	DPRINT
#undef	DPRINT
#endif
#define	DPRINT(i) if (nofork) printf i

#ifdef POSIX_SIGNALS
static struct sigaction s_action;
#endif /* POSIX_SIGNALS */

static void
debprret(char *w, update_status_t ret, kdb_sno_t sno)
{
	switch (ret) {
	case UPDATE_OK:
		printf("%s: end (OK, sno=%u)\n",
		    w, sno);
		break;
	case UPDATE_ERROR:
		printf("%s: end (ERROR)\n", w);
		break;
	case UPDATE_FULL_RESYNC_NEEDED:
		printf("%s: end (FR NEEDED)\n", w);
		break;
	case UPDATE_BUSY:
		printf("%s: end (BUSY)\n", w);
		break;
	case UPDATE_NIL:
		printf("%s: end (NIL)\n", w);
		break;
	case UPDATE_PERM_DENIED:
		printf("%s: end (PERM)\n", w);
		break;
	default:
		printf("%s: end (UNKNOWN return code (%d))\n", w, ret);
	}
}

static char *
replystr(update_status_t ret)
{
	switch (ret) {
	case UPDATE_OK:
		return (reply_ok_str);
	case UPDATE_ERROR:
		return (reply_err_str);
	case UPDATE_FULL_RESYNC_NEEDED:
		return (reply_fr_str);
	case UPDATE_BUSY:
		return (reply_busy_str);
	case UPDATE_NIL:
		return (reply_nil_str);
	case UPDATE_PERM_DENIED:
		return (reply_perm_str);
	default:
		return (reply_unknown_str);
	}
}

kdb_incr_result_t *
iprop_get_updates_1(kdb_last_t *arg, struct svc_req *rqstp)
{
	static kdb_incr_result_t ret;
	char *whoami = "iprop_get_updates_1";
	int kret;
	kadm5_server_handle_t handle = global_server_handle;
	char *client_name = NULL, *service_name = NULL;
	gss_name_t name = NULL;
	OM_uint32 min_stat;
	char obuf[256] = {0};

	/* default return code */
	ret.ret = UPDATE_ERROR;

	DPRINT(("%s: start, last_sno=%u\n", whoami, (ulong_t)arg->last_sno));

	if (!handle) {
		krb5_klog_syslog(LOG_ERR,
				gettext("%s: server handle is NULL"),
					whoami);
		goto out;
	}

	if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
		krb5_klog_syslog(LOG_ERR,
			gettext("%s: setup_gss_names failed"),
			whoami);
		goto out;
	}

	DPRINT(("%s: clprinc=`%s'\n\tsvcprinc=`%s'\n",
		whoami, client_name, service_name));

	if (!(name = get_clnt_name(rqstp))) {
		krb5_klog_syslog(LOG_ERR,
			gettext("%s: Couldn't obtain client's name"),
			whoami);
		goto out;
	}
	if (!kadm5int_acl_check(handle->context,
		    name,
		    ACL_IPROP,
		    NULL,
		    NULL)) {
		ret.ret = UPDATE_PERM_DENIED;

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    whoami,
				    "<null>", client_name);
		krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, whoami,
				"<null>", client_name, service_name,
				client_addr(rqstp, abuf));
		goto out;
	}

	kret = ulog_get_entries(handle->context, *arg, &ret);

	if (ret.ret == UPDATE_OK) {
		(void) snprintf(obuf, sizeof (obuf),
		gettext("%s; Incoming SerialNo=%u; Outgoing SerialNo=%u"),
				replystr(ret.ret),
				(ulong_t)arg->last_sno,
				(ulong_t)ret.lastentry.last_sno);
	} else {
		(void) snprintf(obuf, sizeof (obuf),
		gettext("%s; Incoming SerialNo=%u; Outgoing SerialNo=N/A"),
				replystr(ret.ret),
				(ulong_t)arg->last_sno);
	}

	audit_kadmind_auth(rqstp->rq_xprt, l_port,
			whoami,
			obuf, client_name, kret);

	krb5_klog_syslog(LOG_NOTICE, LOG_DONE, whoami,
			obuf,
			((kret == 0) ? "success" : error_message(kret)),
			client_name, service_name,
			client_addr(rqstp, abuf));

out:
	if (nofork)
		debprret(whoami, ret.ret, ret.lastentry.last_sno);
	if (client_name)
		free(client_name);
	if (service_name)
		free(service_name);
	if (name)
		gss_release_name(&min_stat, &name);
	return (&ret);
}


/*
 * Given a client princ (foo/fqdn@R), copy (in arg cl) the fqdn substring.
 * Return arg cl str ptr on success, else NULL.
 */
static char *
getclhoststr(char *clprinc, char *cl, int len)
{
	char *s;
	if (s = strchr(clprinc, '/')) {
		if (!++s || strlcpy(cl, s, len) >= len) {
			return (NULL);
		}
		if (s = strchr(cl, '@')) {
			*s = '\0';
			return (cl); /* success */
		}
	}

	return (NULL);
}

kdb_fullresync_result_t *
iprop_full_resync_1(
	/* LINTED */
	void *argp,
	struct svc_req *rqstp)
{
	static kdb_fullresync_result_t ret;
	char tmpf[MAX_FILENAME] = {0};
	char ubuf[MAX_FILENAME + sizeof (KDB5_UTIL_DUMP_STR)] = {0};
	char clhost[MAXHOSTNAMELEN] = {0};
	int pret, fret;
	kadm5_server_handle_t handle = global_server_handle;
	OM_uint32 min_stat;
	gss_name_t name = NULL;
	char *client_name = NULL, *service_name = NULL;
	char *whoami = "iprop_full_resync_1";

	/* default return code */
	ret.ret = UPDATE_ERROR;

	if (!handle) {
		krb5_klog_syslog(LOG_ERR,
				gettext("%s: server handle is NULL"),
					whoami);
		goto out;
	}

	DPRINT(("%s: start\n", whoami));

	if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
		krb5_klog_syslog(LOG_ERR,
			gettext("%s: setup_gss_names failed"),
			whoami);
		goto out;
	}

	DPRINT(("%s: clprinc=`%s'\n\tsvcprinc=`%s'\n",
		whoami, client_name, service_name));

	if (!(name = get_clnt_name(rqstp))) {
		krb5_klog_syslog(LOG_ERR,
			gettext("%s: Couldn't obtain client's name"),
			whoami);
		goto out;
	}
	if (!kadm5int_acl_check(handle->context,
		    name,
		    ACL_IPROP,
		    NULL,
		    NULL)) {
		ret.ret = UPDATE_PERM_DENIED;

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    whoami,
				    "<null>", client_name);
		krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, whoami,
				"<null>", client_name, service_name,
				client_addr(rqstp, abuf));
		goto out;
	}

	if (!getclhoststr(client_name, clhost, sizeof (clhost))) {
		krb5_klog_syslog(LOG_ERR,
			gettext("%s: getclhoststr failed"),
			whoami);
		goto out;
	}

	/*
	 * construct db dump file name; kprop style name + clnt fqdn
	 */
	(void) strcpy(tmpf, "/var/krb5/slave_datatrans_");
	if (strlcat(tmpf, clhost, sizeof (tmpf)) >= sizeof (tmpf)) {
		krb5_klog_syslog(LOG_ERR,
		gettext("%s: db dump file name too long; max length=%d"),
				whoami,
				(sizeof (tmpf) - 1));
		goto out;
	}

	/*
	 * note the -i; modified version of kdb5_util dump format
	 * to include sno (serial number)
	 */
	if (strlcpy(ubuf, KDB5_UTIL_DUMP_STR, sizeof (ubuf)) >=
	    sizeof (ubuf)) {
		goto out;
	}
	if (strlcat(ubuf, tmpf, sizeof (ubuf)) >= sizeof (ubuf)) {
		krb5_klog_syslog(LOG_ERR,
		gettext("%s: kdb5 util dump string too long; max length=%d"),
				whoami,
				(sizeof (ubuf) - 1));
		goto out;
	}

	/*
	 * Fork to dump the db and xfer it to the slave.
	 * (the fork allows parent to return quickly and the child
	 * acts like a callback to the slave).
	 */
	fret = fork();
	DPRINT(("%s: fork=%d (%d)\n", whoami, fret, getpid()));

	switch (fret) {
	case -1: /* error */
		if (nofork) {
			perror(whoami);
		}
		krb5_klog_syslog(LOG_ERR,
				gettext("%s: fork failed: %s"),
				whoami,
				error_message(errno));
		goto out;

	case 0: /* child */
		DPRINT(("%s: run `%s' ...\n", whoami, ubuf));
#ifdef POSIX_SIGNALS
		(void) sigemptyset(&s_action.sa_mask);
		s_action.sa_handler = SIG_DFL;
		(void) sigaction(SIGCHLD, &s_action, (struct sigaction *) NULL);
#else
		(void) signal(SIGCHLD, SIG_DFL);
#endif /* POSIX_SIGNALS */
		/* run kdb5_util(1M) dump for IProp */
		pret = pclose(popen(ubuf, "w"));
		DPRINT(("%s: pclose=%d\n", whoami, pret));
		if (pret == -1) {
			if (nofork) {
				perror(whoami);
			}
			krb5_klog_syslog(LOG_ERR,
				gettext("%s: pclose(popen) failed: %s"),
					whoami,
					error_message(errno));
			goto out;
		}

		DPRINT(("%s: exec `kprop -f %s %s' ...\n",
			whoami, tmpf, clhost));
		pret = execl("/usr/lib/krb5/kprop", "kprop", "-f", tmpf,
			    clhost, NULL);
		if (pret == -1) {
			if (nofork) {
				perror(whoami);
			}
			krb5_klog_syslog(LOG_ERR,
					gettext("%s: exec failed: %s"),
					whoami,
					error_message(errno));
			goto out;
		}
		/* NOTREACHED */
		break;

	default: /* parent */
		ret.ret = UPDATE_OK;
		/* not used by slave (sno is retrieved from kdb5_util dump) */
		ret.lastentry.last_sno = 0;
		ret.lastentry.last_time.seconds = 0;
		ret.lastentry.last_time.useconds = 0;

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				whoami,
				"<null>", client_name, 0);

		krb5_klog_syslog(LOG_NOTICE, LOG_DONE, whoami,
				"<null>",
				"success",
				client_name, service_name,
				client_addr(rqstp, abuf));

		goto out;
	}

out:
	if (nofork)
		debprret(whoami, ret.ret, 0);
	if (client_name)
		free(client_name);
	if (service_name)
		free(service_name);
	if (name)
		gss_release_name(&min_stat, &name);
	return (&ret);
}

void
krb5_iprop_prog_1(
	struct svc_req *rqstp,
	register SVCXPRT *transp)
{
	union {
		kdb_last_t iprop_get_updates_1_arg;
	} argument;
	char *result;
	bool_t (*_xdr_argument)(), (*_xdr_result)();
	char *(*local)();
	char *whoami = "krb5_iprop_prog_1";

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply(transp, xdr_void,
			(char *)NULL);
		return;

	case IPROP_GET_UPDATES:
		_xdr_argument = xdr_kdb_last_t;
		_xdr_result = xdr_kdb_incr_result_t;
		local = (char *(*)()) iprop_get_updates_1;
		break;

	case IPROP_FULL_RESYNC:
		_xdr_argument = xdr_void;
		_xdr_result = xdr_kdb_fullresync_result_t;
		local = (char *(*)()) iprop_full_resync_1;
		break;

	default:
		krb5_klog_syslog(LOG_ERR,
				gettext("RPC unknown request: %d (%s)"),
				rqstp->rq_proc, whoami);
		svcerr_noproc(transp);
		return;
	}
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, _xdr_argument, (caddr_t)&argument)) {
		krb5_klog_syslog(LOG_ERR,
				gettext("RPC svc_getargs failed (%s)"),
				whoami);
		svcerr_decode(transp);
		return;
	}
	result = (*local)(&argument, rqstp);

	if (_xdr_result && result != NULL &&
	    !svc_sendreply(transp, _xdr_result, result)) {
		krb5_klog_syslog(LOG_ERR,
				gettext("RPC svc_sendreply failed (%s)"),
				whoami);
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, _xdr_argument, (caddr_t)&argument)) {
		krb5_klog_syslog(LOG_ERR,
				gettext("RPC svc_freeargs failed (%s)"),
				whoami);

		exit(1);
	}

	if (rqstp->rq_proc == IPROP_GET_UPDATES) {
		/* LINTED */
		kdb_incr_result_t *r = (kdb_incr_result_t *)result;

		if (r->ret == UPDATE_OK) {
			ulog_free_entries(r->updates.kdb_ulog_t_val,
					r->updates.kdb_ulog_t_len);
			r->updates.kdb_ulog_t_val = NULL;
			r->updates.kdb_ulog_t_len = 0;
		}
	}

}

/*
 * Get the host base service name for the kiprop principal. Returns
 * KADM5_OK on success. Caller must free the storage allocated for
 * host_service_name.
 */
kadm5_ret_t
kiprop_get_adm_host_srv_name(
	krb5_context context,
	const char *realm,
	char **host_service_name)
{
	kadm5_ret_t ret;
	char *name;
	char *host;

	if (ret = kadm5_get_master(context, realm, &host))
		return (ret);

	name = malloc(strlen(KIPROP_SVC_NAME)+ strlen(host) + 2);
	if (name == NULL) {
		free(host);
		return (ENOMEM);
	}
	(void) sprintf(name, "%s@%s", KIPROP_SVC_NAME, host);
	free(host);
	*host_service_name = name;

	return (KADM5_OK);
}
