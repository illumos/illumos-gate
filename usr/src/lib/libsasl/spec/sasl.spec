#
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libsasl/spec/sasl.spec
#

function	sasl_set_alloc
include		<sasl/sasl.h>
declaration	void sasl_set_alloc(sasl_malloc_t *malloc, \
			sasl_calloc_t *calloc, sasl_realloc_t *realloc, \
			sasl_free_t *free)
version		SUNW_1.1
end

function	sasl_set_mutex
include		<sasl/sasl.h>
declaration	void sasl_set_mutex(sasl_mutex_alloc_t *alloc, \
			sasl_mutex_lock_t *lock, sasl_mutex_unlock_t *unlock, \
			sasl_mutex_free_t *free)
version		SUNW_1.1
end

function	sasl_version
include		<sasl/sasl.h>
declaration	void sasl_version(const char **implementation, int *version)
version		SUNW_1.1
end

function	sasl_done
include		<sasl/sasl.h>
declaration	void sasl_done(void)
version		SUNW_1.1
end

function	sasl_dispose
include		<sasl/sasl.h>
declaration	void sasl_dispose(sasl_conn_t **pconn)
version		SUNW_1.1
end

function	sasl_errstring
include		<sasl/sasl.h>
declaration	const char *sasl_errstring(int saslerr, const char *langlist, \
			const char **outlang)
version		SUNW_1.1
exception	$return == NULL
end

function	sasl_errdetail
include		<sasl/sasl.h>
declaration	const char *sasl_errdetail(sasl_conn_t *conn)
version		SUNW_1.1
exception	$return == NULL
end

function	sasl_seterror
include		<sasl/sasl.h>
declaration	void sasl_seterror(sasl_conn_t *conn, unsigned flags, \
			const char *fmt, ...)
version		SUNW_1.1
end

function	sasl_getprop
include		<sasl/sasl.h>
declaration	int sasl_getprop(sasl_conn_t *conn, int propnum, \
			     const void **pvalue)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_setprop
include		<sasl/sasl.h>
declaration	int sasl_setprop(sasl_conn_t *conn, int propnum, \
			     const void *value)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_idle
include		<sasl/sasl.h>
declaration	int sasl_idle(sasl_conn_t *conn)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_client_init
include		<sasl/sasl.h>
declaration	int sasl_client_init(const sasl_callback_t *callbacks)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_client_new
include		<sasl/sasl.h>
declaration	int sasl_client_new(const char *service, \
			const char *serverFQDN, const char *iplocalport, \
			const char *ipremoteport, \
			const sasl_callback_t *prompt_supp, \
			unsigned flags, sasl_conn_t **pconn)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_client_start
include		<sasl/sasl.h>
declaration	int sasl_client_start(sasl_conn_t *conn, const char *mechlist, \
			sasl_interact_t **prompt_need, const char **clientout, \
			unsigned *clientoutlen, const char **mech)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_client_step
include		<sasl/sasl.h>
declaration	int sasl_client_step(sasl_conn_t *conn, const char *serverin, \
			unsigned serverinlen, sasl_interact_t **prompt_need, \
			const char **clientout, unsigned *clientoutlen)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_server_init
include		<sasl/sasl.h>
declaration	int sasl_server_init(const sasl_callback_t *callbacks, \
			const char *appname)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_server_new
include		<sasl/sasl.h>
declaration	int sasl_server_new(const char *service, \
			const char *serverFQDN, const char *user_realm, \
			const char *iplocalport, const char *ipremoteport, \
			const sasl_callback_t *callbacks, \
			unsigned flags, sasl_conn_t **pconn)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_listmech
include		<sasl/sasl.h>
declaration	int sasl_listmech(sasl_conn_t *conn, const char *user, \
			const char *prefix, const char *sep, \
			const char *suffix, const char **result, \
			unsigned *plen, int *pcount)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_server_start
include		<sasl/sasl.h>
declaration	int sasl_server_start(sasl_conn_t *conn, const char *mech, \
			const char *clientin, unsigned clientinlen, \
			const char **serverout, unsigned *serveroutlen)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_server_step
include		<sasl/sasl.h>
declaration	int sasl_server_step(sasl_conn_t *conn, const char *clientin, \
			unsigned clientinlen, const char **serverout, \
			unsigned *serveroutlen)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_checkpass
include		<sasl/sasl.h>
declaration	int sasl_checkpass(sasl_conn_t *conn, \
			const char *user, unsigned userlen, \
			const char *pass, unsigned passlen)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_user_exists
include		<sasl/sasl.h>
declaration	int sasl_user_exists(sasl_conn_t *conn, const char *service, \
			const char *user_realm, const char *user)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_setpass
include		<sasl/sasl.h>
declaration	int sasl_setpass(sasl_conn_t *conn, const char *user, \
			const char *pass, unsigned passlen, \
			const char *oldpass, unsigned oldpasslen, \
			unsigned flags)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_auxprop_request
include		<sasl/sasl.h>
declaration	int sasl_auxprop_request(sasl_conn_t *conn, \
			const char **propnames)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_auxprop_getctx
include		<sasl/sasl.h>
declaration	struct propctx *sasl_auxprop_getctx(sasl_conn_t *conn)
version		SUNW_1.1
exception	$return == NULL
end

function	sasl_encode
include		<sasl/sasl.h>
declaration	int sasl_encode(sasl_conn_t *conn, \
			const char *input, unsigned inputlen, \
			const char **output, unsigned *outputlen)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_encodev
include		<sasl/sasl.h>
declaration	int sasl_encodev(sasl_conn_t *conn, \
			const struct iovec *invec, unsigned numiov, \
			const char **output, unsigned *outputlen)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_decode
include		<sasl/sasl.h>
declaration	int sasl_decode(sasl_conn_t *conn, \
			const char *input, unsigned inputlen, \
			const char **output, unsigned *outputlen)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_global_listmech
include		<sasl/sasl.h>
declaration	const char ** sasl_global_listmech(void)
version		SUNW_1.1
exception	$return == NULL
end

function	sasl_checkapop
include		<sasl/sasl.h>
declaration	int sasl_checkapop(sasl_conn_t *conn, \
			const char *challenge, unsigned challen, \
			const char *response, unsigned resplen)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_client_add_plugin
include		<sasl/saslplug.h>
declaration	int sasl_client_add_plugin(const char *plugname, \
			sasl_client_plug_init_t *cplugfunc)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_server_add_plugin
include		<sasl/saslplug.h>
declaration	int sasl_server_add_plugin(const char *plugname, \
			sasl_server_plug_init_t *splugfunc)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_canonuser_add_plugin
include		<sasl/saslplug.h>
declaration	int sasl_canonuser_add_plugin(const char *plugname, \
			sasl_canonuser_init_t *canonuserfunc)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_auxprop_add_plugin
include		<sasl/saslplug.h>
declaration	int sasl_auxprop_add_plugin(const char *plugname, \
			sasl_auxprop_init_t *auxpropfunc)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_decode64
include		<sasl/saslutil.h>
declaration	int sasl_decode64(const char *in, unsigned inlen, \
			char *out, unsigned outmax, unsigned *outlen)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_encode64
include		<sasl/saslutil.h>
declaration	int sasl_encode64(const char *in, unsigned inlen, \
			char *out, unsigned outmax, unsigned *outlen)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_utf8verify
include		<sasl/saslutil.h>
declaration	int sasl_utf8verify(const char *str, unsigned len)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	sasl_erasebuffer
include		<sasl/saslutil.h>
declaration	void sasl_erasebuffer(char *pass, unsigned len)
version		SUNW_1.1
end

function	prop_new
include		<sasl/prop.h>
declaration	struct propctx *prop_new(unsigned estimate)
version		SUNW_1.1
exception	$return == NULL
end

function	prop_dup
include		<sasl/prop.h>
declaration	int prop_dup(struct propctx *src_ctx, \
			struct propctx **dst_ctx)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	prop_request
include		<sasl/prop.h>
declaration	int prop_request(struct propctx *ctx, const char **names)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	prop_get
include		<sasl/prop.h>
declaration	const struct propval *prop_get(struct propctx *ctx)
version		SUNW_1.1
exception	$return == NULL
end

function	prop_getnames
include		<sasl/prop.h>
declaration	int prop_getnames(struct propctx *ctx, const char **names, \
			struct propval *vals)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	prop_clear
include		<sasl/prop.h>
declaration	void prop_clear(struct propctx *ctx, int requests)
version		SUNW_1.1
end

function	prop_erase
include		<sasl/prop.h>
declaration	void prop_erase(struct propctx *ctx, const char *name)
version		SUNW_1.1
end

function	prop_dispose
include		<sasl/prop.h>
declaration	void prop_dispose(struct propctx **ctx)
version		SUNW_1.1
end

function	prop_format
include		<sasl/prop.h>
declaration	int prop_format(struct propctx *ctx, const char *sep, \
			int seplen, char *outbuf, unsigned outmax, \
			unsigned *outlen)
version		SUNW_1.1
exception	$return == SASL_FAIL
end

function	prop_set
include		<sasl/prop.h>
declaration	int prop_set(struct propctx *ctx, const char *name, \
			const char *value, int vallen)
version		SUNW_1.1
exception	$return == NULL
end

function	prop_setvals
include		<sasl/prop.h>
declaration	int prop_setvals(struct propctx *ctx, const char *name, \
			const char **values)
version		SUNW_1.1
exception	$return == NULL
end

function	sasl_create_context
declaration	void *sasl_create_context(void)
version		SUNWprivate_1.1
exception	$return == NULL
end

function	sasl_free_context
declaration	void sasl_free_context(void *ctx)
version		SUNWprivate_1.1
end

function	_sasl_client_init
include		<sasl/sasl.h>
declaration	int _sasl_client_init(void *ctx, \
			const sasl_callback_t *callbacks)
version		SUNWprivate_1.1
exception	$return == SASL_FAIL
end

function	_sasl_client_new
include		<sasl/sasl.h>
declaration	int _sasl_client_new(void *ctx, const char *service, \
			const char *serverFQDN, const char *iplocalport, \
			const char *ipremoteport, \
			const sasl_callback_t *prompt_supp, \
			unsigned flags, sasl_conn_t **pconn)
version		SUNWprivate_1.1
exception	$return == SASL_FAIL
end

function	_sasl_server_init
include		<sasl/sasl.h>
declaration	int _sasl_server_init(void *ctx, \
			const sasl_callback_t *callbacks, const char *appname)
version		SUNWprivate_1.1
exception	$return == SASL_FAIL
end

function	_sasl_server_new
include		<sasl/sasl.h>
declaration	int _sasl_server_new(void *ctx, const char *service, \
			const char *serverFQDN, const char *user_realm, \
			const char *iplocalport, const char *ipremoteport, \
			const sasl_callback_t *callbacks, \
			unsigned flags, sasl_conn_t **pconn)
version		SUNWprivate_1.1
exception	$return == SASL_FAIL
end

function	_sasl_client_add_plugin
include		<sasl/saslplug.h>
declaration	int _sasl_client_add_plugin(void *ctx, const char *plugname, \
			sasl_client_plug_init_t *cplugfunc)
version		SUNWprivate_1.1
exception	$return == SASL_FAIL
end

function	_sasl_server_add_plugin
include		<sasl/saslplug.h>
declaration	int _sasl_server_add_plugin(void *ctx, const char *plugname, \
			sasl_server_plug_init_t *splugfunc)
version		SUNWprivate_1.1
exception	$return == SASL_FAIL
end

function	_sasl_canonuser_add_plugin
include		<sasl/saslplug.h>
declaration	int _sasl_canonuser_add_plugin(void *ctx, \
			const char *plugname, \
			sasl_canonuser_init_t *canonuserfunc)
version		SUNWprivate_1.1
exception	$return == SASL_FAIL
end

function	_sasl_auxprop_add_plugin
include		<sasl/saslplug.h>
declaration	int _sasl_auxprop_add_plugin(void *ctx, const char *plugname, \
			sasl_auxprop_init_t *auxpropfunc)
version		SUNWprivate_1.1
exception	$return == SASL_FAIL
end
