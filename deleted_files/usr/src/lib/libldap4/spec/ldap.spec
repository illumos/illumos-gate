#
# Copyright (c) 1998-1999 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libldap/spec/ldap.spec

function	ber_alloc_t
include		<lber.h>, <ldap.h>
declaration	BerElement *ber_alloc_t(int options)
version		SUNW_1.1
exception	$return == NULLBER
end		

function	ber_bvdup
include		<lber.h>, <ldap.h>
declaration	struct berval *ber_bvdup(struct berval *bv)
version		SUNW_1.1
exception	$return == NULL
end		

function	ber_bvecfree
include		<lber.h>, <ldap.h>
declaration	void ber_bvecfree(struct berval **bv)
version		SUNW_1.1
end		

function	ber_bvfree
include		<lber.h>, <ldap.h>
declaration	void ber_bvfree(struct berval *bv)
version		SUNW_1.1
end		

function	ber_first_element
include		<lber.h>, <ldap.h>
declaration	unsigned int ber_first_element(BerElement *ber, \
			unsigned int *len, char **last)
version		SUNW_1.1
end		

function	ber_flatten
include		<lber.h>, <ldap.h>
declaration	int ber_flatten(BerElement *ber, struct berval **bvPtr)
version		SUNW_1.1
exception	$return == -1
end		

function	ber_free
include		<lber.h>, <ldap.h>
declaration	void ber_free(BerElement *ber, int freebuf)
version		SUNW_1.1
end		

function	ber_init
include		<lber.h>, <ldap.h>
declaration	BerElement *ber_init(struct berval *bv)
version		SUNW_1.1
exception	$return == NULLBER
end		

function	ber_next_element
include		<lber.h>, <ldap.h>
declaration	unsigned int ber_next_element(BerElement *ber, \
			unsigned int *len, char *last)
version		SUNW_1.1
end		

function	ber_peek_tag
include		<lber.h>, <ldap.h>
declaration	unsigned int ber_peek_tag(BerElement *ber, unsigned int *len)
version		SUNW_1.1
end		

function	ber_printf
include		<lber.h>, <ldap.h>
declaration	int ber_printf(BerElement *ber, char *fmt, ...)
version		SUNW_1.1
exception	$return == -1
end		

function	ber_scanf
include		<lber.h>, <ldap.h>
declaration	unsigned int ber_scanf(BerElement *ber, char *fmt, ...)
version		SUNW_1.1
exception	$return == LBER_DEFAULT
end		

function	ber_skip_tag
include		<lber.h>, <ldap.h>
declaration	unsigned int ber_skip_tag(BerElement *ber, unsigned int *len)
version		SUNW_1.1
end		

function	ber_get_int
include		<lber.h>
declaration	unsigned int ber_get_int(BerElement *ber, int *num)
version		SUNW_1.2
end

function	ber_alloc
include		<lber.h>
declaration	BerElement *ber_alloc(void)
version		SUNW_1.2
end

function	cldap_close
include		<lber.h>, <ldap.h>
declaration	void cldap_close(LDAP *ld)
version		SUNW_1.1
end		

function	cldap_open
include		<lber.h>, <ldap.h>
declaration	LDAP *cldap_open(char *host, int port)
version		SUNW_1.1
exception	$return == NULL
end		

function	cldap_search_s
include		<lber.h>, <ldap.h>
declaration	int cldap_search_s(LDAP *ld, char *base, int scope, \
			char *filter, char **attrs, int attrsonly, \
			LDAPMessage **res, char *logdn)
version		SUNW_1.1
exception	$return == -1
end		

function	cldap_setretryinfo
include		<lber.h>, <ldap.h>
declaration	void cldap_setretryinfo(LDAP *ld, int tries, time_t timeout)
version		SUNW_1.1
end		

function	i18n_catopen
include		<lber.h>, <ldap.h>
declaration	void i18n_catopen(char *name)
version		SUNWprivate_1.1
end		

function	ldap_abandon
include		<lber.h>, <ldap.h>
declaration	int ldap_abandon(LDAP *ld, int msgid)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_abandon_ext
include		<lber.h>, <ldap.h>
declaration	int ldap_abandon_ext(LDAP *ld, int msgid, \
			LDAPControl **serverctrls, LDAPControl **clientctrls)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_add
include		<lber.h>, <ldap.h>
declaration	int ldap_add(LDAP *ld, char *dn, LDAPMod **attrs)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_add_ext
include		<lber.h>, <ldap.h>
declaration	int ldap_add_ext(LDAP *ld, char *dn, LDAPMod **attrs, \
			LDAPControl **serverctrls, \
			LDAPControl **clientctrls, int *msgidp)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_add_ext_s
include		<lber.h>, <ldap.h>
declaration	int ldap_add_ext_s(LDAP *ld, char *dn, LDAPMod **attrs, LDAPControl **serverctrls, LDAPControl **clientctrls)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_add_s
include		<lber.h>, <ldap.h>
declaration	int ldap_add_s(LDAP *ld, char *dn, LDAPMod **attrs)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_bind
include		<lber.h>, <ldap.h>
declaration	int ldap_bind(LDAP *ld, char *dn, char *passwd, int authmethod)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_bind_s
include		<lber.h>, <ldap.h>
declaration	int ldap_bind_s(LDAP *ld, char *dn, char *passwd, \
			int authmethod)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_build_filter
include		<lber.h>, <ldap.h>
declaration	void ldap_build_filter(char *filtbuf, size_t buflen, \
			char *pattern, char *prefix, char *suffix, \
			char *attr, char *value, char **valwords)
version		SUNW_1.1
end		

function	ldap_compare
include		<lber.h>, <ldap.h>
declaration	int ldap_compare(LDAP *ld, char *dn, char *attr, char *value)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_compare_ext
include		<lber.h>, <ldap.h>
declaration	int ldap_compare_ext(LDAP *ld, char *dn, char *attr, \
			struct berval *bvalue, LDAPControl **serverctrls, \
			LDAPControl **clientctrls, int *msgidp)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_compare_ext_s
include		<lber.h>, <ldap.h>
declaration	int ldap_compare_ext_s(LDAP *ld, char *dn, char *attr, \
			struct berval *bvalue, LDAPControl **serverctrls, \
			LDAPControl **clientctrls)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_compare_s
include		<lber.h>, <ldap.h>
declaration	int ldap_compare_s(LDAP *ld, char *dn, char *attr, char *value)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_control_free
include		<lber.h>, <ldap.h>
declaration	void ldap_control_free (LDAPControl *ctrl)
version		SUNW_1.1
end		

function	ldap_controls_free
include		<lber.h>, <ldap.h>
declaration	void ldap_controls_free (LDAPControl **ctrls)
version		SUNW_1.1
end		

function	ldap_count_entries
include		<lber.h>, <ldap.h>
declaration	int ldap_count_entries(LDAP *ld, LDAPMessage *res)
version		SUNW_1.1
end		

function	ldap_count_messages
include		<lber.h>, <ldap.h>
declaration	int ldap_count_messages(LDAP *ld, LDAPMessage *res)
version		SUNW_1.1
end		

function	ldap_count_references
include		<lber.h>, <ldap.h>
declaration	int ldap_count_references(LDAP *ld, LDAPMessage *res)
version		SUNW_1.1
end		

function	ldap_count_values
include		<lber.h>, <ldap.h>
declaration	int ldap_count_values(char **vals)
version		SUNW_1.1
end		

function	ldap_count_values_len
include		<lber.h>, <ldap.h>
declaration	int ldap_count_values_len(struct berval **vals)
version		SUNW_1.1
end		

function	ldap_create_page_control
include		<lber.h>, <ldap.h>
declaration	int ldap_create_page_control(LDAP *ld, \
			unsigned int pagesize, struct berval *cookie, \
			char isCritical, LDAPControl **output)
version		SUNWprivate_1.1
end		

function	ldap_delete
include		<lber.h>, <ldap.h>
declaration	int ldap_delete(LDAP *ld, char *dn)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_delete_ext
include		<lber.h>, <ldap.h>
declaration	int ldap_delete_ext(LDAP *ld, char *dn, \
			LDAPControl **serverctrls, \
			LDAPControl **clientctrls, int *msgidp)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_delete_ext_s
include		<lber.h>, <ldap.h>
declaration	int ldap_delete_ext_s(LDAP *ld, char *dn, \
			LDAPControl **serverctrls, LDAPControl **clientctrls)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_delete_s
include		<lber.h>, <ldap.h>
declaration	int ldap_delete_s(LDAP *ld, char *dn)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_destroy_cache
include		<lber.h>, <ldap.h>
declaration	void ldap_destroy_cache(LDAP *ld)
version		SUNW_1.1
end		

function	ldap_disable_cache
include		<lber.h>, <ldap.h>
declaration	void ldap_disable_cache(LDAP *ld)
version		SUNW_1.1
end		

function	ldap_dn2ufn
include		<lber.h>, <ldap.h>
declaration	char *ldap_dn2ufn(char *dn)
version		SUNW_1.1
end		

function	ldap_dn_to_url
include		<lber.h>, <ldap.h>
declaration	char *ldap_dn_to_url(LDAP *ld, char*dn, int nameparts)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_dns_to_dn
include		<lber.h>, <ldap.h>
declaration	char *ldap_dns_to_dn(char *dns_name, int *nameparts)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_dns_to_url
include		<lber.h>, <ldap.h>
declaration	char *ldap_dns_to_url(LDAP *ld, char *dns_name, \
			char *attrs, char *scope, char *filter)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_enable_cache
include		<lber.h>, <ldap.h>
declaration	int ldap_enable_cache(LDAP *ld, time_t timeout, ssize_t maxmem)
version		SUNW_1.1
end		

function	ldap_enable_translation
include		<lber.h>, <ldap.h>
declaration	void ldap_enable_translation(LDAP *ld, LDAPMessage *entry, \
			int enable)
version		SUNW_1.1
end		

function	ldap_entry2html
include		<lber.h>, <ldap.h>
declaration	int ldap_entry2html(LDAP *ld, char *buf, LDAPMessage *entry, \
			struct ldap_disptmpl *tmpl, char **defattrs, \
			char ***defvals, writeptype writeproc, \
			void *writeparm, char *eol, int rdncount, \
			unsigned int opts, char *base, char *urlprefix)
version		SUNW_1.1
end		

function	ldap_entry2html_search
include		<lber.h>, <ldap.h>
declaration	int ldap_entry2html_search(LDAP *ld, char *dn, char *base, \
			LDAPMessage *entry, struct ldap_disptmpl*tmpllist, \
			char **defattrs, char ***defvals, \
			writeptype writeproc, void *writeparm, \
			char *eol,int rdncount, unsigned int opts, \
			char *urlprefix)
version		SUNW_1.1
end		

function	ldap_entry2text
include		<lber.h>, <ldap.h>
declaration	int ldap_entry2text(LDAP *ld, char *buf, \
			LDAPMessage *entry, struct ldap_disptmpl *tmpl, \
			char **defattrs, char ***defvals, \
			writeptype writeproc, void *writeparm, char *eol, \
			int rdncount, unsigned int opts)
version		SUNW_1.1
end		

function	ldap_entry2text_search
include		<lber.h>, <ldap.h>
declaration	int ldap_entry2text_search(LDAP *ld,char *dn, char *base, \
			LDAPMessage *entry, struct ldap_disptmpl*tmpllist, \
			char **defattrs, char ***defvals, \
			writeptype writeproc, void *writeparm, \
			char *eol,int rdncount, unsigned int opts)
version		SUNW_1.1
end		

function	ldap_err2string
include		<lber.h>, <ldap.h>
declaration	char *ldap_err2string(int err)
version		SUNW_1.1
end		

function	ldap_explode_dn
include		<lber.h>, <ldap.h>
declaration	char **ldap_explode_dn(char *dn, int notypes)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_explode_dns
include		<lber.h>, <ldap.h>
declaration	char **ldap_explode_dns(char *dn)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_explode_rdn
include		<lber.h>, <ldap.h>
declaration	char **ldap_explode_rdn(char *rdn, int notypes)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_extended_operation
include		<lber.h>, <ldap.h>
declaration	int ldap_extended_operation(LDAP *ld, char *exoid, \
			struct berval *exdata, LDAPControl **serverctrls, \
			LDAPControl**clientctrls, int *msgidp)
version		SUNW_1.1
end		

function	ldap_extended_operation_s
include		<lber.h>, <ldap.h>
declaration	int ldap_extended_operation_s(LDAP *ld, char *exoid, \
			struct berval *exdata, LDAPControl **serverctrls, \
			LDAPControl **clientctrls, char **retoidp, \
			struct berval **retdatap)
version		SUNW_1.1
end		

function	ldap_first_attribute
include		<lber.h>, <ldap.h>
declaration	char *ldap_first_attribute(LDAP *ld, LDAPMessage *entry, \
			BerElement **ber) 
version		SUNW_1.1
end		

function	ldap_first_disptmpl
include		<lber.h>, <ldap.h>
declaration	struct ldap_disptmpl *ldap_first_disptmpl \
			(struct ldap_disptmpl *tmpllist)
version		SUNW_1.1
end		

function	ldap_first_entry
include		<lber.h>, <ldap.h>
declaration	LDAPMessage *ldap_first_entry(LDAP *ld, LDAPMessage *res)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_first_message
include		<lber.h>, <ldap.h>
declaration	LDAPMessage *ldap_first_message(LDAP *ld, LDAPMessage *res)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_first_reference
include		<lber.h>, <ldap.h>
declaration	LDAPMessage *ldap_first_reference(LDAP *ld, LDAPMessage *res)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_first_searchobj
include		<lber.h>, <ldap.h>
declaration	struct ldap_searchobj *ldap_first_searchobj \
			(struct ldap_searchobj *solist) 
version		SUNW_1.1
end		

function	ldap_first_tmplcol
include		<lber.h>, <ldap.h>
declaration	struct ldap_tmplitem *ldap_first_tmplcol \
			(struct ldap_disptmpl *tmpl, \
			struct ldap_tmplitem *row)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_first_tmplrow
include		<lber.h>, <ldap.h>
declaration	struct ldap_tmplitem *ldap_first_tmplrow \
			(struct ldap_disptmpl *tmpl)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_flush_cache
include		<lber.h>, <ldap.h>
declaration	void ldap_flush_cache(LDAP *ld) 
version		SUNW_1.1
end		

function	ldap_free_friendlymap
include		<lber.h>, <ldap.h>
declaration	void ldap_free_friendlymap(FriendlyMap **map) 
version		SUNW_1.1
end		

function	ldap_free_searchprefs
include		<lber.h>, <ldap.h>
declaration	void ldap_free_searchprefs(struct ldap_searchobj *solist) 
version		SUNW_1.1
end		

function	ldap_free_templates
include		<lber.h>, <ldap.h>
declaration	void ldap_free_templates(struct ldap_disptmpl *tmpllist) 
version		SUNW_1.1
end		

function	ldap_free_urldesc
include		<lber.h>, <ldap.h>
declaration	void ldap_free_urldesc(LDAPURLDesc *ludp) 
version		SUNW_1.1
end		

function	ldap_friendly_name
include		<lber.h>, <ldap.h>
declaration	char *ldap_friendly_name(char *filename, char *uname, \
			FriendlyMap **map)
version		SUNW_1.1
end		

function	ldap_get_dn
include		<lber.h>, <ldap.h>
declaration	char *ldap_get_dn(LDAP *ld, LDAPMessage *entry)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_get_option
include		<lber.h>, <ldap.h>
declaration	int ldap_get_option (LDAP *ld, int option, void *outvalue)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_get_reference_urls
include		<lber.h>, <ldap.h>
declaration	char **ldap_get_reference_urls(LDAP *ld, LDAPMessage *res)
version		SUNWprivate_1.1
exception	$return == NULL
end		

function	ldap_get_values
include		<lber.h>, <ldap.h>
declaration	char **ldap_get_values(LDAP *ld, LDAPMessage *entry, \
			char *target)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_get_values_len
include		<lber.h>, <ldap.h>
declaration	struct berval **ldap_get_values_len(LDAP *ld, \
			LDAPMessage *entry, char *target)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_getfilter_free
include		<lber.h>, <ldap.h>
declaration	void ldap_getfilter_free(LDAPFiltDesc *lfdp) 
version		SUNW_1.1
end		

function	ldap_getfirstfilter
include		<lber.h>, <ldap.h>
declaration	LDAPFiltInfo *ldap_getfirstfilter(LDAPFiltDesc *lfdp, \
			char *tagpat, char *value)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_getnextfilter
include		<lber.h>, <ldap.h>
declaration	LDAPFiltInfo *ldap_getnextfilter(LDAPFiltDesc *lfdp)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_init
include		<lber.h>, <ldap.h>
declaration	LDAP *ldap_init(char *defhost, int defport)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_init_getfilter
include		<lber.h>, <ldap.h>
declaration	LDAPFiltDesc *ldap_init_getfilter(char *fname)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_init_getfilter_buf
include		<lber.h>, <ldap.h>
declaration	LDAPFiltDesc *ldap_init_getfilter_buf(char *buf, \
			ssize_t buflen)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_init_searchprefs
include		<lber.h>, <ldap.h>
declaration	int ldap_init_searchprefs(char *file, \
			struct ldap_searchobj **solistp)
version		SUNW_1.1
exception	$return == (int) NULLSEARCHOBJ
end		

function	ldap_init_searchprefs_buf
include		<lber.h>, <ldap.h>
declaration	int ldap_init_searchprefs_buf(char *buf, ssize_t buflen, \
			struct ldap_searchobj **solistp)
version		SUNW_1.1
exception	$return == (int) NULLSEARCHOBJ
end		

function	ldap_init_templates
include		<lber.h>, <ldap.h>
declaration	int ldap_init_templates(char *file, \
			struct ldap_disptmpl **tmpllistp)
version		SUNW_1.1
end		

function	ldap_init_templates_buf
include		<lber.h>, <ldap.h>
declaration	int ldap_init_templates_buf(char *buf, ssize_t buflen, \
			struct ldap_disptmpl **tmpllistp)
version		SUNW_1.1
end		

function	ldap_is_dns_dn
include		<lber.h>, <ldap.h>
declaration	int ldap_is_dns_dn(char *dn)
version		SUNW_1.1
exception	$return == 0
end		

function	ldap_is_ldap_url
include		<lber.h>, <ldap.h>
declaration	int ldap_is_ldap_url(char *url)
version		SUNW_1.1
exception	$return == 0
end		

function	ldap_memfree
include		<lber.h>, <ldap.h>
declaration	void ldap_memfree(char *mem) 
version		SUNW_1.1
end		

function	ldap_modify
include		<lber.h>, <ldap.h>
declaration	int ldap_modify(LDAP *ld, char *dn, LDAPMod **mods)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_modify_ext
include		<lber.h>, <ldap.h>
declaration	int ldap_modify_ext(LDAP *ld, char *dn, LDAPMod **mods, \
			LDAPControl **serverctrls, \
			LDAPControl **clientctrls, int *msgidp)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_modify_ext_s
include		<lber.h>, <ldap.h>
declaration	int ldap_modify_ext_s(LDAP *ld, char *dn, LDAPMod **mods, \
			LDAPControl **serverctrls, LDAPControl **clientctrls)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_modify_s
include		<lber.h>, <ldap.h>
declaration	int ldap_modify_s(LDAP *ld, char *dn, LDAPMod **mods)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_modrdn
include		<lber.h>, <ldap.h>
declaration	int ldap_modrdn(LDAP *ld, char *dn, char *newrdn, \
			int deleteoldrdn)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_modrdn_s
include		<lber.h>, <ldap.h>
declaration	int ldap_modrdn_s(LDAP *ld, char *dn, char *newrdn, \
			int deleteoldrdn)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_mods_free
include		<lber.h>, <ldap.h>
declaration	void ldap_mods_free(LDAPMod **mods, int freemods) 
version		SUNW_1.1
end		

function	ldap_msgfree
include		<lber.h>, <ldap.h>
declaration	int ldap_msgfree(LDAPMessage *lm) 
version		SUNW_1.1
end		

function	ldap_msgid
include		<lber.h>, <ldap.h>
declaration	int ldap_msgid(LDAPMessage *res)
version		SUNW_1.1
exception	$return == LDAP_RES_ANY
end		

function	ldap_msgtype
include		<lber.h>, <ldap.h>
declaration	int ldap_msgtype(LDAPMessage *res)
version		SUNW_1.1
exception	$return == LDAP_RES_ANY
end		

function	ldap_next_attribute
include		<lber.h>, <ldap.h>
declaration	char *ldap_next_attribute(LDAP *ld, LDAPMessage *entry, \
			BerElement *ber)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_next_disptmpl
include		<lber.h>, <ldap.h>
declaration	struct ldap_disptmpl *ldap_next_disptmpl \
			(struct ldap_disptmpl *tmpllist, \
			struct ldap_disptmpl *tmpl)
version		SUNW_1.1
exception	$return == NULLDISPTMPL
end		

function	ldap_next_entry
include		<lber.h>, <ldap.h>
declaration	LDAPMessage *ldap_next_entry(LDAP *ld, LDAPMessage *entry)
version		SUNW_1.1
exception	$return == NULLMSG
end		

function	ldap_next_message
include		<lber.h>, <ldap.h>
declaration	LDAPMessage *ldap_next_message(LDAP *ld, LDAPMessage *msg)
version		SUNW_1.1
exception	$return == NULLMSG
end		

function	ldap_next_reference
include		<lber.h>, <ldap.h>
declaration	LDAPMessage *ldap_next_reference(LDAP *ld, LDAPMessage *entry)
version		SUNW_1.1
exception	$return == NULLMSG
end		

function	ldap_next_searchobj
include		<lber.h>, <ldap.h>
declaration	struct ldap_searchobj *ldap_next_searchobj \
			(struct ldap_searchobj *solist, \
			struct ldap_searchobj *so)
version		SUNW_1.1
exception	$return == NULLSEARCHOBJ
end		

function	ldap_next_tmplcol
include		<lber.h>, <ldap.h>
declaration	struct ldap_tmplitem *ldap_next_tmplcol \
			(struct ldap_disptmpl *tmpl, \
			struct ldap_tmplitem *row, \
			struct ldap_tmplitem *col)
version		SUNW_1.1
exception	$return == NULLTMPLITEM
end		

function	ldap_next_tmplrow
include		<lber.h>, <ldap.h>
declaration	struct ldap_tmplitem *ldap_next_tmplrow \
			(struct ldap_disptmpl *tmpl, \
			struct ldap_tmplitem *row)
version		SUNW_1.1
exception	$return == NULLTMPLITEM
end		

function	ldap_oc2template
include		<lber.h>, <ldap.h>
declaration	struct ldap_disptmpl *ldap_oc2template(char **oclist, \
			struct ldap_disptmpl *tmpllist)
version		SUNW_1.1
exception	$return == NULLDISPTMPL
end		

function	ldap_open
include		<lber.h>, <ldap.h>
declaration	LDAP *ldap_open(char *host, int port)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_parse_extended_result
include		<lber.h>, <ldap.h>
declaration	int ldap_parse_extended_result(LDAP *ld, LDAPMessage *res, \
			char **resultoidp, struct berval **resultdata, \
			int freeit)
version		SUNW_1.1
end		

function	ldap_parse_page_control
include		<lber.h>, <ldap.h>
declaration	int ldap_parse_page_control(LDAP *ld, \
			LDAPControl **controls, unsigned int *totalcount, \
			struct berval **cookie)
version		SUNWprivate_1.1
end		

function	ldap_parse_result
include		<lber.h>, <ldap.h>
declaration	int ldap_parse_result(LDAP *ld, LDAPMessage *res, \
			int *errcodep, char **matcheddnp, char **errmsgp, \
			char ***referralsp, LDAPControl ***serverctrlsp, \
			int freeit)
version		SUNW_1.1
end		

function	ldap_parse_sasl_bind_result
include		<lber.h>, <ldap.h>
declaration	int ldap_parse_sasl_bind_result(LDAP *ld, LDAPMessage *res, \
			struct berval **servercredp, int freeit)
version		SUNW_1.1
end		

function	ldap_perror
include		<lber.h>, <ldap.h>
declaration	void ldap_perror(LDAP *ld, char *s) 
version		SUNW_1.1
end		

function	ldap_rename
include		<lber.h>, <ldap.h>
declaration	int ldap_rename(LDAP *ld, char *dn, char *newrdn, \
			char *newparent, int deleteoldrdn, \
			LDAPControl **serverctrls, \
			LDAPControl **clientctrls, int *msgidp)
version		SUNW_1.1
end		

function	ldap_rename_s
include		<lber.h>, <ldap.h>
declaration	int ldap_rename_s(LDAP *ld, char *dn, char *newrdn, \
			char *newparent, int deleteoldrdn, \
			LDAPControl **serverctrls, LDAPControl **clientctrls)
version		SUNW_1.1
end		

function	ldap_result2error
include		<lber.h>, <ldap.h>
declaration	int ldap_result2error(LDAP *ld, LDAPMessage *r, int freeit)
version		SUNW_1.1
end		

function	ldap_result
include		<lber.h>, <ldap.h>
declaration	int ldap_result(LDAP *ld, int msgid, int all, \
			struct timeval *timeout, LDAPMessage **result)
version		SUNW_1.1
end		

function	ldap_sasl_bind
include		<lber.h>, <ldap.h>
declaration	int ldap_sasl_bind(LDAP *ld, char *dn, char *mechanism, \
			struct berval *cred, LDAPControl **serverctrls, \
			LDAPControl **clientctrls, int *msgidp)
version		SUNW_1.1
end		

function	ldap_sasl_bind_s
include		<lber.h>, <ldap.h>
declaration	int ldap_sasl_bind_s(LDAP *ld, char *dn, char *mechanism, \
			struct berval *cred, LDAPControl **serverctrls, \
			LDAPControl **clientctrls, struct berval **servercredp)
version		SUNW_1.1
end		

function	ldap_sasl_cram_md5_bind_s
include		<lber.h>, <ldap.h>
declaration	int ldap_sasl_cram_md5_bind_s(LDAP *ld, char *dn, \
			struct berval *cred, LDAPControl **serverctrls, \
			LDAPControl **clientctrls)
version		SUNW_1.1
end		

function	ldap_search
include		<lber.h>, <ldap.h>
declaration	int ldap_search(LDAP *ld, char *base, int scope, \
			char *filter, char **attrs, int attrsonly)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_search_ext
include		<lber.h>, <ldap.h>
declaration	int ldap_search_ext(LDAP *ld, char *base, int scope, \
			char *filter, char **attrs, int attrsonly, \
			LDAPControl **serverctrls, LDAPControl **clientctrls, \
			struct timeval *timeoutp, int sizelimit, int *msgidp)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_search_ext_s
include		<lber.h>, <ldap.h>
declaration	int ldap_search_ext_s(LDAP *ld, char *base, int scope, \
			char *filter, char **attrs, int attrsonly, \
			LDAPControl **serverctrls, \
			LDAPControl **clientctrls, struct timeval *timeoutp, \
			int sizelimit, LDAPMessage **res)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_search_s
include		<lber.h>, <ldap.h>
declaration	int ldap_search_s(LDAP *ld, char *base, int scope, \
			char *filter, char **attrs, int attrsonly, \
			LDAPMessage **res)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_search_st
include		<lber.h>, <ldap.h>
declaration	int ldap_search_st(LDAP *ld, char *base, int scope, \
			char *filter, char **attrs, int attrsonly, \
			struct timeval *timeout, LDAPMessage **res)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_set_cache_options
include		<lber.h>, <ldap.h>
declaration	void ldap_set_cache_options(LDAP *ld, unsigned int opts) 
version		SUNW_1.1
end		

function	ldap_set_option
include		<lber.h>, <ldap.h>
declaration	int ldap_set_option (LDAP *ld, int option, void *invalue) 
version		SUNW_1.1
end		

function	ldap_set_rebind_proc
include		<lber.h>, <ldap.h>
declaration	void ldap_set_rebind_proc(LDAP *ld, \
			LDAP_REBIND_FUNCTION *rebindproc, void *extra_arg) 
version		SUNW_1.1
end		

function	ldap_set_string_translators
include		<lber.h>, <ldap.h>
declaration	void ldap_set_string_translators(LDAP *ld, \
			BERTranslateProc encode_proc, \
			BERTranslateProc decode_proc)
version		SUNW_1.1
end		

function	ldap_setfilteraffixes
include		<lber.h>, <ldap.h>
declaration	void ldap_setfilteraffixes(LDAPFiltDesc *lfdp, \
			char *prefix, char *suffix) 
version		SUNW_1.1
end		

function	ldap_simple_bind
include		<lber.h>, <ldap.h>
declaration	int ldap_simple_bind(LDAP *ld, char *dn, char *passwd)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_simple_bind_s
include		<lber.h>, <ldap.h>
declaration	int ldap_simple_bind_s(LDAP *ld, char *dn, char *passwd)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_sort_entries
include		<lber.h>, <ldap.h>
declaration	int ldap_sort_entries(LDAP *ld, LDAPMessage **chain, \
			char *attr, int (*cmp)())
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_sort_strcasecmp
include		<lber.h>, <ldap.h>
declaration	int ldap_sort_strcasecmp(char **a, char **b)
version		SUNW_1.1
end		

function	ldap_sort_values
include		<lber.h>, <ldap.h>
declaration	int ldap_sort_values(LDAP *ld, char **vals, int (*cmp)())
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_tmplattrs
include		<lber.h>, <ldap.h>
declaration	char **ldap_tmplattrs(struct ldap_disptmpl *tmpl, \
			char **includeattrs, int exclude, \
			unsigned int syntaxmask)
version		SUNW_1.1
exception	$return == NULL
end		

function	ldap_translate_from_t61
include		<lber.h>, <ldap.h>
declaration	int ldap_translate_from_t61(LDAP *ld, char **bufp, \
			unsigned int *lenp, int free_input)
version		SUNW_1.1
end		

function	ldap_translate_to_t61
include		<lber.h>, <ldap.h>
declaration	int ldap_translate_to_t61(LDAP *ld, char **bufp, \
			unsigned int *lenp, int free_input)
version		SUNW_1.1
end		

function	ldap_ufn_search_c
include		<lber.h>, <ldap.h>, "ufn.h"
declaration	int ldap_ufn_search_c(LDAP *ld, char *ufn, char **attrs, \
			int attrsonly, LDAPMessage **res, \
			cancelptype cancelproc, void *cancelparm)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_ufn_search_ct
include		<lber.h>, <ldap.h>, "ufn.h"
declaration	int ldap_ufn_search_ct(LDAP *ld, char *ufn, char **attrs, \
			int attrsonly, LDAPMessage **res, \
			cancelptype cancelproc, void *cancelparm, \
			char *tag1, char *tag2, char *tag3)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_ufn_search_s
include		<lber.h>, <ldap.h>
declaration	int ldap_ufn_search_s(LDAP *ld, char *ufn, char **attrs, \
			int attrsonly, LDAPMessage **res)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_ufn_setfilter
include		<lber.h>, <ldap.h>
declaration	LDAPFiltDesc *ldap_ufn_setfilter(LDAP *ld, char *fname) 
version		SUNW_1.1
end		

function	ldap_ufn_setprefix
include		<lber.h>, <ldap.h>
declaration	void ldap_ufn_setprefix(LDAP *ld, char *prefix) 
version		SUNW_1.1
end		

function	ldap_ufn_timeout
include		<lber.h>, <ldap.h>
declaration	int ldap_ufn_timeout(void *tvparam)
version		SUNW_1.1
exception	$return == 0
end		

function	ldap_unbind
include		<lber.h>, <ldap.h>
declaration	int ldap_unbind(LDAP *ld)
version		SUNW_1.1
exception	$return == 0
end		

function	ldap_unbind_s
include		<lber.h>, <ldap.h>
declaration	int ldap_unbind_s(LDAP *ld)
version		SUNW_1.1
exception	$return == 0
end		

function	ldap_uncache_entry
include		<lber.h>, <ldap.h>
declaration	void ldap_uncache_entry(LDAP *ld, char *dn) 
version		SUNW_1.1
end		

function	ldap_uncache_request
include		<lber.h>, <ldap.h>
declaration	void ldap_uncache_request(LDAP *ld, int msgid) 
version		SUNW_1.1
end		

function	ldap_url_parse
include		<lber.h>, <ldap.h>
declaration	int ldap_url_parse(char *url, LDAPURLDesc **ludpp)
version		SUNW_1.1
end		

function	ldap_url_search
include		<lber.h>, <ldap.h>
declaration	int ldap_url_search(LDAP *ld, char *url, int attrsonly)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_url_search_s
include		<lber.h>, <ldap.h>
declaration	int ldap_url_search_s(LDAP *ld, char *url, int attrsonly, \
			LDAPMessage **res)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_url_search_st
include		<lber.h>, <ldap.h>
declaration	int ldap_url_search_st(LDAP *ld, char *url, int attrsonly, \
			struct timeval *timeout, LDAPMessage **res)
version		SUNW_1.1
exception	$return == -1
end		

function	ldap_vals2html
include		<lber.h>, <ldap.h>
declaration	int ldap_vals2html(LDAP *ld, char *buf, char **vals, \
			char *label, int labelwidth, unsigned int syntaxid, \
			writeptype writeproc, void *writeparm, char *eol, \
			int rdncount, char *urlprefix)
version		SUNW_1.1
end		

function	ldap_vals2text
include		<lber.h>, <ldap.h>
declaration	int ldap_vals2text(LDAP *ld, char *buf, char **vals, \
			char *label, int labelwidth, \
			unsigned int syntaxid, writeptype writeproc, \
			void *writeparm, char *eol, int rdncount)
version		SUNW_1.1
end		

function	ldap_value_free
include		<lber.h>, <ldap.h>
declaration	void ldap_value_free(char **vals) 
version		SUNW_1.1
end		

function	ldap_value_free_len
include		<lber.h>, <ldap.h>
declaration	void ldap_value_free_len(struct berval **vals) 
version		SUNW_1.1
end		

function	ldaplogconfigf
include		<lber.h>, <ldap.h>
declaration	void ldaplogconfigf(FILE *fd) 
version		SUNWprivate_1.1
end		

function	ldif_type_and_value
include		<lber.h>, <ldap.h>
declaration	char *ldif_type_and_value(char *type, char *val, int vlen)
version		SUNWprivate_1.1
exception	$return == NULL
end		

function	open_default_ldap_connection
include		<lber.h>, <ldap.h>
declaration	int open_default_ldap_connection(LDAP *ld)
version		SUNW_1.1
end		

function	set_ber_options
include		<lber.h>, <ldap.h>
declaration	void set_ber_options(LDAP *ld, BerElement *ber) 
version		SUNW_1.1
end		

data		slapdcat
include		<lber.h>, <ldap.h>
version		SUNWprivate_1.1
end		

function	str_getline
include		<lber.h>, <ldap.h>
declaration	char *str_getline(char **next)
version		SUNWprivate_1.1
exception	$return == NULL
end		

function	str_parse_line
include		<lber.h>, <ldap.h>
declaration	int str_parse_line(char *line, char **type, \
			char **value, int *vlen)
version		SUNWprivate_1.1
exception	$return == -1
end		

function	ldap_create_sort_control
include		<lber.h>, <ldap.h>
declaration	int ldap_create_sort_control (LDAP *ld, \
			LDAPsortkey **sortKeyList, const char ctl_iscritical, \
			LDAPControl **ctrlp);
version		SUNW_1.1
end		

function	ldap_parse_sort_control
include		<lber.h>, <ldap.h>
declaration	int ldap_parse_sort_control(LDAP *ld, LDAPControl **ctrlp, \
			unsigned long *result, char **attribute);
version		SUNW_1.1
end		

function	ldap_create_sort_keylist
include		<lber.h>, <ldap.h>
declaration	int ldap_create_sort_keylist(LDAPsortkey ***sortKeyList, \
			char *string_rep);
version		SUNW_1.1
end		

function	ldap_free_sort_keylist
include		<lber.h>, <ldap.h>
declaration	void ldap_free_sort_keylist(LDAPsortkey **sortKeyList);
version		SUNW_1.1
end		

function	ldap_create_virtuallist_control
include		<lber.h>, <ldap.h>
declaration	int ldap_create_virtuallist_control(LDAP *ld, \
			LDAPVirtualList *ldvlistp, LDAPControl **ctrlp);
version		SUNW_1.1
end		

function	ldap_parse_virtuallist_control
include		<lber.h>, <ldap.h>
declaration	int ldap_parse_virtuallist_control(LDAP *ld, \
			LDAPControl **ctrls, unsigned long *target_posp, \
			unsigned long *list_sizep, int *errcodep);
version		SUNW_1.1
end		
