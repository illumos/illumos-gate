#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2012 Nexenta Systems, Inc. All rights reserved.
#

file path=usr/share/man/man3ldap/ber_decode.3ldap
file path=usr/share/man/man3ldap/ber_encode.3ldap
file path=usr/share/man/man3ldap/cldap_close.3ldap
file path=usr/share/man/man3ldap/cldap_open.3ldap
file path=usr/share/man/man3ldap/cldap_search_s.3ldap
file path=usr/share/man/man3ldap/cldap_setretryinfo.3ldap
file path=usr/share/man/man3ldap/ldap.3ldap
file path=usr/share/man/man3ldap/ldap_abandon.3ldap
file path=usr/share/man/man3ldap/ldap_add.3ldap
file path=usr/share/man/man3ldap/ldap_ber_free.3ldap
file path=usr/share/man/man3ldap/ldap_bind.3ldap
file path=usr/share/man/man3ldap/ldap_charset.3ldap
file path=usr/share/man/man3ldap/ldap_compare.3ldap
file path=usr/share/man/man3ldap/ldap_control_free.3ldap
file path=usr/share/man/man3ldap/ldap_delete.3ldap
file path=usr/share/man/man3ldap/ldap_disptmpl.3ldap
file path=usr/share/man/man3ldap/ldap_entry2text.3ldap
file path=usr/share/man/man3ldap/ldap_error.3ldap
file path=usr/share/man/man3ldap/ldap_first_attribute.3ldap
file path=usr/share/man/man3ldap/ldap_first_entry.3ldap
file path=usr/share/man/man3ldap/ldap_first_message.3ldap
file path=usr/share/man/man3ldap/ldap_friendly.3ldap
file path=usr/share/man/man3ldap/ldap_get_dn.3ldap
file path=usr/share/man/man3ldap/ldap_get_entry_controls.3ldap
file path=usr/share/man/man3ldap/ldap_get_lang_values.3ldap
file path=usr/share/man/man3ldap/ldap_get_option.3ldap
file path=usr/share/man/man3ldap/ldap_get_values.3ldap
file path=usr/share/man/man3ldap/ldap_getfilter.3ldap
file path=usr/share/man/man3ldap/ldap_memcache.3ldap
file path=usr/share/man/man3ldap/ldap_memfree.3ldap
file path=usr/share/man/man3ldap/ldap_modify.3ldap
file path=usr/share/man/man3ldap/ldap_modrdn.3ldap
file path=usr/share/man/man3ldap/ldap_open.3ldap
file path=usr/share/man/man3ldap/ldap_parse_result.3ldap
file path=usr/share/man/man3ldap/ldap_result.3ldap
file path=usr/share/man/man3ldap/ldap_search.3ldap
file path=usr/share/man/man3ldap/ldap_searchprefs.3ldap
file path=usr/share/man/man3ldap/ldap_sort.3ldap
file path=usr/share/man/man3ldap/ldap_ufn.3ldap
file path=usr/share/man/man3ldap/ldap_url.3ldap
file path=usr/share/man/man3ldap/ldap_version.3ldap
link path=usr/share/man/man3ldap/ber_alloc.3ldap target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ber_alloc_t.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_bvdup.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_bvecfree.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_bvfree.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_first_element.3ldap \
    target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_flatten.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_free.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_get_bitstring.3ldap \
    target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_get_boolean.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_get_int.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_get_next.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_get_null.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_get_stringa.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_get_stringal.3ldap \
    target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_get_stringb.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_init.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_next_element.3ldap \
    target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_peek_tag.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_printf.3ldap target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ber_put_bitstring.3ldap \
    target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ber_put_boolean.3ldap target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ber_put_int.3ldap target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ber_put_null.3ldap target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ber_put_ostring.3ldap target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ber_put_seq.3ldap target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ber_put_set.3ldap target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ber_put_string.3ldap target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ber_scanf.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_skip_tag.3ldap target=ber_decode.3ldap
link path=usr/share/man/man3ldap/ber_start_seq.3ldap target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ber_start_set.3ldap target=ber_encode.3ldap
link path=usr/share/man/man3ldap/ldap_8859_to_t61.3ldap \
    target=ldap_charset.3ldap
link path=usr/share/man/man3ldap/ldap_add_ext.3ldap target=ldap_add.3ldap
link path=usr/share/man/man3ldap/ldap_add_ext_s.3ldap target=ldap_add.3ldap
link path=usr/share/man/man3ldap/ldap_add_s.3ldap target=ldap_add.3ldap
link path=usr/share/man/man3ldap/ldap_bind_s.3ldap target=ldap_bind.3ldap
link path=usr/share/man/man3ldap/ldap_build_filter.3ldap \
    target=ldap_getfilter.3ldap
link path=usr/share/man/man3ldap/ldap_compare_ext.3ldap \
    target=ldap_compare.3ldap
link path=usr/share/man/man3ldap/ldap_compare_ext_s.3ldap \
    target=ldap_compare.3ldap
link path=usr/share/man/man3ldap/ldap_compare_s.3ldap \
    target=ldap_compare.3ldap
link path=usr/share/man/man3ldap/ldap_controls_free.3ldap \
    target=ldap_control_free.3ldap
link path=usr/share/man/man3ldap/ldap_count_entries.3ldap \
    target=ldap_first_entry.3ldap
link path=usr/share/man/man3ldap/ldap_count_messages.3ldap \
    target=ldap_first_message.3ldap
link path=usr/share/man/man3ldap/ldap_count_references.3ldap \
    target=ldap_first_entry.3ldap
link path=usr/share/man/man3ldap/ldap_count_values.3ldap \
    target=ldap_get_values.3ldap
link path=usr/share/man/man3ldap/ldap_count_values_len.3ldap \
    target=ldap_get_values.3ldap
link path=usr/share/man/man3ldap/ldap_delete_ext.3ldap \
    target=ldap_delete.3ldap
link path=usr/share/man/man3ldap/ldap_delete_ext_s.3ldap \
    target=ldap_delete.3ldap
link path=usr/share/man/man3ldap/ldap_delete_s.3ldap target=ldap_delete.3ldap
link path=usr/share/man/man3ldap/ldap_dn2ufn.3ldap target=ldap_get_dn.3ldap
link path=usr/share/man/man3ldap/ldap_dn_to_url.3ldap target=ldap_url.3ldap
link path=usr/share/man/man3ldap/ldap_dns_to_dn.3ldap target=ldap_get_dn.3ldap
link path=usr/share/man/man3ldap/ldap_dns_to_url.3ldap target=ldap_url.3ldap
link path=usr/share/man/man3ldap/ldap_enable_translation.3ldap \
    target=ldap_charset.3ldap
link path=usr/share/man/man3ldap/ldap_entry2html.3ldap \
    target=ldap_entry2text.3ldap
link path=usr/share/man/man3ldap/ldap_entry2html_search.3ldap \
    target=ldap_entry2text.3ldap
link path=usr/share/man/man3ldap/ldap_entry2text_search.3ldap \
    target=ldap_entry2text.3ldap
link path=usr/share/man/man3ldap/ldap_err2string.3ldap target=ldap_error.3ldap
link path=usr/share/man/man3ldap/ldap_explode_dn.3ldap \
    target=ldap_get_dn.3ldap
link path=usr/share/man/man3ldap/ldap_explode_dns.3ldap \
    target=ldap_get_dn.3ldap
link path=usr/share/man/man3ldap/ldap_first_disptmpl.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_first_reference.3ldap \
    target=ldap_first_entry.3ldap
link path=usr/share/man/man3ldap/ldap_first_searchobj.3ldap \
    target=ldap_searchprefs.3ldap
link path=usr/share/man/man3ldap/ldap_first_tmplcol.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_first_tmplrow.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_free_friendlymap.3ldap \
    target=ldap_friendly.3ldap
link path=usr/share/man/man3ldap/ldap_free_searchprefs.3ldap \
    target=ldap_searchprefs.3ldap
link path=usr/share/man/man3ldap/ldap_free_templates.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_free_urldesc.3ldap target=ldap_url.3ldap
link path=usr/share/man/man3ldap/ldap_friendly_name.3ldap \
    target=ldap_friendly.3ldap
link path=usr/share/man/man3ldap/ldap_get_lang_values_len.3ldap \
    target=ldap_get_lang_values.3ldap
link path=usr/share/man/man3ldap/ldap_get_values_len.3ldap \
    target=ldap_get_values.3ldap
link path=usr/share/man/man3ldap/ldap_getfilter_free.3ldap \
    target=ldap_getfilter.3ldap
link path=usr/share/man/man3ldap/ldap_getfirstfilter.3ldap \
    target=ldap_getfilter.3ldap
link path=usr/share/man/man3ldap/ldap_getnextfilter.3ldap \
    target=ldap_getfilter.3ldap
link path=usr/share/man/man3ldap/ldap_init.3ldap target=ldap_open.3ldap
link path=usr/share/man/man3ldap/ldap_init_getfilter.3ldap \
    target=ldap_getfilter.3ldap
link path=usr/share/man/man3ldap/ldap_init_getfilter_buf.3ldap \
    target=ldap_getfilter.3ldap
link path=usr/share/man/man3ldap/ldap_init_searchprefs.3ldap \
    target=ldap_searchprefs.3ldap
link path=usr/share/man/man3ldap/ldap_init_searchprefs_buf.3ldap \
    target=ldap_searchprefs.3ldap
link path=usr/share/man/man3ldap/ldap_init_templates.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_init_templates_buf.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_is_dns_dn.3ldap target=ldap_get_dn.3ldap
link path=usr/share/man/man3ldap/ldap_is_ldap_url.3ldap target=ldap_url.3ldap
link path=usr/share/man/man3ldap/ldap_memcache_destroy.3ldap \
    target=ldap_memcache.3ldap
link path=usr/share/man/man3ldap/ldap_memcache_flush.3ldap \
    target=ldap_memcache.3ldap
link path=usr/share/man/man3ldap/ldap_memcache_get.3ldap \
    target=ldap_memcache.3ldap
link path=usr/share/man/man3ldap/ldap_memcache_init.3ldap \
    target=ldap_memcache.3ldap
link path=usr/share/man/man3ldap/ldap_memcache_set.3ldap \
    target=ldap_memcache.3ldap
link path=usr/share/man/man3ldap/ldap_memcache_update.3ldap \
    target=ldap_memcache.3ldap
link path=usr/share/man/man3ldap/ldap_modify_ext.3ldap \
    target=ldap_modify.3ldap
link path=usr/share/man/man3ldap/ldap_modify_ext_s.3ldap \
    target=ldap_modify.3ldap
link path=usr/share/man/man3ldap/ldap_modify_s.3ldap target=ldap_modify.3ldap
link path=usr/share/man/man3ldap/ldap_modrdn2.3ldap target=ldap_modrdn.3ldap
link path=usr/share/man/man3ldap/ldap_modrdn2_s.3ldap target=ldap_modrdn.3ldap
link path=usr/share/man/man3ldap/ldap_modrdn_s.3ldap target=ldap_modrdn.3ldap
link path=usr/share/man/man3ldap/ldap_mods_free.3ldap target=ldap_modify.3ldap
link path=usr/share/man/man3ldap/ldap_msgfree.3ldap target=ldap_result.3ldap
link path=usr/share/man/man3ldap/ldap_msgtype.3ldap \
    target=ldap_first_message.3ldap
link path=usr/share/man/man3ldap/ldap_name2template.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_next_attribute.3ldap \
    target=ldap_first_attribute.3ldap
link path=usr/share/man/man3ldap/ldap_next_disptmpl.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_next_entry.3ldap \
    target=ldap_first_entry.3ldap
link path=usr/share/man/man3ldap/ldap_next_message.3ldap \
    target=ldap_first_message.3ldap
link path=usr/share/man/man3ldap/ldap_next_reference.3ldap \
    target=ldap_first_entry.3ldap
link path=usr/share/man/man3ldap/ldap_next_searchobj.3ldap \
    target=ldap_searchprefs.3ldap
link path=usr/share/man/man3ldap/ldap_next_tmplcol.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_next_tmplrow.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_oc2template.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_parse_extended_result.3ldap \
    target=ldap_parse_result.3ldap
link path=usr/share/man/man3ldap/ldap_parse_sasl_bind_result.3ldap \
    target=ldap_parse_result.3ldap
link path=usr/share/man/man3ldap/ldap_perror.3ldap target=ldap_error.3ldap
link path=usr/share/man/man3ldap/ldap_rename.3ldap target=ldap_modrdn.3ldap
link path=usr/share/man/man3ldap/ldap_rename_s.3ldap target=ldap_modrdn.3ldap
link path=usr/share/man/man3ldap/ldap_result2error.3ldap \
    target=ldap_error.3ldap
link path=usr/share/man/man3ldap/ldap_sasl_bind.3ldap target=ldap_bind.3ldap
link path=usr/share/man/man3ldap/ldap_sasl_bind_s.3ldap target=ldap_bind.3ldap
link path=usr/share/man/man3ldap/ldap_sasl_interactive_bind_s.3ldap \
    target=ldap_bind.3ldap
link path=usr/share/man/man3ldap/ldap_search_ext.3ldap \
    target=ldap_search.3ldap
link path=usr/share/man/man3ldap/ldap_search_ext_s.3ldap \
    target=ldap_search.3ldap
link path=usr/share/man/man3ldap/ldap_search_s.3ldap target=ldap_search.3ldap
link path=usr/share/man/man3ldap/ldap_search_st.3ldap target=ldap_search.3ldap
link path=usr/share/man/man3ldap/ldap_set_option.3ldap \
    target=ldap_get_option.3ldap
link path=usr/share/man/man3ldap/ldap_set_rebind_proc.3ldap \
    target=ldap_bind.3ldap
link path=usr/share/man/man3ldap/ldap_set_string_translators.3ldap \
    target=ldap_charset.3ldap
link path=usr/share/man/man3ldap/ldap_setfilteraffixes.3ldap \
    target=ldap_getfilter.3ldap
link path=usr/share/man/man3ldap/ldap_simple_bind.3ldap target=ldap_bind.3ldap
link path=usr/share/man/man3ldap/ldap_simple_bind_s.3ldap \
    target=ldap_bind.3ldap
link path=usr/share/man/man3ldap/ldap_sort_entries.3ldap \
    target=ldap_sort.3ldap
link path=usr/share/man/man3ldap/ldap_sort_strcasecmp.3ldap \
    target=ldap_sort.3ldap
link path=usr/share/man/man3ldap/ldap_sort_values.3ldap target=ldap_sort.3ldap
link path=usr/share/man/man3ldap/ldap_t61_to_8859.3ldap \
    target=ldap_charset.3ldap
link path=usr/share/man/man3ldap/ldap_tmplattrs.3ldap \
    target=ldap_disptmpl.3ldap
link path=usr/share/man/man3ldap/ldap_translate_from_t61.3ldap \
    target=ldap_charset.3ldap
link path=usr/share/man/man3ldap/ldap_translate_to_t61.3ldap \
    target=ldap_charset.3ldap
link path=usr/share/man/man3ldap/ldap_ufn_search_c.3ldap target=ldap_ufn.3ldap
link path=usr/share/man/man3ldap/ldap_ufn_search_ct.3ldap \
    target=ldap_ufn.3ldap
link path=usr/share/man/man3ldap/ldap_ufn_search_s.3ldap target=ldap_ufn.3ldap
link path=usr/share/man/man3ldap/ldap_ufn_setfilter.3ldap \
    target=ldap_ufn.3ldap
link path=usr/share/man/man3ldap/ldap_ufn_setprefix.3ldap \
    target=ldap_ufn.3ldap
link path=usr/share/man/man3ldap/ldap_ufn_timeout.3ldap target=ldap_ufn.3ldap
link path=usr/share/man/man3ldap/ldap_unbind.3ldap target=ldap_bind.3ldap
link path=usr/share/man/man3ldap/ldap_unbind_ext.3ldap target=ldap_bind.3ldap
link path=usr/share/man/man3ldap/ldap_unbind_s.3ldap target=ldap_bind.3ldap
link path=usr/share/man/man3ldap/ldap_url_parse.3ldap target=ldap_url.3ldap
link path=usr/share/man/man3ldap/ldap_url_parse_nodn.3ldap \
    target=ldap_url.3ldap
link path=usr/share/man/man3ldap/ldap_url_search.3ldap target=ldap_url.3ldap
link path=usr/share/man/man3ldap/ldap_url_search_s.3ldap target=ldap_url.3ldap
link path=usr/share/man/man3ldap/ldap_url_search_st.3ldap \
    target=ldap_url.3ldap
link path=usr/share/man/man3ldap/ldap_vals2html.3ldap \
    target=ldap_entry2text.3ldap
link path=usr/share/man/man3ldap/ldap_vals2text.3ldap \
    target=ldap_entry2text.3ldap
link path=usr/share/man/man3ldap/ldap_value_free.3ldap \
    target=ldap_get_values.3ldap
link path=usr/share/man/man3ldap/ldap_value_free_len.3ldap \
    target=ldap_get_values.3ldap
