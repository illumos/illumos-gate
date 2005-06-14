#
# Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_keytab.spec
#

function	krb5_kt_add_entry
include		<krb5.h>
declaration	krb5_error_code krb5_kt_add_entry \
			(krb5_context context, krb5_keytab id, \
			krb5_keytab_entry *entry)
version		SUNWprivate_1.1
end

function	krb5_kt_default
include		<krb5.h>
declaration	krb5_error_code krb5_kt_default \
			(krb5_context context, krb5_keytab *id)
version		SUNWprivate_1.1
end

function	krb5_kt_default_name
include		<krb5.h>
declaration	krb5_error_code krb5_kt_default_name \
			(krb5_context context, char *name, int namesize)
version		SUNWprivate_1.1
end

function	krb5_kt_dfl_ops
version		SUNWprivate_1.1
end

function	krb5_kt_free_entry
include		<krb5.h>
declaration	krb5_error_code krb5_kt_free_entry \
			(krb5_context context, krb5_keytab_entry *entry)
version		SUNWprivate_1.1
end

function	krb5_kt_read_service_key
include		<krb5.h>
declaration	krb5_error_code krb5_kt_read_service_key \
			(krb5_context context, krb5_pointer keyprocarg, \
			krb5_principal principal, krb5_kvno vno, \
			krb5_enctype enctype, krb5_keyblock **key)
version		SUNWprivate_1.1
end

function	krb5_kt_register
include		<krb5.h>
declaration	krb5_error_code krb5_kt_register \
			(krb5_context context, krb5_kt_ops *ops)
version		SUNWprivate_1.1
end

function	krb5_kt_remove_entry
include		<krb5.h>
declaration	krb5_error_code krb5_kt_remove_entry \
			(krb5_context context, krb5_keytab id, \
			krb5_keytab_entry *entry)
version		SUNWprivate_1.1
end

function	krb5_kt_resolve
include		<krb5.h>
declaration	krb5_error_code krb5_kt_resolve ( \
			krb5_context context, \
			const char *name, \
			krb5_keytab *ktid)
version		SUNWprivate_1.1
end

data		krb5_ktf_ops
declaration	struct _krb5_kt_ops krb5_ktf_ops
version		SUNWprivate_1.1
end

data		krb5_ktf_writable_ops
declaration	struct _krb5_kt_ops krb5_ktf_writable_ops
version		SUNWprivate_1.1
end

function	krb5_ktfile_add
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfile_add \
			(krb5_context context, krb5_keytab id, \
			krb5_keytab_entry *entry)
version		SUNWprivate_1.1
end

function	krb5_ktfile_close
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfile_close \
			(krb5_context, krb5_keytab id)
version		SUNWprivate_1.1
end

function	krb5_ktfile_end_get
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfile_end_get \
			(krb5_context context, krb5_keytab id, \
			krb5_kt_cursor *cursor)
version		SUNWprivate_1.1
end

function	krb5_ktfile_get_entry
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfile_get_entry \
			(krb5_context context, krb5_keytab id, \
			krb5_const_principal principal, krb5_kvno kvno, \
			krb5_enctype enctype, krb5_keytab_entry *entry)
version		SUNWprivate_1.1
end

function	krb5_ktfile_get_name
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfile_get_name \
			(krb5_context context, krb5_keytab id, \
			char *name, int len)
version		SUNWprivate_1.1
end

function	krb5_ktfile_get_next
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfile_get_next \
			(krb5_context context, krb5_keytab id, \
			krb5_keytab_entry *entry, krb5_kt_cursor *cursor)
version		SUNWprivate_1.1
end

function	krb5_ktfile_remove
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfile_remove \
			(krb5_context context, krb5_keytab id, \
			krb5_keytab_entry *entry)
version		SUNWprivate_1.1
end

function	krb5_ktfile_resolve
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfile_resolve \
			(krb5_context context, const char *name, \
			krb5_keytab *id)
version		SUNWprivate_1.1
end

data		krb5_ktfile_ser_entry
declaration	const krb5_ser_entry krb5_ktfile_ser_entry
version		SUNWprivate_1.1
end

function	krb5_ktfile_start_seq_get
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfile_start_seq_get \
			(krb5_context context, krb5_keytab id, \
			krb5_kt_cursor *cursorp)
version		SUNWprivate_1.1
end

function	krb5_ktfile_wresolve
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfile_wresolve \
			(krb5_context context, const char *name, \
			krb5_keytab *id)
version		SUNWprivate_1.1
end

function	krb5_ktfileint_close
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfileint_close \
			(krb5_context context, krb5_keytab id)
version		SUNWprivate_1.1
end

function	krb5_ktfileint_delete_entry
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfileint_delete_entry \
			(krb5_context context, krb5_keytab id, \
			krb5_int32 delete_point)
version		SUNWprivate_1.1
end

function	krb5_ktfileint_find_slot
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfileint_find_slot \
			(krb5_context context, krb5_keytab id, \
			krb5_int32 *size_needed, \
			krb5_int32 *commit_point)
version		SUNWprivate_1.1
end

function	krb5_ktfileint_internal_read_entry
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfileint_internal_read_entry \
			(krb5_context context, krb5_keytab id, \
			krb5_keytab_entry *ret_entry, \
			krb5_int32 *delete_point)
version		SUNWprivate_1.1
end

function	krb5_ktfileint_openr
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfileint_openr \
			(krb5_context context, krb5_keytab id)
version		SUNWprivate_1.1
end

function	krb5_ktfileint_openw
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfileint_openw \
			(krb5_context context, krb5_keytab id)
version		SUNWprivate_1.1
end

function	krb5_ktfileint_read_entry
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfileint_read_entry \
			(krb5_context context, krb5_keytab id, \
			krb5_keytab_entry *entryp)
version		SUNWprivate_1.1
end

function	krb5_ktfileint_size_entry
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfileint_size_entry \
			(krb5_context context, krb5_keytab_entry *entry, \
			krb5_int32 *size_needed)
version		SUNWprivate_1.1
end

function	krb5_ktfileint_write_entry
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_ktfileint_write_entry \
			(krb5_context context, krb5_keytab id, \
			krb5_keytab_entry *entry)
version		SUNWprivate_1.1
end

data		krb5_ser_keytab_init
declaration	krb5_error_code krb5_ser_keytab_init(krb5_context kcontext)
version		SUNWprivate_1.1
end

data		krb5_overridekeyname
declaration	char * krb5_overridekeyname
version		SUNWprivate_1.1
end
