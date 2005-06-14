#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_cache.spec
#

function	krb5_fcc_close
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_close \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_fcc_close_file
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_close_file \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_fcc_destroy
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_destroy \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_fcc_end_seq_get
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_end_seq_get \
			(krb5_context context, krb5_ccache id, \
			krb5_cc_cursor *cursor)
version		SUNWprivate_1.1
end

function	krb5_fcc_generate_new
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_generate_new \
			(krb5_context context, krb5_ccache *id)
version		SUNWprivate_1.1
end

function	krb5_fcc_get_name
include		<krb5.h>, <fcc-proto.h>
declaration	char * krb5_fcc_get_name \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_fcc_get_principal
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_get_principal \
			(krb5_context context, krb5_ccache id, \
			krb5_principal *princ)
version		SUNWprivate_1.1
end

function	krb5_fcc_initialize
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_initialize \
			(krb5_context context, krb5_ccache id, \
			krb5_principal princ)
version		SUNWprivate_1.1
end

function	krb5_fcc_interpret
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_interpret \
			(krb5_context context, int errnum)
version		SUNWprivate_1.1
end

function	krb5_fcc_next_cred
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_next_cred \
			(krb5_context, krb5_ccache id, \
			krb5_cc_cursor *cursor, \
			krb5_creds *creds)
version		SUNWprivate_1.1
end

function	krb5_fcc_open_file
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_open_file \
			(krb5_context context, krb5_ccache id, \
			int mode)
version		SUNWprivate_1.1
end

data		krb5_fcc_ops
declaration	krb5_cc_ops krb5_fcc_ops
version		SUNWprivate_1.1
end

function	krb5_fcc_read
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read \
			(krb5_context context, krb5_ccache id, \
			krb5_pointer buf, int len)
version		SUNWprivate_1.1
end

function	krb5_fcc_read_addr
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read_addr \
			(krb5_context context, krb5_ccache id, \
			krb5_address *addr)
version		SUNWprivate_1.1
end

function	krb5_fcc_read_addrs
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read_addrs \
			(krb5_context context, krb5_ccache id, \
			krb5_address ***addrs)
version		SUNWprivate_1.1
end

function	krb5_fcc_read_authdata
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read_authdata \
			(krb5_context context, krb5_ccache id, \
			krb5_authdata ***a)
version		SUNWprivate_1.1
end

function	krb5_fcc_read_authdatum
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read_authdatum \
			(krb5_context context, krb5_ccache id, \
			krb5_authdata *a)
version		SUNWprivate_1.1
end

function	krb5_fcc_read_data
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read_data \
			(krb5_context context, krb5_ccache id, \
			krb5_data *data)
version		SUNWprivate_1.1
end

function	krb5_fcc_read_int32
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read_int32 \
			(krb5_context context, krb5_ccache id, \
			krb5_int32 *i)
version		SUNWprivate_1.1
end

function	krb5_fcc_read_keyblock
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read_keyblock \
			(krb5_context context, krb5_ccache id, \
			krb5_keyblock *keyblock)
version		SUNWprivate_1.1
end

function	krb5_fcc_read_octet
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read_octet \
			(krb5_context context, krb5_ccache id, \
			krb5_octet *i)
version		SUNWprivate_1.1
end

function	krb5_fcc_read_principal
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read_principal \
			(krb5_context context, krb5_ccache id, \
			krb5_principal *princ)
version		SUNWprivate_1.1
end

function	krb5_fcc_read_times
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read_times \
			(krb5_context context, krb5_ccache id, \
			krb5_ticket_times *t)
version		SUNWprivate_1.1
end

function	krb5_fcc_read_ui_2
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_read_ui_2 \
			(krb5_context context, krb5_ccache id, \
			krb5_ui_2 *i)
version		SUNWprivate_1.1
end

function	krb5_fcc_resolve
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_resolve \
			(krb5_context context, krb5_ccache *id, \
			const char *residual)
version		SUNWprivate_1.1
end

function	krb5_fcc_retrieve
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_retrieve \
			(krb5_context context, krb5_ccache id, \
			krb5_flags whichfields, krb5_creds *mcreds, \
			krb5_creds *creds)
version		SUNWprivate_1.1
end

function	krb5_fcc_set_flags
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_set_flags \
			(krb5_context context, krb5_ccache id, \
			krb5_flags flags)
version		SUNWprivate_1.1
end

function	krb5_fcc_skip_header
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_skip_header \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_fcc_skip_principal
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_skip_principal \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_fcc_start_seq_get
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_start_seq_get \
			(krb5_context context, krb5_ccache id, \
			krb5_cc_cursor *cursor)
version		SUNWprivate_1.1
end

function	krb5_fcc_store
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store \
			(krb5_context context, krb5_ccache id, \
			krb5_creds *creds)
version		SUNWprivate_1.1
end

function	krb5_fcc_store_addr
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store_addr \
			(krb5_context context, krb5_ccache id, \
			krb5_address *addr)
version		SUNWprivate_1.1
end

function	krb5_fcc_store_addrs
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store_addrs \
			(krb5_context context, krb5_ccache id, \
			krb5_address **addrs)
version		SUNWprivate_1.1
end

function	krb5_fcc_store_authdata
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store_authdata \
			(krb5_context context, krb5_ccache id, \
			krb5_authdata **a)
version		SUNWprivate_1.1
end

function	krb5_fcc_store_authdatum
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store_authdatum \
			(krb5_context context, krb5_ccache id, \
			krb5_authdata *a)
version		SUNWprivate_1.1
end

function	krb5_fcc_store_data
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store_data \
			(krb5_context context, krb5_ccache id, \
			krb5_data *data)
version		SUNWprivate_1.1
end

function	krb5_fcc_store_int32
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store_int32 \
			(krb5_context context, krb5_ccache id, \
			krb5_int32 i)
version		SUNWprivate_1.1
end

function	krb5_fcc_store_keyblock
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store_keyblock \
			(krb5_context context, krb5_ccache id, \
			krb5_keyblock *keyblock)
version		SUNWprivate_1.1
end

function	krb5_fcc_store_octet
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store_octet \
			(krb5_context context, krb5_ccache id, \
			krb5_int32 i)
version		SUNWprivate_1.1
end

function	krb5_fcc_store_principal
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store_principal \
			(krb5_context context, krb5_ccache id, \
			krb5_principal princ)
version		SUNWprivate_1.1
end

function	krb5_fcc_store_times
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store_times \
			(krb5_context context, krb5_ccache id, \
			krb5_ticket_times *t)
version		SUNWprivate_1.1
end

function	krb5_fcc_store_ui_2
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_store_ui_2 \
			(krb5_context context, krb5_ccache id, \
			krb5_int32 i)
version		SUNWprivate_1.1
end

function	krb5_fcc_write
include		<krb5.h>, <fcc-proto.h>
declaration	krb5_error_code krb5_fcc_write \
			(krb5_context context, krb5_ccache id, \
			krb5_pointer buf, int len)
version		SUNWprivate_1.1
end

function	krb5_rc_default
include		<krb5.h>
declaration	krb5_error_code krb5_rc_default \
			(krb5_context context, krb5_rcache *id)
version		SUNWprivate_1.1
end

function	krb5_rc_default_name
include		<krb5.h>
declaration	char * krb5_rc_default_name (krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_rc_file_close
include		<krb5.h>, <k5-int.h>, <rc_file.h>
declaration	krb5_error_code krb5_rc_file_close \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_file_close_no_free
include		<krb5.h>, <k5-int.h>, <rc_file.h>
declaration	krb5_error_code krb5_rc_file_close_no_free \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_file_destroy
include		<krb5.h>, <k5-int.h>, <rc_file.h>
declaration	krb5_error_code krb5_rc_file_destroy \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_file_expunge
include		<krb5.h>, <k5-int.h>, <rc_file.h>
declaration	krb5_error_code krb5_rc_file_expunge \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_file_get_name
include		<krb5.h>, <k5-int.h>, <rc_file.h>
declaration	char * krb5_rc_file_get_name \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_file_get_span
include		<krb5.h>, <k5-int.h>, <rc_file.h>
declaration	krb5_error_code krb5_rc_file_get_span \
			(krb5_context context, krb5_rcache id, \
			krb5_deltat *lifespan)
version		SUNWprivate_1.1
end

function	krb5_rc_file_init
include		<krb5.h>, <k5-int.h>, <rc_file.h>
declaration	krb5_error_code krb5_rc_file_init \
			(krb5_context context, krb5_rcache id, \
			krb5_deltat lifespan)
version		SUNWprivate_1.1
end

data		krb5_rc_file_ops
declaration	krb5_rc_ops krb5_rc_file_ops
version		SUNWprivate_1.1
end

function	krb5_rc_file_recover
include		<krb5.h>, <k5-int.h>, <rc_file.h>
declaration	krb5_error_code krb5_rc_file_recover \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_file_resolve
include		<krb5.h>, <k5-int.h>, <rc_file.h>
declaration	krb5_error_code krb5_rc_file_resolve \
			(krb5_context context, krb5_rcache id, \
			char *name)
version		SUNWprivate_1.1
end

function	krb5_rc_file_store
include		<krb5.h>, <k5-int.h>, <rc_file.h>
declaration	krb5_error_code krb5_rc_file_store \
			(krb5_context context, krb5_rcache id, \
			krb5_donot_replay *rep)
version		SUNWprivate_1.1
end

function	krb5_rc_free_entry
include		<krb5.h>, <k5-int.h>, <rc_file.h>
declaration	void krb5_rc_free_entry \
			(krb5_context context, \
			krb5_donot_replay **rep)
version		SUNWprivate_1.1
end

function	krb5_rc_get_type
include		<krb5.h>
declaration	char * krb5_rc_get_type \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_io_close
include		<krb5.h>, <rc_io.h>
declaration	krb5_error_code krb5_rc_io_close \
			(krb5_context context, krb5_rc_iostuff *d)
version		SUNWprivate_1.1
end

function	krb5_rc_io_creat
include		<krb5.h>, <rc_io.h>
declaration	krb5_error_code krb5_rc_io_creat \
			(krb5_context context, \
			krb5_rc_iostuff *d, char **fn)
version		SUNWprivate_1.1
end

function	krb5_rc_io_destroy
include		<krb5.h>, <rc_io.h>
declaration	krb5_error_code krb5_rc_io_destroy \
			(krb5_context context, krb5_rc_iostuff *d)
version		SUNWprivate_1.1
end

function	krb5_rc_io_mark
include		<krb5.h>, <rc_io.h>
declaration	krb5_error_code krb5_rc_io_mark \
			(krb5_context context, krb5_rc_iostuff *d)
version		SUNWprivate_1.1
end

function	krb5_rc_io_move
include		<krb5.h>, <rc_io.h>
declaration	krb5_error_code krb5_rc_io_move \
			(krb5_context context, krb5_rc_iostuff *new, \
			krb5_rc_iostuff *old)
version		SUNWprivate_1.1
end

function	krb5_rc_io_open
include		<krb5.h>, <rc_io.h>
declaration	krb5_error_code krb5_rc_io_open \
			(krb5_context context, \
			krb5_rc_iostuff *d, char *fn)
version		SUNWprivate_1.1
end

function	krb5_rc_io_read
include		<krb5.h>, <rc_io.h>
declaration	krb5_error_code krb5_rc_io_read \
			(krb5_context context, krb5_rc_iostuff *d, \
			krb5_pointer buf, int num)
version		SUNWprivate_1.1
end

function	krb5_rc_io_size
include		<krb5.h>, <rc_io.h>
declaration	long krb5_rc_io_size \
			(krb5_context context, krb5_rc_iostuff *d)
version		SUNWprivate_1.1
end

function	krb5_rc_io_sync
include		<krb5.h>, <rc_io.h>
declaration	krb5_error_code krb5_rc_io_sync \
			(krb5_context context, krb5_rc_iostuff *d)
version		SUNWprivate_1.1
end

function	krb5_rc_io_unmark
include		<krb5.h>, <rc_io.h>
declaration	krb5_error_code krb5_rc_io_unmark \
			(krb5_context context, krb5_rc_iostuff *d)
version		SUNWprivate_1.1
end

function	krb5_rc_io_write
include		<krb5.h>, <rc_io.h>
declaration	krb5_error_code krb5_rc_io_write \
			(krb5_context context, krb5_rc_iostuff *d, \
			krb5_pointer buf, int num)
version		SUNWprivate_1.1
end

function	krb5_rc_mem_close
include		<krb5.h>, <k5-int.h>, <rc_mem.h>
declaration	krb5_error_code krb5_rc_mem_close \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_mem_close_no_free
include		<krb5.h>, <k5-int.h>, <rc_mem.h>
declaration	krb5_error_code krb5_rc_mem_close_no_free \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_mem_destroy
include		<krb5.h>, <k5-int.h>, <rc_mem.h>
declaration	krb5_error_code krb5_rc_mem_destroy \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_mem_get_name
include		<krb5.h>, <k5-int.h>, <rc_mem.h>
declaration	char * krb5_rc_mem_get_name \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_mem_get_span
include		<krb5.h>, <k5-int.h>, <rc_mem.h>
declaration	krb5_error_code krb5_rc_mem_get_span \
			(krb5_context context, krb5_rcache id, \
			krb5_deltat *lifespan)
version		SUNWprivate_1.1
end

function	krb5_rc_mem_init
include		<krb5.h>, <k5-int.h>, <rc_mem.h>
declaration	krb5_error_code krb5_rc_mem_init \
			(krb5_context context, krb5_rcache id, \
			krb5_deltat lifespan)
version		SUNWprivate_1.1
end

data		krb5_rc_mem_ops
declaration	krb5_rc_ops krb5_rc_mem_ops
version		SUNWprivate_1.1
end

function	krb5_rc_mem_recover
include		<krb5.h>, <k5-int.h>, <rc_mem.h>
declaration	krb5_error_code krb5_rc_mem_recover \
			(krb5_context context, krb5_rcache id)
version		SUNWprivate_1.1
end

function	krb5_rc_mem_resolve
include		<krb5.h>, <k5-int.h>, <rc_mem.h>
declaration	krb5_error_code krb5_rc_mem_resolve \
			(krb5_context context, krb5_rcache id, \
			char *name)
version		SUNWprivate_1.1
end

function	krb5_rc_mem_store
include		<krb5.h>, <k5-int.h>, <rc_mem.h>
declaration	krb5_error_code krb5_rc_mem_store \
			(krb5_context context, krb5_rcache id, \
			krb5_donot_replay *rep)
version		SUNWprivate_1.1
end
function	krb5_rc_register_type
include		<krb5.h>
declaration	krb5_error_code krb5_rc_register_type \
			(krb5_context context, krb5_rc_ops *ops)
version		SUNWprivate_1.1
end

function	krb5_rc_resolve
include		<krb5.h>
declaration	krb5_error_code krb5_rc_resolve \
			(krb5_context context, krb5_rcache id, \
			char *name)
version		SUNWprivate_1.1
end

function	krb5_rc_resolve_full
include		<krb5.h>
declaration	krb5_error_code krb5_rc_resolve_full \
			(krb5_context context, krb5_rcache *id, \
			char *string_name)
version		SUNWprivate_1.1
end

function	krb5_scc_close
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_close \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_scc_close_file
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_close_file \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_scc_destroy
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_destroy \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_scc_end_seq_get
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_end_seq_get \
			(krb5_context, krb5_ccache id, \
			krb5_cc_cursor *cursor)
version		SUNWprivate_1.1
end

function	krb5_scc_generate_new
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_generate_new \
			(krb5_context context, krb5_ccache *id)
version		SUNWprivate_1.1
end

function	krb5_scc_get_name
include		<krb5.h>, <scc-proto.h>
declaration	char *krb5_scc_get_name \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_scc_get_principal
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_get_principal \
			(krb5_context context, krb5_ccache id, \
			krb5_principal *princ)
version		SUNWprivate_1.1
end

function	krb5_scc_initialize
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_initialize \
			(krb5_context context, krb5_ccache id, \
			krb5_principal princ)
version		SUNWprivate_1.1
end

function	krb5_scc_interpret
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_interpret \
			(krb5_context context, int errnum)
version		SUNWprivate_1.1
end

function	krb5_scc_next_cred
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_next_cred \
			(krb5_context context, krb5_ccache id, \
			krb5_cc_cursor *cursor, krb5_creds *creds)
version		SUNWprivate_1.1
end

function	krb5_scc_open_file
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_open_file \
			(krb5_context context, krb5_ccache id, \
			int mode)
version		SUNWprivate_1.1
end

data		krb5_scc_ops
declaration	krb5_cc_ops krb5_scc_ops
version		SUNWprivate_1.1
end

function	krb5_scc_read
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read \
			(krb5_context context, krb5_ccache id, \
			krb5_pointer buf, int len)
version		SUNWprivate_1.1
end

function	krb5_scc_read_addr
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read_addr \
			(krb5_context context, krb5_ccache id, \
			krb5_address *addr)
version		SUNWprivate_1.1
end

function	krb5_scc_read_addrs
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read_addrs \
			(krb5_context context, krb5_ccache id, \
			krb5_address ***addrs)
version		SUNWprivate_1.1
end

function	krb5_scc_read_authdata
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read_authdata \
			(krb5_context context, krb5_ccache id, \
			krb5_authdata ***a)
version		SUNWprivate_1.1
end

function	krb5_scc_read_authdatum
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read_authdatum \
			(krb5_context context, krb5_ccache id, \
			krb5_authdata *a)
version		SUNWprivate_1.1
end

function	krb5_scc_read_data
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read_data \
			(krb5_context context, krb5_ccache id, \
			krb5_data *data)
version		SUNWprivate_1.1
end

function	krb5_scc_read_int32
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read_int32 \
			(krb5_context context, krb5_ccache id, \
			krb5_int32 *i)
version		SUNWprivate_1.1
end

function	krb5_scc_read_keyblock
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read_keyblock \
			(krb5_context context, krb5_ccache id, \
			krb5_keyblock *keyblock)
version		SUNWprivate_1.1
end

function	krb5_scc_read_octet
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read_octet \
			(krb5_context context, krb5_ccache id, \
			krb5_octet *i)
version		SUNWprivate_1.1
end

function	krb5_scc_read_principal
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read_principal \
			(krb5_context context, krb5_ccache id, \
			krb5_principal *princ)
version		SUNWprivate_1.1
end

function	krb5_scc_read_times
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read_times \
			(krb5_context context, krb5_ccache id, \
			krb5_ticket_times *t)
version		SUNWprivate_1.1
end

function	krb5_scc_read_ui_2
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_read_ui_2 \
			(krb5_context context, krb5_ccache id, \
			krb5_ui_2 *i)
version		SUNWprivate_1.1
end

function	krb5_scc_resolve
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_resolve \
			(krb5_context context, krb5_ccache *id, \
			const char *residual)
version		SUNWprivate_1.1
end

function	krb5_scc_retrieve
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_retrieve \
			(krb5_context context, krb5_ccache id, \
			krb5_flags whichfields, krb5_creds *mcreds, \
			krb5_creds *creds)
version		SUNWprivate_1.1
end

function	krb5_scc_set_flags
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_set_flags \
			(krb5_context context, krb5_ccache id, \
			krb5_flags flags)
version		SUNWprivate_1.1
end

function	krb5_scc_skip_header
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_skip_header \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_scc_skip_principal
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_skip_principal \
			(krb5_context context, krb5_ccache id)
version		SUNWprivate_1.1
end

function	krb5_scc_start_seq_get
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_start_seq_get \
			(krb5_context context, krb5_ccache id, \
			krb5_cc_cursor *cursor)
version		SUNWprivate_1.1
end

function	krb5_scc_store
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store \
			(krb5_context context, krb5_ccache id, \
			krb5_creds *creds)
version		SUNWprivate_1.1
end

function	krb5_scc_store_addr
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store_addr \
			(krb5_context context, krb5_ccache id, \
			krb5_address *addr)
version		SUNWprivate_1.1
end

function	krb5_scc_store_addrs
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store_addrs \
			(krb5_context context, krb5_ccache id, \
			krb5_address **addrs)
version		SUNWprivate_1.1
end

function	krb5_scc_store_authdata
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store_authdata \
			(krb5_context, krb5_ccache, \
			krb5_authdata **)
version		SUNWprivate_1.1
end

function	krb5_scc_store_authdatum
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store_authdatum \
			(krb5_context context, krb5_ccache id, \
			krb5_authdata *a)
version		SUNWprivate_1.1
end

function	krb5_scc_store_data
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store_data \
			(krb5_context context, krb5_ccache id, \
			krb5_data *data)
version		SUNWprivate_1.1
end

function	krb5_scc_store_int32
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store_int32 \
			(krb5_context context, krb5_ccache id, \
			krb5_int32 i)
version		SUNWprivate_1.1
end

function	krb5_scc_store_keyblock
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store_keyblock \
			(krb5_context context, krb5_ccache id, \
			krb5_keyblock *keyblock)
version		SUNWprivate_1.1
end

function	krb5_scc_store_octet
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store_octet \
			(krb5_context context, krb5_ccache id, \
			krb5_int32 i)
version		SUNWprivate_1.1
end

function	krb5_scc_store_principal
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store_principal \
			(krb5_context context, krb5_ccache id, \
			krb5_principal princ)
version		SUNWprivate_1.1
end

function	krb5_scc_store_times
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store_times \
			(krb5_context context, krb5_ccache id, \
			krb5_ticket_times *t)
version		SUNWprivate_1.1
end

function	krb5_scc_store_ui_2
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_store_ui_2 \
			(krb5_context context, krb5_ccache id, \
			krb5_int32 i)
version		SUNWprivate_1.1
end

function	krb5_scc_write
include		<krb5.h>, <scc-proto.h>
declaration	krb5_error_code krb5_scc_write \
			(krb5_context context, krb5_ccache id, \
			krb5_pointer buf, int len)
version		SUNWprivate_1.1
end

function	krb5_cc_copy_creds
include		<krb5.h>
declaration	krb5_error_code krb5_cc_copy_creds \
			(krb5_context context, krb5_ccache incc, \
			krb5_ccache outcc)
version		SUNWprivate_1.1
end

function	krb5_cc_default
include		<krb5.h>
declaration	krb5_error_code krb5_cc_default ( \
			krb5_context context, \
			krb5_ccache *ccache)
version		SUNWprivate_1.1
end

function	krb5_cc_default_name
include		<krb5.h>
declaration	const char * krb5_cc_default_name (krb5_context context)
version		SUNWprivate_1.1
end

data		krb5_cc_dfl_ops
declaration	krb5_cc_ops *krb5_cc_dfl_ops
version		SUNWprivate_1.1
end

data		krb5_cc_file_ops
declaration	krb5_cc_ops krb5_cc_file_ops
version		SUNWprivate_1.1
end

function	krb5_cc_register
include		<krb5.h>
declaration	krb5_error_code krb5_cc_register \
			(krb5_context context, krb5_cc_ops *ops, \
			krb5_boolean override)
version		SUNWprivate_1.1
end

function	krb5_cc_resolve
include		<krb5.h>
declaration	krb5_error_code krb5_cc_resolve \
			(krb5_context context, const char *name, \
			krb5_ccache *cache)
version		SUNWprivate_1.1
end

function	krb5_cc_retrieve_cred_default
include		<krb5.h>
declaration	krb5_error_code krb5_cc_retrieve_cred_default \
			(krb5_context context, krb5_ccache id, \
			krb5_flags flags, krb5_creds *mcreds, \
			krb5_creds *creds)
version		SUNWprivate_1.1
end

function	krb5_cc_set_default_name
include		<krb5.h>
declaration	krb5_error_code krb5_cc_set_default_name ( \
			krb5_context context, const char *name)
version		SUNWprivate_1.1
end

data		krb5_cc_stdio_ops
declaration	krb5_cc_ops krb5_cc_stdio_ops
version		SUNWprivate_1.1
end

function	krb5_change_cache
include		<fcc-proto.h>
declaration	krb5_error_code krb5_change_cache (void)
version		SUNWprivate_1.1
end

function	krb5_get_notification_message
include		<fcc-proto.h>
declaration	unsigned int krb5_get_notification_message (void)
version		SUNWprivate_1.1
end

