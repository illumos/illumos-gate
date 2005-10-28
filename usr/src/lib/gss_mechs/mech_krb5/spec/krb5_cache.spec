#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_cache.spec
#



data		krb5_fcc_ops
declaration	krb5_cc_ops krb5_fcc_ops
version		SUNWprivate_1.1
end

function	krb5_rc_close
include		<krb5.h>
declaration	krb5_error_code krb5_rc_close \
			(krb5_context context, krb5_rcache id)
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

function	krb5_cc_retrieve_cred
include		<krb5.h>
declaration	krb5_error_code krb5_cc_retrieve_cred \
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

function	krb5_cc_initialize
include		<krb5.h>
declaration	krb5_error_code  krb5_cc_initialize \
			(krb5_context context, krb5_ccache cache, \
                       	krb5_principal principal)
version		SUNWprivate_1.1
end

function	krb5_cc_get_principal
include		<krb5.h>
declaration	krb5_error_code  krb5_cc_get_principal \
			(krb5_context context, krb5_ccache cache, \
                       	krb5_principal *principal)
version		SUNWprivate_1.1
end

function	krb5_cc_close
include		<krb5.h>
declaration	krb5_error_code  krb5_cc_close \
			(krb5_context context, krb5_ccache cache)
version		SUNWprivate_1.1
end

function	krb5_cc_destroy
include		<krb5.h>
declaration	krb5_error_code  krb5_cc_destroy \
			(krb5_context context, krb5_ccache cache)
version		SUNWprivate_1.1
end

function	krb5_cc_end_seq_get
include		<krb5.h>
declaration	krb5_error_code  krb5_cc_end_seq_get \
			(krb5_context context, krb5_ccache cache, \
			krb5_cc_cursor *cursor)
version		SUNWprivate_1.1
end

function	krb5_cc_get_name
include		<krb5.h>
declaration	krb5_error_code  krb5_cc_get_name \
			(krb5_context context, krb5_ccache cache)
version		SUNWprivate_1.1
end

function	krb5_cc_get_type
include		<krb5.h>
declaration	krb5_error_code  krb5_cc_get_type \
			(krb5_context context, krb5_ccache cache)
version		SUNWprivate_1.1
end

function	krb5_cc_next_cred
include		<krb5.h>
declaration	krb5_error_code  krb5_cc_next_cred \
			(krb5_context context, krb5_ccache cache, \
			krb5_cc_cursor *cursor, krb5_creds *creds)
version		SUNWprivate_1.1
end

function	krb5_cc_set_flags
include		<krb5.h>
declaration	krb5_error_code  krb5_cc_destroy \
			(krb5_context context, krb5_ccache cache, \
			krb5_flags flags)
version		SUNWprivate_1.1
end

function	krb5_cc_start_seq_get
include		<krb5.h>
declaration	krb5_error_code  krb5_cc_start_seq_get \
			(krb5_context context, krb5_ccache cache, \
			krb5_cc_cursor *cursor)
version		SUNWprivate_1.1
end

function	krb5_cc_store_cred
include		<krb5.h>
declaration	krb5_error_code  krb5_cc_store_cred \
			(krb5_context context, krb5_ccache cache, \
			krb5_creds *creds)
version		SUNWprivate_1.1
end
