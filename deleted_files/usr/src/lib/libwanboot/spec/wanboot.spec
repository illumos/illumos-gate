#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libwanboot/spec/wanboot.spec

#
# Note that we do not define prototypes for these APIs as we
# are not generating the ABI libraries. Please do not add any
# prototypes.
#

function	http_get_version
version		SUNWprivate_1.1
end

function	http_set_p12_format
version		SUNWprivate_1.1
end

function	http_set_verbose
version		SUNWprivate_1.1
end

function	http_set_cipher_list
version		SUNWprivate_1.1
end

function	http_srv_init
version		SUNWprivate_1.1
end

function	http_set_proxy
version		SUNWprivate_1.1
end


function	http_set_keepalive
version		SUNWprivate_1.1
end

function	http_set_socket_read_timeout
version		SUNWprivate_1.1
end

function	http_set_basic_auth
version		SUNWprivate_1.1
end

function	http_set_random_file
version		SUNWprivate_1.1
end

function	http_set_certificate_authority_file
version		SUNWprivate_1.1
end

function	http_set_client_certificate_file
version		SUNWprivate_1.1
end

function	http_set_password
version		SUNWprivate_1.1
end

function	http_set_key_file_password
version		SUNWprivate_1.1
end

function	http_set_private_key_file
version		SUNWprivate_1.1
end

function	http_srv_connect
version		SUNWprivate_1.1
end

function	http_head_request
version		SUNWprivate_1.1
end

function	http_get_request
version		SUNWprivate_1.1
end

function	http_get_range_request
version		SUNWprivate_1.1
end

function	http_free_respinfo
version		SUNWprivate_1.1
end

function	http_process_headers
version		SUNWprivate_1.1
end

function	http_process_part_headers
version		SUNWprivate_1.1
end

function	http_get_header_value
version		SUNWprivate_1.1
end

function	http_get_response_header
version		SUNWprivate_1.1
end

function	http_read_body
version		SUNWprivate_1.1
end

function	http_srv_disconnect
version		SUNWprivate_1.1
end

function	http_srv_close
version		SUNWprivate_1.1
end

function	http_get_conn_info
version		SUNWprivate_1.1
end

function	http_conn_is_https
version		SUNWprivate_1.1
end

function	http_get_lasterr
version		SUNWprivate_1.1
end

function	http_decode_err
version		SUNWprivate_1.1
end

function	http_errorstr
version		SUNWprivate_1.1
end

function	url_parse_hostport
version		SUNWprivate_1.1
end

function	url_parse
version		SUNWprivate_1.1
end

function	bootlog
version		SUNWprivate_1.1
end

function	bootinfo_init
version		SUNWprivate_1.1
end

function	bootinfo_end
version		SUNWprivate_1.1
end

function	bootinfo_get
version		SUNWprivate_1.1
end

function	bootconf_init
version		SUNWprivate_1.1
end

function	bootconf_get
version		SUNWprivate_1.1
end

function	bootconf_end
version		SUNWprivate_1.1
end

function	bootconf_errmsg
version		SUNWprivate_1.1
end

function	sunw_crypto_init
version		SUNWprivate_1.1
end

function	sunw_PKCS12_parse
version		SUNWprivate_1.1
end

function	sunw_PKCS12_create
version		SUNWprivate_1.1
end

function	sunw_issuer_attrs
version		SUNWprivate_1.1
end

function	sunw_subject_attrs
version		SUNWprivate_1.1
end

function	sunw_print_times
version		SUNWprivate_1.1
end

function	sunw_check_keys
version		SUNWprivate_1.1
end

function	sunw_evp_pkey_free
version		SUNWprivate_1.1
end
