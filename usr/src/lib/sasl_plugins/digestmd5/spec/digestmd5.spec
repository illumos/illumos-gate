#
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libsasl/plugin/digestmd5/spec/digestmd5.spec
#

function	sasl_client_plug_init
include		<sasl/saslplug.h>
declaration	int sasl_client_plug_init(const sasl_utils_t *utils, \
                         int maxversion, int *out_version, \
                         sasl_client_plug_t **pluglist, \
                         int *plugcount)
exception	$return == SASL_FAIL
version		SUNWprivate_1.1
end		

function	sasl_server_plug_init
include		<sasl/saslplug.h>
declaration	int sasl_server_plug_init(const sasl_utils_t *utils, \
                         int maxversion, int *out_version, \
			 sasl_server_plug_t **pluglist, \
                         int *plugcount)
exception	$return == SASL_FAIL
version		SUNWprivate_1.1
end		
