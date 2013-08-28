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

file path=usr/share/man/man3pam/pam.3pam
file path=usr/share/man/man3pam/pam_acct_mgmt.3pam
file path=usr/share/man/man3pam/pam_authenticate.3pam
file path=usr/share/man/man3pam/pam_chauthtok.3pam
file path=usr/share/man/man3pam/pam_get_user.3pam
file path=usr/share/man/man3pam/pam_getenv.3pam
file path=usr/share/man/man3pam/pam_getenvlist.3pam
file path=usr/share/man/man3pam/pam_open_session.3pam
file path=usr/share/man/man3pam/pam_putenv.3pam
file path=usr/share/man/man3pam/pam_set_data.3pam
file path=usr/share/man/man3pam/pam_set_item.3pam
file path=usr/share/man/man3pam/pam_setcred.3pam
file path=usr/share/man/man3pam/pam_sm.3pam
file path=usr/share/man/man3pam/pam_sm_acct_mgmt.3pam
file path=usr/share/man/man3pam/pam_sm_authenticate.3pam
file path=usr/share/man/man3pam/pam_sm_chauthtok.3pam
file path=usr/share/man/man3pam/pam_sm_open_session.3pam
file path=usr/share/man/man3pam/pam_sm_setcred.3pam
file path=usr/share/man/man3pam/pam_start.3pam
file path=usr/share/man/man3pam/pam_strerror.3pam
link path=usr/share/man/man3pam/pam_close_session.3pam \
    target=pam_open_session.3pam
link path=usr/share/man/man3pam/pam_end.3pam target=pam_start.3pam
link path=usr/share/man/man3pam/pam_get_data.3pam target=pam_set_data.3pam
link path=usr/share/man/man3pam/pam_get_item.3pam target=pam_set_item.3pam
link path=usr/share/man/man3pam/pam_sm_close_session.3pam \
    target=pam_sm_open_session.3pam
