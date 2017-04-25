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

# Copyright 2017, Richard Lowe

file path=usr/share/man/man3sysevent/sysevent_bind_handle.3sysevent
file path=usr/share/man/man3sysevent/sysevent_free.3sysevent
file path=usr/share/man/man3sysevent/sysevent_get_attr_list.3sysevent
file path=usr/share/man/man3sysevent/sysevent_get_class_name.3sysevent
file path=usr/share/man/man3sysevent/sysevent_get_vendor_name.3sysevent
file path=usr/share/man/man3sysevent/sysevent_post_event.3sysevent
file path=usr/share/man/man3sysevent/sysevent_subscribe_event.3sysevent
link path=usr/share/man/man3sysevent/sysevent_get_pid.3sysevent \
    target=sysevent_get_vendor_name.3sysevent
link path=usr/share/man/man3sysevent/sysevent_get_pub_name.3sysevent \
    target=sysevent_get_vendor_name.3sysevent
link path=usr/share/man/man3sysevent/sysevent_get_seq.3sysevent \
    target=sysevent_get_class_name.3sysevent
link path=usr/share/man/man3sysevent/sysevent_get_size.3sysevent \
    target=sysevent_get_class_name.3sysevent
link path=usr/share/man/man3sysevent/sysevent_get_subclass_name.3sysevent \
    target=sysevent_get_class_name.3sysevent
link path=usr/share/man/man3sysevent/sysevent_get_time.3sysevent \
    target=sysevent_get_class_name.3sysevent
link path=usr/share/man/man3sysevent/sysevent_unbind_handle.3sysevent \
    target=sysevent_bind_handle.3sysevent
link path=usr/share/man/man3sysevent/sysevent_unsubscribe_event.3sysevent \
    target=sysevent_subscribe_event.3sysevent
