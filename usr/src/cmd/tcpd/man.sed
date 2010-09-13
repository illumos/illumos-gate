#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# This sed command script edits the man pages distrubuted with tcp_wrappers
# into a format appropriate for Solaris.  This mostly changes the section names
# of these man pages and of references to Solaris man pages, but also tweaks
# the body text in a few places to better describe the operation under Solaris.
#

1i\
'\\" t\
\.\\"\
\.\\" Modified for Solaris to to add the Solaris stability classification,\
\.\\" and to add a note about source availability.\
\.\\"\ 
s/#include "tcpd.h"/#include <tcpd.h>/

/#include <tcpd.h>/a\
\.\\" Begin Sun update\
\
cc [ flag  ... ] file ...  [ library ... ] \-lwrap\
\.\\" End Sun update

s/or \\fItlid\\fR//
s/or \\fItlid.conf\\fR //
s/tlid.conf(5), format of the tlid control file.//

s/inetd.conf(5)/inetd.conf(4)/g
s/hosts_access(5)/hosts_access(4)/g
s/\\fIhosts_access\\fR(5)/\\fIhosts_access\\fR(4)/g
s/hosts_options(5)/hosts_options(4)/g
s/\\fIhosts_options\\fR(5)/\\fIhosts_options\\fR(4)/g
s/syslog.conf(5)/syslog.conf(4)/g
s/inetd(8)/inetd(1M)/g
s/\\fIinetd\\fR(8)/\\fIinetd\\fR(1M)/g
s/tcpd(8)/tcpd(1M)/g
s/tcpdmatch(8)/tcpdmatch(1M)/g
s/tcpdchk(8)/tcpdchk(1M)/g
/^\.TH .* 8$/s/8$/1M/
/^\.TH .* 5$/s/5$/4/
s/\\fIlibwrap.a\\fR/\\fIlibwrap.so\\fR/g

$a\
\.\\" Begin Sun update\
.SH ATTRIBUTES\
See\
.BR attributes (5)\
for descriptions of the following attributes:\
.sp\
.TS\
box;\
cbp-1 | cbp-1\
l | l .\
ATTRIBUTE TYPE	ATTRIBUTE VALUE\
=\
Availability	SUNWtcpd\
=\
Interface Stability	Committed\
.TE \
.PP\
.SH NOTES\
Source for tcp_wrappers is available in the SUNWtcpdS package.\
\.\\" End Sun update

/^that pretend to have someone elses network address./a\
.SH LIBWRAP INTERFACE\
The same monitoring and access control functionality provided by the\
tcpd standalone program is also available through the libwrap shared\
library interface. Some programs, including the Solaris inetd daemon,\
have been modified  to use the libwrap interface and thus do not\
require replacing the real server programs with tcpd. The libwrap\
interface is also more efficient and can be used for inetd internal\
services. See\
.BR inetd (1M)\
for more information.

/^from PCs./,/^\.SH EXAMPLES/c\
from PCs.\
.PP\
Warning: If the local system runs an RFC 931 server it is important\
that it be configured NOT to use TCP Wrappers, or that TCP Wrappers\
be configured to avoid RFC 931-based access control for this service.\
If you use usernames in the access control files, make sure that you\
have a hosts.allow entry that allows the RFC 931 service (often called\
"identd" or "auth") without any username restrictions. Failure to heed\
this warning can result in two hosts getting in an endless loop of\
consulting each other's identd services.\
.SH EXAMPLES

/format of the inetd control file./a\
inetd(1M), how to invoke tcpd from inetd using the libwrap library.\
inetadm(1M), managing inetd services in the Service Management Framework.
