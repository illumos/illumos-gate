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
use ExtUtils::MakeMaker;
use ExtUtils::Constant 0.11 'WriteConstants';

WriteMakefile(
    NAME		=> 'Sys::Syslog',
    VERSION_FROM	=> 'Syslog.pm', 
    MAN3PODS		=> {}, 	# Pods will be built by installman.
    XSPROTOARG          => '-noprototypes',
    realclean => {FILES=> 'const-c.inc const-xs.inc'},
);

my $_PATH_LOG;

if (-S "/dev/log" && -w "/dev/log") {
        # Most unixes have a unix domain socket /dev/log.
       $_PATH_LOG = "/dev/log";
} elsif (-c "/dev/conslog" && -w "/dev/conslog") {
        # SunOS 5.8 has a worldwritable /dev/conslog STREAMS log driver.
        # The /dev/log STREAMS log driver on this platform has permissions
        # and ownership `crw-r----- root sys'.  /dev/conslog has more liberal
        # permissions.
       $_PATH_LOG = "/dev/conslog";
} else {
       $_PATH_LOG = "";
}

WriteConstants(
    NAME => 'Sys::Syslog',
    NAMES => [qw(LOG_ALERT LOG_AUTH LOG_AUTHPRIV LOG_CONS LOG_CRIT LOG_CRON
                 LOG_DAEMON LOG_DEBUG LOG_EMERG LOG_ERR LOG_FACMASK LOG_FTP
                 LOG_INFO LOG_KERN LOG_LFMT LOG_LOCAL0 LOG_LOCAL1 LOG_LOCAL2
                 LOG_LOCAL3 LOG_LOCAL4 LOG_LOCAL5 LOG_LOCAL6 LOG_LOCAL7 LOG_LPR
                 LOG_MAIL LOG_NDELAY LOG_NEWS LOG_NFACILITIES LOG_NOTICE
                 LOG_NOWAIT LOG_ODELAY LOG_PERROR LOG_PID LOG_PRIMASK LOG_SYSLOG
                 LOG_USER LOG_UUCP LOG_WARNING),
              {name=>"_PATH_LOG", type=>"PV", default=>["PV",qq("$_PATH_LOG")]},
             ],
);
