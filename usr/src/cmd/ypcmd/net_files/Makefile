#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
# Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
#
#      Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
#      All Rights Reserved
#
# Portions of this source code were derived from Berkeley
# under license from the Regents of the University of
# California.
#
#----
# It is somewhat confusing to note that Solaris 2.x uses /etc/auto_master
# instead of the 4.x /etc/auto.master file name because of NIS+ treating a
# "." in a special way.
#
# Set the following variable to "-b" to have NIS servers use the domain name
# resolver for hosts not in the current domain.
#B=-b
B=
DIR =/etc
#
# If the ipnodes (IPv6 hosts file) lives in a directory other than
# /etc/inet, then you'll need to change the following line.
#
INETDIR=/etc/inet
#
# If the auth_attr, exec_attr, prof_attr files
# live in a directory other than /etc/security, then you'll
# need to change the following line.
#
RBACDIR=/etc/security
#
# If the passwd, shadow and/or adjunct files used by rpc.yppasswdd
# live in directory other than /etc then you'll need to change the
# following line.
# DO NOT indent the line, however, since /etc/init.d/yp attempts
# to find it with grep "^PWDIR" ...
#
PWDIR =/etc
DOM = `domainname`
NOPUSH = ""
ALIASES = /etc/mail/aliases
YPDIR=/usr/lib/netsvc/yp
SBINDIR=/usr/sbin
YPDBDIR=/var/yp
YPPUSH=$(YPDIR)/yppush
MAKEDBM=$(SBINDIR)/makedbm
MULTI=$(YPDIR)/multi
REVNETGROUP=$(SBINDIR)/revnetgroup
STDETHERS=$(YPDIR)/stdethers
STDHOSTS=$(YPDIR)/stdhosts
MKNETID=$(SBINDIR)/mknetid
MKALIAS=$(YPDIR)/mkalias

CHKPIPE=  || (  echo "NIS make terminated:" $@ 1>&2; kill -TERM 0 )


k:
	@if [ ! $(NOPUSH) ]; then $(MAKE)  $(MFLAGS) -k all; \
	else $(MAKE) $(MFLAGS) -k all NOPUSH=$(NOPUSH);fi

all: passwd group hosts ipnodes ethers networks rpc services protocols \
	netgroup bootparams aliases publickey netid netmasks c2secure \
	timezone auto.master auto.home ageing \
	auth.attr exec.attr prof.attr user.attr

c2secure:
	-@if [ -f $(PWDIR)/security/passwd.adjunct ]; then \
		if [ ! $(NOPUSH) ]; then $(MAKE)  $(MFLAGS) -k \
		passwd.adjunct.time group.adjunct.time; \
		else $(MAKE) $(MFLAGS) -k NOPUSH=$(NOPUSH) \
		passwd.adjunct.time group.adjunct.time; \
		fi; \
	fi

passwd.time: $(PWDIR)/passwd $(PWDIR)/shadow
	-@if [ -f $(PWDIR)/security/passwd.adjunct ]; then \
		(nawk 'BEGIN { FS=":"; OFS=":" } /^[a-zA-Z0-9_]/ { $$2 = "##" $$1; printf "%s\t%s\n", $$1, $$0 }' $(PWDIR)/passwd $(CHKPIPE)) | $(MAKEDBM) - $(YPDBDIR)/$(DOM)/passwd.byname; \
		(nawk 'BEGIN { FS=":"; OFS=":"  } /^[a-zA-Z0-9_]/ { $$2 = "##" $$1; printf "%-10d\t%s\n", $$3, $$0 }' $(PWDIR)/passwd $(CHKPIPE)) | $(MAKEDBM) - $(YPDBDIR)/$(DOM)/passwd.byuid; \
	elif [ -f $(PWDIR)/shadow ]; then \
		(nawk 'BEGIN { FS=":"; OFS=":"; while ( getline < "$(PWDIR)/shadow" > 0) shadow[$$1] = $$2; } /^[a-zA-Z0-9_]/ { $$2 = shadow[$$1]; printf "%s\t%s\n",$$1,$$0 }' $(PWDIR)/passwd $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/passwd.byname; \
		(nawk 'BEGIN { FS=":"; OFS=":"; while ( getline < "$(PWDIR)/shadow" > 0) shadow[$$1] = $$2; } /^[a-zA-Z0-9_]/ { $$2 = shadow[$$1]; printf "%-10d\t%s\n",$$3,$$0 }' $(PWDIR)/passwd $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/passwd.byuid; \
	else \
		(awk 'BEGIN { FS=":"; OFS="\t"; } /^[a-zA-Z0-9_]/ { print $$1, $$0 }' $(PWDIR)/passwd  $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/passwd.byname; \
		(awk 'BEGIN { FS=":"; OFS="\t"; } /^[a-zA-Z0-9_]/ { printf("%-10d ", $$3); print $$0 }' $(PWDIR)/passwd $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/passwd.byuid; \
	fi
	@touch passwd.time;
	@echo "updated passwd";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) passwd.byname; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) passwd.byuid; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed passwd"; fi

group.time: $(DIR)/group
	@(awk 'BEGIN { FS=":"; OFS="\t"; } /^[a-zA-Z0-9_]/ { print $$1, $$0 }' $(DIR)/group $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/group.byname;
	@(awk 'BEGIN { FS=":"; OFS="\t"; } /^[a-zA-Z0-9_]/ { printf("%-10d ", $$3); print $$0 }' $(DIR)/group $(CHKPIPE)) | $(MAKEDBM) - $(YPDBDIR)/$(DOM)/group.bygid;
	@touch group.time;
	@echo "updated group";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) group.byname; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) group.bygid; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed group"; fi

project.time: $(DIR)/project
	@(awk 'BEGIN { FS=":"; OFS="\t"; } /^[a-zA-Z0-9_]/ { print $$1, $$0 }' $(DIR)/project $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/project.byname;
	@(awk 'BEGIN { FS=":"; OFS="\t"; } /^[a-zA-Z0-9_]/ { printf("%-10d ", $$2); print $$0 }' $(DIR)/project $(CHKPIPE)) | $(MAKEDBM) - $(YPDBDIR)/$(DOM)/project.byprojid;
	@touch project.time;
	@echo "updated project";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) project.byname; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) project.byprojid; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed project"; fi

ipnodes.time: $(INETDIR)/ipnodes
	@($(MULTI) -n $(B) -l $(INETDIR)/ipnodes);
	@($(STDHOSTS) -wn $(INETDIR)/ipnodes $(CHKPIPE))| \
	(awk 'BEGIN { OFS="\t"; } $$1 !~ /^#/ { print $$1, $$0 }' $(CHKPIPE)) | \
	$(MAKEDBM) $(B) - $(YPDBDIR)/$(DOM)/ipnodes.byaddr;
	@touch ipnodes.time;
	@echo "updated ipnodes";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) ipnodes.byname; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) ipnodes.byaddr; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed ipnodes"; fi

hosts.time: $(DIR)/hosts
	@($(MULTI) $(B) -l $(DIR)/hosts);
	@($(STDHOSTS) -w $(DIR)/hosts $(CHKPIPE))| \
	(awk 'BEGIN { OFS="\t"; } $$1 !~ /^#/ { print $$1, $$0 }' $(CHKPIPE)) | \
	$(MAKEDBM) $(B) - $(YPDBDIR)/$(DOM)/hosts.byaddr;
	@touch hosts.time;
	@echo "updated hosts";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) hosts.byname; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) hosts.byaddr; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed hosts"; fi

ethers.time: $(DIR)/ethers
	@($(STDETHERS) $(DIR)/ethers $(CHKPIPE)) \
	|(awk '{print $$1, $$0; for (i = 3;i <= NF;i++) print $$i,$$0}' $(CHKPIPE)) \
	| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/ethers.byaddr

	@(awk 'BEGIN { OFS="\t"; } $$1 !~ /^#/ { print $$2, $$0 }' \
	   $(DIR)/ethers $(CHKPIPE)) | \
	$(MAKEDBM) - $(YPDBDIR)/$(DOM)/ethers.byname;
	@touch ethers.time;
	@echo "updated ethers";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) ethers.byname; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) ethers.byaddr; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed ethers"; fi

networks.time: $(DIR)/networks
	@(sed -e "/^#/d" -e s/#.*$$// $(DIR)/networks $(CHKPIPE)) |( awk \
	    '{print $$1, $$0; for (i = 3;i <= NF;i++) print $$i,$$0}' \
	    $(CHKPIPE) )| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/networks.byname;
	@(awk 'BEGIN { OFS="\t"; } $$1 !~ /^#/ { print $$2, $$0 }' \
	   $(DIR)/networks $(CHKPIPE)) | $(MAKEDBM) - $(YPDBDIR)/$(DOM)/networks.byaddr;
	@touch networks.time;
	@echo "updated networks";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) networks.byname; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) networks.byaddr; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed networks"; fi

services.time: $(DIR)/services
	@(awk 'BEGIN { OFS="\t"; } $$1 !~ /^#/ { print $$2, $$0 }' \
	    $(DIR)/services $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/services.byname;
	@(awk 'BEGIN { OFS="\t"; } \
	$$1 !~ /^#/ { split($$2,pp,"/"); printf("%s/%s %s\n", $$1, pp[2], $$0);\
		if (seen[$$1] == "") {\
			printf("%s %s\n", $$1, $$0); seen[$$1]=$$1;} \
		for (i = 3; i <= NF && $$i !~ /^#/; i++) {\
			if (seen[$$i] == "") {\
				printf("%s %s\n", $$i, $$0); seen[$$i]=$$i;} \
			printf("%s/%s %s\n", $$i, pp[2], $$0)}}' \
		$(DIR)/services $(CHKPIPE)) | \
	$(MAKEDBM) $(B) - $(YPDBDIR)/$(DOM)/services.byservicename

	@touch services.time;
	@echo "updated services";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) services.byname; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) services.byservicename; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed services"; fi

rpc.time: $(DIR)/rpc
	@(awk 'BEGIN { OFS="\t"; } $$1 !~ /^#/ { print $$2, $$0 }' \
	    $(DIR)/rpc $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/rpc.bynumber;
	@touch rpc.time;
	@echo "updated rpc";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) rpc.bynumber; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed rpc"; fi

protocols.time: $(DIR)/protocols
	@(awk 'BEGIN { OFS="\t"; } $$1 !~ /^#/ { print $$2, $$0 }' \
	    $(DIR)/protocols $(CHKPIPE)) | $(MAKEDBM) - \
	    $(YPDBDIR)/$(DOM)/protocols.bynumber;

	@(sed -e "/^#/d" -e s/#.*$$// $(DIR)/protocols $(CHKPIPE)) |( awk \
	    '{print $$1,$$0; for (i = 3;i <= NF;i++) print $$i, $$0}' \
	    $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/protocols.byname;

	@touch protocols.time;
	@echo "updated protocols";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) protocols.byname; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) protocols.bynumber; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed protocols"; fi

netgroup.time: $(DIR)/netgroup
	@$(MAKEDBM) $(DIR)/netgroup $(YPDBDIR)/$(DOM)/netgroup
	@($(REVNETGROUP) < $(DIR)/netgroup -u $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/netgroup.byuser
	@($(REVNETGROUP) < $(DIR)/netgroup -h $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/netgroup.byhost
	@touch netgroup.time;
	@echo "updated netgroup";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) netgroup; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) netgroup.byuser; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) netgroup.byhost; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed netgroup"; fi

bootparams.time: $(DIR)/bootparams
	@(sed -e '/^#/d' -e s/#.*$$// -e 's/[	 ][	 ]*$$//' \
	    -e '/\\$$/s/\\$$/ /' $(DIR)/bootparams $(CHKPIPE))\
	|( awk '/ $$/ {printf "%s", $$0} !/ $$/ {print}' $(CHKPIPE))\
	|( sed -e 's/[	 ][	 ]*/ /g' $(CHKPIPE))\
	| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/bootparams;
	@touch bootparams.time;
	@echo "updated bootparams";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) bootparams; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed bootparams"; fi

aliases.time: $(ALIASES)
	@cp $(ALIASES) $(YPDBDIR)/$(DOM)/mail.aliases;
	@/usr/lib/sendmail -bi -oA$(YPDBDIR)/$(DOM)/mail.aliases;
	$(MKALIAS) $(YPDBDIR)/$(DOM)/mail.aliases $(YPDBDIR)/$(DOM)/mail.byaddr;
	@rm $(YPDBDIR)/$(DOM)/mail.aliases;
	@touch aliases.time;
	@echo "updated aliases";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) mail.aliases; fi
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) mail.byaddr; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed aliases"; fi

netmasks.time: $(DIR)/netmasks
	$(MAKEDBM) $(DIR)/netmasks $(YPDBDIR)/$(DOM)/netmasks.byaddr;
	@touch netmasks.time;
	@echo "updated netmasks";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) netmasks.byaddr; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed netmasks"; fi


publickey.time: $(DIR)/publickey
	@(sed "/^#/d" < $(DIR)/publickey $(CHKPIPE))| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/publickey.byname;
	@touch publickey.time;
	@echo "updated publickey";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) publickey.byname; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed publickey"; fi

netid.time: $(PWDIR)/passwd $(DIR)/group $(DIR)/hosts $(DIR)/netid
	@$(MKNETID) -q -p $(PWDIR)/passwd -g $(DIR)/group -h $(DIR)/hosts -m $(DIR)/netid > .ypjunk;
	@$(MAKEDBM) .ypjunk $(YPDBDIR)/$(DOM)/netid.byname;
	@rm -f .ypjunk;
	@touch netid.time;
	@echo "updated netid";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) netid.byname; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed netid"; fi

# Old way.  Could be restored by PSARC decision.
#
#passwd.adjunct.time: $(PWDIR)/security/passwd.adjunct
#	@(awk 'BEGIN { FS=":"; OFS="\t"; } /^[a-zA-Z0-9_]/ { print $$1, $$0 }' $(PWDIR)/security/passwd.adjunct $(CHKPIPE)) | \
#		$(MAKEDBM) -s - $(YPDBDIR)/$(DOM)/passwd.adjunct.byname;
#	@chmod 600 $(YPDBDIR)/$(DOM)/passwd.adjunct.byname.dir;
#	@chmod 600 $(YPDBDIR)/$(DOM)/passwd.adjunct.byname.pag;
#	@touch passwd.adjunct.time
#	@echo "updated passwd.adjunct";
#	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) passwd.adjunct.byname; fi
#	@if [ ! $(NOPUSH) ]; then echo "pushed passwd.adjunct"; fi

passwd.adjunct.time: $(PWDIR)/security/passwd.adjunct $(PWDIR)/shadow
	-@if [ -f $(PWDIR)/shadow ]; then \
		(nawk 'BEGIN { FS=":"; while (getline < "$(PWDIR)/shadow" > 0) shadow[$$1] = $$2; } /^[a-zA-Z0-9_]/ { $$2 = shadow[$$1]; OFS=":"; printf "%s\t%s\n", $$1, $$0 }' $(PWDIR)/security/passwd.adjunct $(CHKPIPE)) | $(MAKEDBM) -s - $(YPDBDIR)/$(DOM)/passwd.adjunct.byname; \
	else \
		(awk 'BEGIN { FS=":"; OFS="\t"; } /^[a-zA-Z0-9_]/ { print $$1, $$0 }' $(PWDIR)/security/passwd.adjunct $(CHKPIPE)) | \
		$(MAKEDBM) -s - $(YPDBDIR)/$(DOM)/passwd.adjunct.byname; \
	fi
	@chmod 600 $(YPDBDIR)/$(DOM)/passwd.adjunct.byname.dir;
	@chmod 600 $(YPDBDIR)/$(DOM)/passwd.adjunct.byname.pag;
	@touch passwd.adjunct.time
	@echo "updated passwd.adjunct";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) passwd.adjunct.byname; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed passwd.adjunct"; fi

group.adjunct.time: $(PWDIR)/security/group.adjunct
	@(awk 'BEGIN { FS=":"; OFS="\t"; } /^[a-zA-Z0-9_]/ { print $$1, $$0 }' $(PWDIR)/security/group.adjunct $(CHKPIPE)) | \
	$(MAKEDBM) -s - $(YPDBDIR)/$(DOM)/group.adjunct.byname;
	@chmod 600 $(YPDBDIR)/$(DOM)/group.adjunct.byname.dir;
	@chmod 600 $(YPDBDIR)/$(DOM)/group.adjunct.byname.pag;
	@touch group.adjunct.time
	@echo "updated group.adjunct";
	@if [ ! $(NOPUSH) ]; then $(YPPUSH) -d $(DOM) group.adjunct.byname; fi
	@if [ ! $(NOPUSH) ]; then echo "pushed group.adjunct"; fi

timezone.time:  $(DIR)/timezone
	-@if [ -f $(DIR)/timezone ]; then \
		sed -e "/^#/d" -e s/#.*$$// $(DIR)/timezone \
		| awk '{for (i = 2; i<=NF; i++) print $$i, $$0}' \
		| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/timezone.byname; \
		touch timezone.time; \
		echo "updated timezone"; \
		if [ ! $(NOPUSH) ]; then \
			$(YPPUSH) timezone.byname; \
			echo "pushed timezone"; \
		else \
		: ; \
		fi \
	else \
		echo "couldn't find $(DIR)/timezone"; \
	fi

auto.master.time:  $(DIR)/auto_master
	-@if [ -f $(DIR)/auto_master ]; then \
		sed -e "/^#/d" -e s/#.*$$// $(DIR)/auto_master \
		| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/auto.master; \
		touch auto.master.time; \
		echo "updated auto.master"; \
		if [ ! $(NOPUSH) ]; then \
			$(YPPUSH) auto.master; \
			echo "pushed auto.master"; \
		else \
		: ; \
		fi \
	else \
		echo "couldn't find $(DIR)/auto_master"; \
	fi

auto.home.time:  $(DIR)/auto_home
	-@if [ -f $(DIR)/auto_home ]; then \
		sed -e "/^#/d" -e s/#.*$$// $(DIR)/auto_home \
		| $(MAKEDBM) - $(YPDBDIR)/$(DOM)/auto.home; \
		touch auto.home.time; \
		echo "updated auto.home"; \
		if [ ! $(NOPUSH) ]; then \
			$(YPPUSH) auto.home; \
			echo "pushed auto.home"; \
		else \
		: ; \
		fi \
	else \
		echo "couldn't find $(DIR)/auto_home"; \
	fi


auth.attr.time:  $(RBACDIR)/auth_attr
	-@if [ -f $(RBACDIR)/auth_attr ]; then \
		sed -e "/^#/d" -e s/#.*$$// $(RBACDIR)/auth_attr \
		|sed -e '/\\$$/{:l' -e 'N;s/\\\n//;t h' -e ':h' \
		-e 's/\\$$/\\/;t l' -e } \
		| (nawk 'BEGIN { FS=":"; OFS=":" } /^[a-zA-Z0-9_]/ \
		{printf "%s:%s\n", $$1, $$0 }' $(CHKPIPE)) \
		| $(MAKEDBM) -S ":" -E - $(YPDBDIR)/$(DOM)/auth_attr; \
		touch auth.attr.time; \
		echo "updated auth_attr"; \
		if [ ! $(NOPUSH) ]; then \
			$(YPPUSH) auth_attr; \
			echo "pushed auth_attr"; \
		else \
		: ; \
		fi \
	else \
		echo "couldn't find $(RBACDIR)/auth_attr"; \
	fi

exec.attr.time:  $(RBACDIR)/exec_attr
	-@if [ -f $(RBACDIR)/exec_attr ]; then \
		sed -e "/^#/d" -e s/#.*$$// $(RBACDIR)/exec_attr \
		|sed -e '/\\$$/{:l' -e 'N;s/\\\n//;t h' -e ':h' \
		-e 's/\\$$/\\/;t l' -e } \
		| (nawk 'BEGIN { FS=":"; OFS=":" } /^[a-zA-Z0-9_]/ \
		{printf "%s:%s:%s:%s\n", $$1, $$2, $$6, $$0 }' $(CHKPIPE)) \
		| $(MAKEDBM) -S ":" -E -D 2 - $(YPDBDIR)/$(DOM)/exec_attr; \
		touch exec.attr.time; \
		echo "updated exec_attr"; \
		if [ ! $(NOPUSH) ]; then \
			$(YPPUSH) exec_attr; \
			echo "pushed exec_attr"; \
		else \
		: ; \
		fi \
	else \
		echo "couldn't find $(RBACDIR)/exec_attr"; \
	fi

prof.attr.time:  $(RBACDIR)/prof_attr
	-@if [ -f $(RBACDIR)/prof_attr ]; then \
		sed -e "/^#/d" -e s/#.*$$// $(RBACDIR)/prof_attr \
		|sed -e '/\\$$/{:l' -e 'N;s/\\\n//;t h' -e ':h' \
		-e 's/\\$$/\\/;t l' -e } \
		| (nawk 'BEGIN { FS=":"; OFS=":" } /^[a-zA-Z0-9_]/ \
		{printf "%s:%s\n", $$1, $$0 }' $(CHKPIPE)) \
		| $(MAKEDBM) -S ":" -E - $(YPDBDIR)/$(DOM)/prof_attr; \
		touch prof.attr.time; \
		echo "updated prof_attr"; \
		if [ ! $(NOPUSH) ]; then \
			$(YPPUSH) prof_attr; \
			echo "pushed prof_attr"; \
		else \
		: ; \
		fi \
	else \
		echo "couldn't find $(RBACDIR)/prof_attr"; \
	fi

user.attr.time:  $(DIR)/user_attr
	-@if [ -f $(DIR)/user_attr ]; then \
		sed -e "/^#/d" -e s/#.*$$// $(DIR)/user_attr \
		|sed -e '/\\$$/{:l' -e 'N;s/\\\n//;t h' -e ':h' \
		-e 's/\\$$/\\/;t l' -e } \
		| (nawk 'BEGIN { FS=":"; OFS=":" } /^[a-zA-Z0-9_]/ \
		{printf "%s:%s\n", $$1, $$0 }' $(CHKPIPE)) \
		| $(MAKEDBM) -S ":" -E - $(YPDBDIR)/$(DOM)/user_attr; \
		touch user.attr.time; \
		echo "updated user_attr"; \
		if [ ! $(NOPUSH) ]; then \
			$(YPPUSH) user_attr; \
			echo "pushed user_attr"; \
		else \
		: ; \
		fi \
	else \
		echo "couldn't find $(DIR)/user_attr"; \
	fi

ageing.time:  $(PWDIR)/shadow
	-@if [ -f $(PWDIR)/shadow ]; then \
		(awk 'BEGIN {FS=":"; OFS=":"} $$1 !~ /^#/ {printf "%s\t%s:%s:%s:%s:%s:%s:%s:%s\n", $$1,$$1,$$3,$$4,$$5,$$6,$$7,$$8,$$9}' $(PWDIR)/shadow) | $(MAKEDBM) - $(YPDBDIR)/$(DOM)/ageing.byname; \
		touch ageing.time; \
		echo "updated ageing"; \
	else \
		echo "couldn't find $(PWDIR)/shadow"; \
	fi

passwd: passwd.time
group: group.time
project: project.time
hosts: hosts.time
ipnodes: ipnodes.time
ethers: ethers.time
networks: networks.time
rpc: rpc.time
services: services.time
protocols: protocols.time
netgroup: netgroup.time
bootparams: bootparams.time
aliases: aliases.time
publickey: publickey.time
netid: netid.time
passwd.adjunct: passwd.adjunct.time
group.adjunct: group.adjunct.time
netmasks: netmasks.time
timezone: timezone.time
auto.master: auto.master.time
auto.home: auto.home.time
auth.attr:auth.attr.time
exec.attr:exec.attr.time
prof.attr:prof.attr.time
user.attr:user.attr.time
$(DIR)/netid:
$(DIR)/timezone:
$(DIR)/auto_master:
$(DIR)/auto_home:
$(PWDIR)/shadow:
$(DIR)/auth_attr:
$(DIR)/exec_attr:
$(DIR)/prof_attr:
$(DIR)/user_attr:
ageing: ageing.time
