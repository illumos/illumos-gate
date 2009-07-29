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
# cmd/wbem/provider/com/sun/wbem/solarisprovider/srm/Makefile
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/cmd/wbem/Makefile.wbem

JARFILE=	perfprovider.jar
PACKAGEPATH=	com/sun/wbem/solarisprovider/srm
RESOURCE_PACKAGEPATH=	$(PACKAGEPATH)/resources
DOCDIR=		doc

DIRMODE= 755
FILEMODE= 644

ROOTCOM=				$(ROOTWBEM)/com
ROOTCOMSUN=				$(ROOTCOM)/sun
ROOTCOMSUNWBEM=				$(ROOTCOMSUN)/wbem
ROOTCOMSUNWBEMSOLARISPROVIDER=		$(ROOTCOMSUNWBEM)/solarisprovider
ROOTCOMSUNWBEMSOLARISPROVIDERSRM= 	$(ROOTCOMSUNWBEMSOLARISPROVIDER)/srm
ROOTCOMSUNWBEMSOLARISPROVIDERSRMRESOURCES= $(ROOTCOMSUNWBEMSOLARISPROVIDERSRM)/resources

PROVIDERDIRS=		$(ROOTCOM) 				\
			$(ROOTCOMSUN)	 			\
			$(ROOTCOMSUNWBEM)	 			\
			$(ROOTCOMSUNWBEMSOLARISPROVIDER)	 	\
			$(ROOTCOMSUNWBEMSOLARISPROVIDERSRM)	\
			$(ROOTCOMSUNWBEMSOLARISPROVIDERSRMRESOURCES)

ROOTPROVIDERFILE= 	$(FILE:%=$(ROOTCOMSUNWBEMSOLARISPROVIDERSRM)/%)
ROOTRESOURCEFILE= 	$(FILE:%=$(ROOTCOMSUNWBEMSOLARISPROVIDERSRMRESOURCES)/%)

$(PROVIDERDIRS): $(ROOTWBEMDIRS)
	$(INS.dir)

$(ROOTCOMSUNWBEMSOLARISPROVIDERSRM)/%: %
	$(INS.file)

$(ROOTCOMSUNWBEMSOLARISPROVIDERSRMRESOURCES)/%: %
	$(INS.file)

SOURCE:sh = ls *.java

CLASSES:sh = ls *.class 2> /dev/null | sed 's/\$/\$\$/' 


all: 		$(PROVIDERDIRS) jar 

install: 	all resources mof $(PROG)   

resources:	$(ROOTCOMSUNWBEMSOLARISPROVIDERSRMRESOURCES)/LogMessages.properties 	\
		$(ROOTCOMSUNWBEMSOLARISPROVIDERSRMRESOURCES)/Exceptions.properties 	\
		$(ROOTCOMSUNWBEMSOLARISPROVIDERSRM)/perfprovider.properties


mof:		$(ROOTMOF)/Solaris_Performance1.0.mof

jar:		jarfile $(ROOTWBEM)/$(JARFILE)

jarfile:	$(SOURCE:java=class) 
	cd $(PROVIDERSRC);\
	$(JAR) -cvf0M $(JARFILE) $(PACKAGEPATH)/*class; \
	cd $(PROVIDERSRC);\
	$(JAR) -uvf0M $(JARFILE) $(RESOURCE_PACKAGEPATH:%=%/*.properties);
	$(MV) $(PROVIDERSRC)/$(JARFILE) .

doc:	.FORCE
	$(JAVADOC) -d $(DOCDIR) -classpath $(CLASSPATH) $(SOURCE)

clobber: clean

clean:
	$(RM) *.class

check:
	$(JSTYLE) $(JSTYLE_TAIL) $(SOURCE)

.WAIT:

.FORCE:

