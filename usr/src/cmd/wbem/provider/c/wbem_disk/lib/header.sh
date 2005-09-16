#! /usr/bin/sh
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
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

INFILE=classes.tmp
INFILE1=assocclasses.tmp
CLASSFILE=classes
ASSOCCLASSFILE=assocclasses
LIBFILE=libname
TMPFILE=tmp.tmp
TMPFILE1=tmp1.tmp
PWD=`pwd`

HEADER=${PWD}/master.h


rm -f $HEADER $TMPFILE $TMPFILE1 $CLASSFILE $ASSOCCLASSFILE $LIBFILE

# Convert into separate lines per class
for x in `cat $INFILE`
do
	echo $x >> $TMPFILE
done

# Convert into separate lines per class
for x in `cat $INFILE1`
do
	echo $x >> $TMPFILE1
done
#####################################################
# Create file containing only the library name
tail -1 $TMPFILE > $LIBFILE
LIBNAME=`cat $LIBFILE`

# Create file containing only the class names
COUNT=`cat $TMPFILE | wc -l`
COUNT=`expr $COUNT - 1`
head -n $COUNT $TMPFILE > $CLASSFILE

# Create file containing only the class names
COUNT=`cat $TMPFILE1 | wc -l`
COUNT=`expr $COUNT - 1`
head -n $COUNT $TMPFILE1 > $ASSOCCLASSFILE
##############################################################
#
# Create the header file
#
echo "#include <cimapi.h>" > $HEADER
echo "#include <cimlogsvc.h>" > $HEADER

#
# Create the externs
# cp_enumInstances
# 

echo "" >> $HEADER
for x in `cat $TMPFILE`
do
	echo "extern CCIMInstanceList*" >> $HEADER
	echo "cp_enumInstances_$x(CCIMObjectPath* pOP);" >> $HEADER
done


#
# Create the externs
# cp_enumInstanceNames
# 

echo "" >> $HEADER
for x in `cat $TMPFILE`
do
	echo "extern CCIMObjectPathList*" >> $HEADER
	echo "cp_enumInstanceNames_$x(CCIMObjectPath* pOP);" >> $HEADER
done

#
# cp_createInstance
#

echo "" >> $HEADER
for x in `cat $TMPFILE`
do
	echo "extern CCIMObjectPath*" >> $HEADER
	echo "cp_createInstance_$x(CCIMObjectPath* pOP, CCIMInstance* pInst);" >> $HEADER
done

#
# cp_deleteInstance
#

echo "" >> $HEADER
for x in `cat $TMPFILE`
do
	echo "extern CIMBool" >> $HEADER
	echo "cp_deleteInstance_$x(CCIMObjectPath* pOP);" >> $HEADER
done

#
# cp_getInstance
#

echo "" >> $HEADER
for x in `cat $TMPFILE`
do
	echo "extern CCIMInstance*" >> $HEADER
	echo "cp_getInstance_$x(CCIMObjectPath* pOP);" >> $HEADER
done

#
# cp_setInstance
#

echo "" >> $HEADER
for x in `cat $TMPFILE`
do
	echo "extern CIMBool" >> $HEADER
	echo "cp_setInstance_$x(CCIMObjectPath* pOP, CCIMInstance* pInst);" >> $HEADER
done

#
# cp_setProperty
#

echo "" >> $HEADER
for x in `cat $TMPFILE`
do 
	echo "extern CIMBool" >> $HEADER
	echo "cp_setProperty_$x(CCIMObjectPath* pOP, CCIMProperty* pProp);" >> $HEADER
done

#
# cp_invokeMethod
#

echo "" >> $HEADER
for x in `cat $TMPFILE`
do
	echo "extern CCIMProperty*" >> $HEADER
	echo "cp_invokeMethod_$x(CCIMObjectPath* pOP, cimchar* pName,CCIMPropertyList* pInParams,CCIMPropertyList* pInOutParams);" >> $HEADER
done

#
# cp_execQuery
#

echo "" >> $HEADER
for x in `cat $TMPFILE`
do
	echo "extern CCIMInstanceList *" >> $HEADER
	echo "cp_execQuery_$x(CCIMObjectPath* pOP, char *selectList,char *nonJoinExp, char *queryExp, char *queryType);" >> $HEADER
done


#
# cp_associators
#

echo "" >> $HEADER
for x in `cat $TMPFILE1`
do
	echo "extern CCIMInstanceList *" >> $HEADER
	echo "cp_associators_$x(CCIMObjectPath* pAssocName, CCIMObjectPath *pObjectName, char *pResultClass, char *pRole, char *pResultRole);" >> $HEADER
done

#
# cp_associatorNames
#

echo "" >> $HEADER
for x in `cat $TMPFILE1`
do
	echo "extern CCIMObjectPathList *" >> $HEADER
	echo "cp_associatorNames_$x(CCIMObjectPath* pAssocName, CCIMObjectPath *pObjectName, char *pResultClass, char *pRole, char *pResultRole);" >> $HEADER
done

#
# cp_reference
#

echo "" >> $HEADER
for x in `cat $TMPFILE1`
do
	echo "extern CCIMObjectPathList *" >> $HEADER
	echo "cp_references_$x(CCIMObjectPath* pAssocName, CCIMObjectPath *pObjectName, char *pRole);" >> $HEADER
done

#
# cp_referenceNames
#

echo "" >> $HEADER
for x in `cat $TMPFILE1`
do
	echo "extern CCIMObjectPathList *" >> $HEADER
	echo "cp_referenceNames_$x(CCIMObjectPath* pAssocName, CCIMObjectPath *pObjectName, char *pRole);" >> $HEADER
done

##############################################################
#
# Create the dispatch tables
#
##############################################################


#
# *cpInvokeMethodTable
#

echo "" >> $HEADER
echo "CCIMProperty *" >> $HEADER
echo "(*cpInvokeMethodTable[])(CCIMObjectPath *, cimchar *, CCIMPropertyList *, CCIMPropertyList *) = {" >> $HEADER
for x in `cat $CLASSFILE`
do
	echo "cp_invokeMethod_$x," >> $HEADER
done

echo "cp_invokeMethod_$LIBNAME};" >> $HEADER


#
# *createInstanceTable
#

echo "" >> $HEADER
echo "CCIMObjectPath *" >> $HEADER
echo "(*createInstanceTable[])(CCIMObjectPath *, CCIMInstance *) = {" >> $HEADER
for x in `cat $CLASSFILE`
do
	echo "cp_createInstance_$x," >> $HEADER
done
echo "cp_createInstance_$LIBNAME};" >> $HEADER

#
# *deleteInstanceTable
#

echo "" >> $HEADER
echo "CIMBool" >> $HEADER
echo "(*deleteInstanceTable[])( CCIMObjectPath *) = {" >> $HEADER
for x in `cat $CLASSFILE`
do
	echo "cp_deleteInstance_$x," >> $HEADER
done
echo "cp_deleteInstance_$LIBNAME};" >> $HEADER

#
# *enumInstanceTable
#

echo "" >> $HEADER
echo "CCIMInstanceList *" >> $HEADER
echo "(*enumInstanceTable[])(CCIMObjectPath *) = {" >> $HEADER
for x in `cat $CLASSFILE`
do
	echo "cp_enumInstances_$x," >> $HEADER
done
echo "cp_enumInstances_$LIBNAME};" >> $HEADER

#
# *enumInstanceNamesTable
#

echo "" >> $HEADER
echo "CCIMObjectPathList *" >> $HEADER
echo "(*enumInstanceNamesTable[])(CCIMObjectPath *) = {" >> $HEADER
for x in `cat $CLASSFILE`
do
	echo "cp_enumInstanceNames_$x," >> $HEADER
done
echo "cp_enumInstanceNames_$LIBNAME};" >> $HEADER

#
# *getInstanceTable
#

echo "" >> $HEADER
echo "CCIMInstance *" >> $HEADER
echo "(*getInstanceTable[])(CCIMObjectPath *) = {" >> $HEADER
for x in `cat $CLASSFILE`
do
	echo "cp_getInstance_$x," >> $HEADER
done
echo "cp_getInstance_$LIBNAME};" >> $HEADER

#
# *setInstanceTable
#

echo "" >> $HEADER
echo "CIMBool" >> $HEADER
echo "(*setInstanceTable[])(CCIMObjectPath *, CCIMInstance *) = {" >> $HEADER
for x in `cat $CLASSFILE`
do
	echo "cp_setInstance_$x," >> $HEADER
done
echo "cp_setInstance_$LIBNAME};" >> $HEADER

#
# *setPropertyTable
#

echo "" >> $HEADER
echo "CIMBool" >> $HEADER
echo "(*setPropertyTable[])(CCIMObjectPath *, CCIMProperty *) = {" >> $HEADER
for x in `cat $CLASSFILE`
do
	echo "cp_setProperty_$x," >> $HEADER
done
echo "cp_setProperty_$LIBNAME};" >> $HEADER

#
# *execQueryTable
#

echo "" >> $HEADER
echo "CCIMInstanceList*" >> $HEADER
echo "(*execQueryTable[])(CCIMObjectPath *, char *, char *, char *, char*) = {" >> $HEADER
for x in `cat $CLASSFILE`
do
	echo "cp_execQuery_$x," >> $HEADER
done
echo "cp_execQuery_$LIBNAME};" >> $HEADER


#
# *associatorsTable
#

echo "" >> $HEADER
echo "CCIMInstanceList*" >> $HEADER
echo "(*associatorsTable[])(CCIMObjectPath *, CCIMObjectPath *, char *, char *, char*) = {" >> $HEADER
for x in `cat $ASSOCCLASSFILE`
do
	echo "cp_associators_$x," >> $HEADER
done
echo "cp_associators_$LIBNAME};" >> $HEADER

##############################################################
#
# *associatorNamesTable
#

echo "" >> $HEADER
echo "CCIMObjectPathList*" >> $HEADER
echo "(*associatorNamesTable[])(CCIMObjectPath *, CCIMObjectPath *, char *, char *, char*) = {" >> $HEADER
for x in `cat $ASSOCCLASSFILE`
do
	echo "cp_associatorNames_$x," >> $HEADER
done
echo "cp_associatorNames_$LIBNAME};" >> $HEADER


##############################################################
#
# *referencesTable
#

echo "" >> $HEADER
echo "CCIMObjectPathList*" >> $HEADER
echo "(*referencesTable[])(CCIMObjectPath *, CCIMObjectPath *, char *) = {" >> $HEADER
for x in `cat $ASSOCCLASSFILE`
do
	echo "cp_references_$x," >> $HEADER
done
echo "cp_references_$LIBNAME};" >> $HEADER

##############################################################
#
# *referenceNamesTable
#

echo "" >> $HEADER
echo "CCIMObjectPathList*" >> $HEADER
echo "(*referenceNamesTable[])(CCIMObjectPath *, CCIMObjectPath *, char *) = {" >> $HEADER
for x in `cat $ASSOCCLASSFILE`
do
	echo "cp_referenceNames_$x," >> $HEADER
done
echo "cp_referenceNames_$LIBNAME};" >> $HEADER
#
# Create Class Name table
#
echo "" >> $HEADER
echo "static char *classNameTable [] = {" >> $HEADER
for x in `cat $CLASSFILE`
do
        echo "\"$x\"," >> $HEADER
done
echo "\"$LIBNAME\"};" >> $HEADER

##############################################################
#
# Create Assoc Class Name table
#
echo "" >> $HEADER
echo "static char *assocclassNameTable [] = {" >> $HEADER
for x in `cat $ASSOCCLASSFILE`
do
        echo "\"$x\"," >> $HEADER
done
echo "\"$LIBNAME\"};" >> $HEADER
