/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1993, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

typedef int (*KIT_ADD_INFO) PROTO_LIST ((B_Key *, POINTER));
typedef int (*KIT_MAKE_INFO) PROTO_LIST ((POINTER *, B_Key *));

/* The definition in C++ is:
 class B_KeyInfoType {
 public:
   B_KeyInfoType (KIT_ADD_INFO AddInfo) {
     _AddInfo = AddInfo;
     _MakeInfo = KeyInfoType::makeError;}
   B_KeyInfoType (KIT_ADD_INFO AddInfo, KIT_MAKE_INFO MakeInfo) {
     _AddInfo = AddInfo;
     _MakeInfo = MakeInfo;}

   int addInfo (B_Key *key, POINTER info) {return (*_AddInfo) (key, info);}
   int makeInfo (POINTER *info, B_Key *key) {return (*_MakeInfo) (info, key);}

   static int makeError (POINTER *info, B_Key *key);

 private:
   KIT_ADD_INFO _AddInfo;
   KIT_MAKE_INFO _MakeInfo;
 };

   Note that a derived class simply calls one of the B_KeyInfoType constructors
     which set the addInfo or both the addInfo and makeInfo callbacks.
   There is no need for an extra level involving virtual functions because
     each key class only has one instance, making a V table a waste of space.
   An example of a derived class is:

 class KITItem : public B_KeyInfoType {
 public:
   // Set addInfo and leave makeInfo as B_KeyInfoType::makeError
   KITItem () : B_KeyInfoType (KITItem::addInfo) {};

   static int addInfo (B_Key *key, POINTER info);
 };


   There is one global instance which is used by B_Key::setInfo, etc.:
   
 KITItem KITItem;
 */

typedef struct B_KeyInfoType {
  KIT_ADD_INFO AddInfo;
  KIT_MAKE_INFO MakeInfo;
} B_KeyInfoType;

int B_KeyInfoTypeMakeError PROTO_LIST ((POINTER *, B_Key *));
