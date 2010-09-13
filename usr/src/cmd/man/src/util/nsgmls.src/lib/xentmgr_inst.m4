// Copyright (c) 1994, 1995 James Clark
// See the file COPYING for copying permission.

#include "splib.h"

#ifdef SP_MANUAL_INST

#define SP_DEFINE_TEMPLATES
#include "StringOf.h"
#include "Vector.h"
#include "NCVector.h"
#include "ListIter.h"
#include "IList.h"
#include "List.h"
#include "Owner.h"
#include "OwnerTable.h"
#include "PointerTable.h"
#include "HashTableItemBase.h"
#include "HashTable.h"
#include "Ptr.h"
#include "CharMap.h"
#undef SP_DEFINE_TEMPLATES

#include "StorageManager.h"
#include "ExtendEntityManager.h"
#include "OffsetOrderedList.h"
#include "CodingSystem.h"
#include "CodingSystemKit.h"
#include "types.h"
#include "StringOf.h"
#include "DescriptorManager.h"
#include "StorageManager.h"
#include "Boolean.h"
#include "StorageObjectPosition.h"
#include "CatalogEntry.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

__instantiate(String<char>)
__instantiate(NCVector<Owner<StorageObject> >)
__instantiate(Vector<StorageObjectSpec>)
__instantiate(NCVector<Owner<OffsetOrderedListBlock> >)
__instantiate(NCVector<StorageObjectPosition>)
__instantiate(IList<ListItem<DescriptorUser*> >)
__instantiate(List<DescriptorUser*>)
__instantiate(ListIter<DescriptorUser *>)
__instantiate(ListItem<DescriptorUser *>)
__instantiate(IListIter<ListItem<DescriptorUser*> >)
__instantiate(Owner<StorageObject>)
__instantiate(Owner<Decoder>)
__instantiate(Owner<OffsetOrderedListBlock>)
__instantiate(Owner<ExtendEntityManager::CatalogManager>)
__instantiate(Owner<StorageManager>)
__instantiate(NCVector<Owner<StorageManager> >)
__instantiate(`HashTable<String<Char>,CatalogEntry>')
__instantiate(`HashTableIter<String<Char>,CatalogEntry>')
__instantiate(`HashTableItem<String<Char>,CatalogEntry>')
__instantiate(HashTableItemBase<String<Char> >)
__instantiate(`OwnerTable<HashTableItemBase<String<Char> >,String<Char>,Hash,HashTableKeyFunction<String<Char> > >')
__instantiate(`CopyOwnerTable<HashTableItemBase<String<Char> >,String<Char>,Hash,HashTableKeyFunction<String<Char> > >')
__instantiate(`OwnerTableIter<HashTableItemBase<String<Char> >, String<Char>, Hash, HashTableKeyFunction<String<Char> > >')
__instantiate(`PointerTable<HashTableItemBase<String<Char> >*,String<Char>,Hash,HashTableKeyFunction<String<Char> > >')
__instantiate(`PointerTableIter<HashTableItemBase<String<Char> > *, String<Char>, Hash, HashTableKeyFunction<String<Char> > >')
__instantiate(Vector<HashTableItemBase<String<Char> >*>)
__instantiate(Ptr<ExtendEntityManager>)
__instantiate(ConstPtr<ExtendEntityManager>)
__instantiate(Vector<ParsedSystemId::Map>)
__instantiate(ConstPtr<InputCodingSystemKit>)
__instantiate(Ptr<InputCodingSystemKit>)
__instantiate(ConstPtr<CodingSystemKit>)
__instantiate(Ptr<CodingSystemKit>)
__instantiate(CharMap<Char>)
#ifdef SP_MULTI_BYTE
__instantiate(CharMapPage<Char>)
__instantiate(CharMapColumn<Char>)
#endif
__instantiate(CharMapResource<Char>)
__instantiate(Ptr<CharMapResource<Char> >)
__instantiate(ConstPtr<CharMapResource<Char> >)

#ifdef SP_NAMESPACE
}
#endif

#endif /* SP_MANUAL_INST */
