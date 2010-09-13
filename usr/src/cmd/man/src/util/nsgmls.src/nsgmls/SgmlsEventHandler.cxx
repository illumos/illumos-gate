/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1994 James Clark
 * See the file COPYING for copying permission.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "config.h"
#include "SgmlsEventHandler.h"
#include "SgmlParser.h"
#include "ParserOptions.h"
#include "Entity.h"
#include "Notation.h"
#include "Attribute.h"
#include "ExtendEntityManager.h"
#include "StorageManager.h"
#include "macros.h"

#ifdef __GNUC__
using namespace std;
#endif

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

const char dataCode = '-';
const char piCode = '?';
const char conformingCode = 'C';
const char appinfoCode = '#';
const char startElementCode = '(';
const char endElementCode = ')';
const char referenceEntityCode = '&';
const char attributeCode = 'A';
const char dataAttributeCode = 'D';
const char linkAttributeCode = 'a';
const char defineNotationCode = 'N';
const char defineExternalEntityCode = 'E';
const char defineInternalEntityCode = 'I';
const char defineSubdocEntityCode = 'S';
const char defineExternalTextEntityCode = 'T';
const char pubidCode = 'p';
const char sysidCode = 's';
const char startSubdocCode = '{';
const char endSubdocCode = '}';
const char fileCode = 'f';
const char locationCode = 'L';
const char includedElementCode = 'i';
const char emptyElementCode = 'e';

const OutputCharStream::Newline nl = OutputCharStream::newline;

const char space = ' ';
const Char re = '\r';

inline
void SgmlsEventHandler::startData()
{
	if (!haveData_) {
		os() << dataCode;
		haveData_ = 1;
	}
}

inline
void SgmlsEventHandler::flushData()
{
	if (haveData_) {
		os() << nl;
		haveData_ = 0;
	}
}

inline
void SgmlsEventHandler::outputLocation(const Location &loc)
{
	if (outputLine_)
		outputLocation1(loc);
}

SgmlsEventHandler::SgmlsEventHandler(const SgmlParser *parser,
		OutputCharStream *os,
		Messenger *messenger,
		unsigned outputFlags)
: SgmlsSubdocState(parser), os_(os), messenger_(messenger),
	outputLine_((outputFlags & outputLine) != 0),
	outputEntity_((outputFlags & outputEntity) != 0),
	outputId_((outputFlags & outputId) != 0),
	outputNotationSysid_((outputFlags & outputNotationSysid) != 0),
	outputIncluded_((outputFlags & outputIncluded) != 0),
	outputNonSgml_((outputFlags & outputNonSgml) != 0),
	outputEmpty_((outputFlags & outputEmpty) != 0),
	haveData_(0), lastSos_(0)
{
	os_->setEscaper(escape);
}

SgmlsEventHandler::~SgmlsEventHandler()
{
	flushData();
	if (errorCount() == 0)
		os() << conformingCode << nl;
	delete os_;
}

void SgmlsEventHandler::message(MessageEvent *event)
{
	messenger_->dispatchMessage(event->message());
	ErrorCountEventHandler::message(event);
}

void SgmlsEventHandler::appinfo(AppinfoEvent *event)
{
	const StringC *str;
	if (event->literal(str)) {
		outputLocation(event->location());
		flushData();
		os() << appinfoCode;
		outputString(*str);
		os() << nl;
	}
	delete event;
}

void SgmlsEventHandler::endProlog(EndPrologEvent *event)
{
	if (outputEntity_) {
		flushData();
		const Dtd &dtd = event->dtd();
		Dtd::ConstEntityIter iter(dtd.generalEntityIter());
		for (;;) {
			const Entity *entity = iter.next().pointer();
			if (!entity)
	break;
			defineEntity(entity);
		}
	}
	if (!event->lpdPointer().isNull()) {
		linkProcess_.init(event->lpdPointer());
		haveLinkProcess_ = 1;
		flushData();
	}
	for (size_t i = 0; i < event->simpleLinkNames().size(); i++) {
		flushData();
		attributes(event->simpleLinkAttributes()[i],
			linkAttributeCode,
			&event->simpleLinkNames()[i]);
	}
	delete event;
}

void SgmlsEventHandler::entityDefaulted(EntityDefaultedEvent *event)
{
	if (outputEntity_) {
		flushData();
		defineEntity(event->entityPointer().pointer());
	}
	delete event;
}

void SgmlsEventHandler::uselink(UselinkEvent *event)
{
	linkProcess_.uselink(event->linkSet(),
		event->restore(),
		event->lpd().pointer());
	delete event;
}

void SgmlsEventHandler::sgmlDecl(SgmlDeclEvent *event)
{
	sd_ = event->sdPointer();
	syntax_ = event->instanceSyntaxPointer(); // FIXME which syntax?
	delete event;
}

void SgmlsEventHandler::data(DataEvent *event)
{
	outputLocation(event->location());
	startData();
	outputString(event->data(), event->dataLength());
	delete event;
}

void SgmlsEventHandler::sdataEntity(SdataEntityEvent *event)
{
	outputLocation(event->location());
	startData();
	os() << "\\|";
	outputString(event->data(), event->dataLength());
	os() << "\\|";
	delete event;
}

void SgmlsEventHandler::pi(PiEvent *event)
{
	outputLocation(event->location());
	flushData();
	os() << piCode;
	outputString(event->data(), event->dataLength());
	os() << nl;
	delete event;
}

void SgmlsEventHandler::nonSgmlChar(NonSgmlCharEvent *event)
{
	if (outputNonSgml_) {
		outputLocation(event->location());
		startData();
		os() << "\\%" << (unsigned long)event->character() << ';';
	}
	delete event;
}

void SgmlsEventHandler::startElement(StartElementEvent *event)
{
	flushData();
	currentLocation_ = event->location();
	if (haveLinkProcess_) {
		const AttributeList *linkAttributes;
		const ResultElementSpec *resultElementSpec;
		linkProcess_.startElement(event->elementType(),
			event->attributes(),
			event->location(),
			*this, // Messenger &
			linkAttributes,
			resultElementSpec);
		if (linkAttributes)
			attributes(*linkAttributes,
				linkAttributeCode, &linkProcess_.name());
	}
	attributes(event->attributes(), attributeCode, 0);
	currentLocation_.clear();
	if (outputIncluded_ && event->included())
		os() << includedElementCode << nl;
	if (outputEmpty_ && event->mustOmitEnd())
		os() << emptyElementCode << nl;
	outputLocation(event->location());
	os() << startElementCode << event->name() << nl;
	delete event;
}

void SgmlsEventHandler::attributes(const AttributeList &attributes,
	char code,
	const StringC *ownerName)
{
	size_t nAttributes = attributes.size();
	for (size_t i = 0; i < nAttributes; i++) {
		const Text *text;
		const StringC *string;
		const AttributeValue *value = attributes.value(i);
		if (value) {
			switch (value->info(text, string)) {
			case AttributeValue::implied:
	startAttribute(attributes.name(i), code, ownerName);
	os() << "IMPLIED" << nl;
	break;
			case AttributeValue::tokenized:
	{
		const char *typeString = "TOKEN";
		const AttributeSemantics *semantics = attributes.semantics(i);
		if (semantics) {
			ConstPtr < Notation > notation
				= semantics->notation();
			if (!notation.isNull()) {
				defineNotation(notation.pointer());
				typeString = "NOTATION";
			} else {
				size_t nEntities = semantics->nEntities();
				if (nEntities) {
		typeString = "ENTITY";
		if (!outputEntity_)
			for (size_t i = 0; i < nEntities; i++) {
				const Entity *entity =
					semantics->entity(i).pointer();
				if (!markEntity(entity))
					defineEntity(entity);
			}
				}
			}
		}
		if (outputId_ && attributes.id(i))
			typeString = "ID";
		startAttribute(attributes.name(i), code, ownerName);
		os() << typeString << space << *string << nl;
	}
	break;
			case AttributeValue::cdata:
	{
		startAttribute(attributes.name(i), code, ownerName);
		os() << "CDATA ";
		TextIter iter(*text);
		TextItem::Type type;
		const Char *p;
		size_t length;
		const Location *loc;
		while (iter.next(type, p, length, loc))
			switch (type) {
			case TextItem::data:
			case TextItem::cdata:
				outputString(p, length);
				break;
			case TextItem::sdata:
				os() << "\\|";
				outputString(p, length);
				os() << "\\|";
				break;
			case TextItem::nonSgml:
				if (outputNonSgml_)
		os() << "\\%" << (unsigned long)*p << ';';
				break;
			default:
				break;
			}
		os() << nl;
	}
	break;
			}
		}
	}
}

void SgmlsEventHandler::startAttribute(const StringC &name,
		char code,
		const StringC *ownerName)
{
	os() << code;
	if (ownerName)
		os() << *ownerName << space;
	os() << name << space;
}

void SgmlsEventHandler::endElement(EndElementEvent *event)
{
	flushData();
	if (haveLinkProcess_)
		linkProcess_.endElement();
	outputLocation(event->location());
	os() << endElementCode << event->name() << nl;
	delete event;
}

void SgmlsEventHandler::externalDataEntity(ExternalDataEntityEvent *event)
{
	currentLocation_ = event->location();
	outputLocation(event->location());
	flushData();
	if (!outputEntity_ && !markEntity(event->entity()))
		defineExternalDataEntity(event->entity());
	currentLocation_.clear();
	os() << referenceEntityCode << event->entity()->name() << nl;
	delete event;
}

void SgmlsEventHandler::subdocEntity(SubdocEntityEvent *event)
{
	currentLocation_ = event->location();
	outputLocation(event->location());
	flushData();
	const SubdocEntity *entity = event->entity();
	if (!outputEntity_ && !markEntity(entity))
		defineSubdocEntity(entity);
	currentLocation_.clear();
	os() << startSubdocCode << entity->name() << nl;
	SgmlParser::Params params;
	params.subdocInheritActiveLinkTypes = 1;
	params.subdocReferenced = 1;
	params.origin = event->entityOrigin()->copy();
	params.parent = parser_;
	params.sysid = entity->externalId().effectiveSystemId();
	params.entityType = SgmlParser::Params::subdoc;
	SgmlParser parser(params);
	SgmlsSubdocState oldState;
	SgmlsSubdocState::swap(oldState);
	SgmlsSubdocState::init(&parser);
	parser.parseAll(*this);
	oldState.swap(*this);
	os() << endSubdocCode << entity->name() << nl;
	delete event;
}

void SgmlsEventHandler::defineEntity(const Entity *entity)
{
	const InternalEntity *internalEntity = entity->asInternalEntity();
	if (internalEntity)
		defineInternalEntity(internalEntity);
	else {
		switch (entity->dataType()) {
		case Entity::cdata:
		case Entity::sdata:
		case Entity::ndata:
			defineExternalDataEntity(
				entity->asExternalDataEntity());
			break;
		case Entity::subdoc:
			defineSubdocEntity(entity->asSubdocEntity());
			break;
		case Entity::sgmlText:
			defineExternalTextEntity(entity->asExternalEntity());
			break;
		default:
			CANNOT_HAPPEN();
		}
	}
}

void SgmlsEventHandler::defineExternalDataEntity(
	const ExternalDataEntity *entity)
{
	const Notation *notation = entity->notation();
	defineNotation(notation);
	externalId(entity->externalId());
	const char *typeString;
	switch (entity->dataType()) {
	case Entity::cdata:
		typeString = "CDATA";
		break;
	case Entity::sdata:
		typeString = "SDATA";
		break;
	case Entity::ndata:
		typeString = "NDATA";
		break;
	default:
		CANNOT_HAPPEN();
	}
	os() << defineExternalEntityCode << entity->name()
		<< space << typeString
		<< space << notation->name()
		<< nl;
	attributes(entity->attributes(), dataAttributeCode, &entity->name());
}

void SgmlsEventHandler::defineSubdocEntity(const SubdocEntity *entity)
{
	externalId(entity->externalId());
	os() << defineSubdocEntityCode << entity->name() << nl;
}

void SgmlsEventHandler::defineExternalTextEntity(const ExternalEntity *entity)
{
	externalId(entity->externalId());
	os() << defineExternalTextEntityCode << entity->name() << nl;
}

void SgmlsEventHandler::defineInternalEntity(const InternalEntity *entity)
{
	os() << defineInternalEntityCode << entity->name() << space;
	const char *s;
	switch (entity->dataType()) {
	case Entity::sdata:
		s = "SDATA";
		break;
	case Entity::cdata:
		s = "CDATA";
		break;
	case Entity::sgmlText:
		s = "TEXT";
		break;
	case Entity::pi:
		s = "PI";
		break;
	default:
		CANNOT_HAPPEN();
	}
	os() << s << space;
	outputString(entity->string());
	os() << nl;
}

void SgmlsEventHandler::defineNotation(const Notation *notation)
{
	if (markNotation(notation))
		return;
	externalId(notation->externalId(), outputNotationSysid_);
	os() << defineNotationCode << notation->name() << nl;
}

void SgmlsEventHandler::externalId(const ExternalId &id, Boolean outputFile)
{
	const StringC *str = id.publicIdString();
	if (str) {
		os() << pubidCode;
		outputString(*str);
		os() << nl;
	}
	str = id.systemIdString();
	if (str) {
		os() << sysidCode;
		outputString(*str);
		os() << nl;
	}
	if (outputFile && id.effectiveSystemId().size()) {
		os() << fileCode;
		outputString(id.effectiveSystemId());
		os() << nl;
	}
}

Boolean SgmlsEventHandler::markEntity(const Entity *entity)
{
	return (definedEntities_.add(entity->name()));
}

Boolean SgmlsEventHandler::markNotation(const Notation *notation)
{
	return (definedNotations_.add(notation->name()));
}

void SgmlsEventHandler::outputString(const Char *p, size_t n)
{
	for (; n > 0; p++, n--) {
		switch (*p) {
		case '\\':
			// FIXME we're punning Chars and chars
			os() << "\\\\";
			break;
		case re:
			os() << "\\n";
			if (outputLine_ && haveData_)
	lastLineno_++;
			break;
		default:
			// FIXME not clear what to do here
			// given possibility of wide characters
			if (*p < 040) {
	static const char digits[] = "0123456789";
	os() << "\\0" << digits[*p / 8] << digits[*p % 8];
			}
			else
	os().put(*p);
			break;
		}
	}
}

void SgmlsEventHandler::escape(OutputCharStream &s, Char c)
{
	s << "\\#" << (unsigned long)c << ";";
}

void SgmlsEventHandler::outputLocation1(const Location &loc)
{
	const Origin *origin = loc.origin().pointer();
	const InputSourceOrigin *inputSourceOrigin;
	const ExternalInfo *info;
	Index index = loc.index();
	for (;;) {
		if (!origin)
			return;
		inputSourceOrigin = origin->asInputSourceOrigin();
		if (inputSourceOrigin) {
			info = inputSourceOrigin->externalInfo();
			if (info)
	break;
		}
		const Location &loc = origin->parent();
		index = loc.index();
		origin = loc.origin().pointer();
	}
	Offset off = inputSourceOrigin->startOffset(index);
	StorageObjectLocation soLoc;
	if (!ExtendEntityManager::externalize(info, off, soLoc))
		return;
	if (soLoc.lineNumber == (unsigned long)-1)
		return;
	if (soLoc.storageObjectSpec == lastSos_) {
		if (soLoc.lineNumber == lastLineno_)
			return;
		flushData();
		os() << locationCode << soLoc.lineNumber << nl;
		lastLineno_ = soLoc.lineNumber;
	} else {
		flushData();
		os() << locationCode << soLoc.lineNumber << space;
		outputString(soLoc.actualStorageId);
		os() << nl;
		lastLineno_ = soLoc.lineNumber;
		lastSos_ = soLoc.storageObjectSpec;
		lastLoc_ = loc;		// make sure lastSos_ doesn't get freed
	}
}

void SgmlsEventHandler::dispatchMessage(const Message &msg)
{
	if (!cancelled()) {
		noteMessage(msg);
		messenger_->dispatchMessage(msg);
	}
}

void SgmlsEventHandler::initMessage(Message &msg)
{
	msg.loc = currentLocation_;
}

SgmlsSubdocState::SgmlsSubdocState()
: haveLinkProcess_(0), parser_(0)
{
}

SgmlsSubdocState::SgmlsSubdocState(const SgmlParser *parser)
: haveLinkProcess_(0), parser_(parser)
{
}

void SgmlsSubdocState::init(const SgmlParser *parser)
{
	parser_ = parser;
	definedNotations_.clear();
	definedEntities_.clear();
	haveLinkProcess_ = 0;
	linkProcess_.clear();
}

void SgmlsSubdocState::swap(SgmlsSubdocState &to)
{
	{
		const SgmlParser *tem = to.parser_;
		to.parser_ = parser_;
		parser_ = tem;
	}
	{
		Boolean tem = to.haveLinkProcess_;
		to.haveLinkProcess_ = haveLinkProcess_;
		haveLinkProcess_ = tem;
	}
	linkProcess_.swap(to.linkProcess_);
	definedNotations_.swap(to.definedNotations_);
	definedEntities_.swap(to.definedEntities_);
}

#ifdef SP_NAMESPACE
}
#endif
