/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 1994, 1995 James Clark
 * See the file COPYING for copying permission.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "config.h"
#include "Event.h"
#include "MessageEventHandler.h"
#include "SgmlsEventHandler.h"
#include "RastEventHandler.h"
#include "OutputCharStream.h"
#include "Boolean.h"
#include "NsgmlsMessages.h"
#include "MessageArg.h"
#include "ErrnoMessageArg.h"
#include "ParserApp.h"
#include "sptchar.h"
#include "macros.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#ifdef __GNUC__
using namespace std;
#endif

class NsgmlsApp : public ParserApp {
public:
	NsgmlsApp();
	int processArguments(int argc, AppChar **argv);
	ErrorCountEventHandler *makeEventHandler();
	void processOption(AppChar opt, const AppChar *arg);
	void allLinkTypesActivated();
private:
	Boolean suppressOutput_;
	Boolean prologOnly_;
	unsigned outputFlags_;
	String < AppChar > rastFile_;
	const AppChar *rastOption_;
	Boolean batchMode_;
};

SP_DEFINE_APP(NsgmlsApp)

class PrologMessageEventHandler : public MessageEventHandler {
public:
	PrologMessageEventHandler(Messenger *messenger);
	void endProlog(EndPrologEvent *);
};

class XRastEventHandler : public RastEventHandler {
public:
	XRastEventHandler(SgmlParser *,
				const NsgmlsApp::AppChar *filename,
				const StringC &filenameStr,
				const OutputCodingSystem *,
				CmdLineApp *,
				Messenger *messenger);
	~XRastEventHandler();
	void message(MessageEvent *);
	void truncateOutput();
	void allLinkTypesActivated();
private:
	Messenger *messenger_;
	// file_ must come before os_ so it gets inited first
	FileOutputByteStream file_;
	EncodeOutputCharStream os_;
	const NsgmlsApp::AppChar *filename_;
	const StringC filenameStr_;
	CmdLineApp *app_;
};

NsgmlsApp::NsgmlsApp()
: suppressOutput_(0),
	batchMode_(0),
	prologOnly_(0),
	outputFlags_(0),
	rastOption_(0)
{
	registerOption('B');
	registerOption('d');
	registerOption('l');
	registerOption('m', SP_T("catalog_sysid"));
	registerOption('o', SP_T("output_option"));
	registerOption('p');
	registerOption('r');
	registerOption('s');
	registerOption('t', SP_T("rast_file"));
	registerOption('u');
}

void NsgmlsApp::processOption(AppChar opt, const AppChar *arg)
{
	switch (opt) {
	case 'B':
		batchMode_ = 1;
		break;
	case 'd':
		// warn about duplicate entity declarations
		options_.warnDuplicateEntity = 1;
		break;
	case 'l':
		// output L commands
		outputFlags_ |= SgmlsEventHandler::outputLine;
		break;
	case 'm':
		processOption(SP_T('c'), arg);
		break;
	case 'o':
		{
			static struct {
	// Qualifier works around CodeWarrior bug
	const CmdLineApp::AppChar *name;
	unsigned flag;
			} outputOptions[] = {
	{ SP_T("line"), SgmlsEventHandler::outputLine },
	{ SP_T("entity"), SgmlsEventHandler::outputEntity },
	{ SP_T("id"), SgmlsEventHandler::outputId },
	{ SP_T("included"), SgmlsEventHandler::outputIncluded },
	{ SP_T("notation-sysid"), SgmlsEventHandler::outputNotationSysid },
	{ SP_T("nonsgml"), SgmlsEventHandler::outputNonSgml },
	{ SP_T("empty"), SgmlsEventHandler::outputEmpty },
			};
			Boolean found = 0;
			for (size_t i = 0; i < SIZEOF(outputOptions); i++)
	if (tcscmp(arg, outputOptions[i].name) == 0) {
		outputFlags_ |= outputOptions[i].flag;
		found = 1;
		break;
	}
			if (!found)
	message(NsgmlsMessages::unknownOutputOption,
		StringMessageArg(convertInput(arg)));
		}
		break;
	case 'p':
		prologOnly_ = 1;
		break;
	case 'r':
		// warn about defaulted entity reference
		options_.warnDefaultEntityReference = 1;
		break;
	case 's':
		suppressOutput_ = 1;
		break;
	case 't':
		rastOption_ = arg;
		break;
	case 'u':
		// warn about undefined elements
		options_.warnUndefinedElement = 1;
		break;
	default:
		ParserApp::processOption(opt, arg);
		break;
	}
}

int NsgmlsApp::processArguments(int argc, AppChar **argv)
{
	if (batchMode_) {
		int ret = 0;
		for (int i = 0; i < argc; i++) {
			if (rastOption_) {
	rastFile_.assign(rastOption_, tcslen(rastOption_));
	rastFile_.append(argv[i], tcslen(argv[i]));
	rastFile_ += SP_T('\0');
			}
			int tem = ParserApp::processArguments(1, argv + i);
			if (tem > ret)
	ret = tem;
		}
		return (ret);
	}
	else
		return (ParserApp::processArguments(argc, argv));
}

void NsgmlsApp::allLinkTypesActivated()
{
	if (!rastOption_)
		ParserApp::allLinkTypesActivated();
}

ErrorCountEventHandler *NsgmlsApp::makeEventHandler()
{
	if (prologOnly_)
		return (new PrologMessageEventHandler(this));
	else if (rastOption_) {
		const AppChar *s = batchMode_ ? rastFile_.data() : rastOption_;
		return (new XRastEventHandler(&parser_, s, convertInput(s),
			outputCodingSystem_, this, this));
	} else if (suppressOutput_)
		return (new MessageEventHandler(this, &parser_));
	else
		return (new SgmlsEventHandler(&parser_,
			makeStdOut(),
			this,
			outputFlags_));
}

PrologMessageEventHandler::PrologMessageEventHandler(Messenger *messenger)
: MessageEventHandler(messenger)
{
}

void PrologMessageEventHandler::endProlog(EndPrologEvent *event)
{
	cancel();
	delete event;
}

XRastEventHandler::XRastEventHandler(SgmlParser *parser,
		const NsgmlsApp::AppChar *filename,
		const StringC &filenameStr,
		const OutputCodingSystem *codingSystem,
		CmdLineApp *app,
		Messenger *messenger)
: RastEventHandler(parser, messenger),
	messenger_(messenger),
	filename_(filename),
	filenameStr_(filenameStr),
	app_(app)
{
	errno = 0;
	if (!file_.open(filename)) {
		messenger->message(CmdLineApp::openFileErrorMessage(),
				StringMessageArg(filenameStr),
				ErrnoMessageArg(errno));
		exit(1);
	}
	os_.open(&file_, codingSystem);
	setOutputStream(&os_);
}

XRastEventHandler::~XRastEventHandler()
{
	end();
}

void XRastEventHandler::truncateOutput()
{
	os_.flush();
	errno = 0;
	if (!file_.close())
		messenger_->message(CmdLineApp::closeFileErrorMessage(),
			StringMessageArg(filenameStr_),
			ErrnoMessageArg(errno));
	errno = 0;
	if (!file_.open(filename_)) {
		messenger_->message(CmdLineApp::openFileErrorMessage(),
			StringMessageArg(filenameStr_),
			ErrnoMessageArg(errno));
		exit(1);
	}
}

void XRastEventHandler::message(MessageEvent *event)
{
	messenger_->dispatchMessage(event->message());
	ErrorCountEventHandler::message(event);
}
