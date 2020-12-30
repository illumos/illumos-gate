/*
 * regression test support
 *
 * @(#)TEST.mk (AT&T Research) 2010-05-19
 *
 * test management is still in the design phase
 */

/*
 * three forms for :TEST:
 *
 *	:TEST: xxx yyy ...
 *
 *		$(REGRESS) $(REGRESSFLAGS) xxx.tst
 *		$(REGRESS) $(REGRESSFLAGS) yyy.tst
 *
 *	:TEST: xxx.tst yyy ...
 *
 *		$(REGRESS) $(REGRESSFLAGS) xxx.tst yyy ...
 *
 *	:TEST: xxx.c [ :: test-prereq ... :: ] [ args [ : args ... ] ]
 *
 *	:TEST: xxx.sh [ :: test-prereq ... :: ] [ args [ : args ... ] ]
 *
 *	xxx :TEST: prereq ...
 *		[ action ]
 *
 *		$(*) if no action
 */

":TEST:" : .MAKE .OPERATOR
	local B G P S T
	test : .INSERT .TESTINIT
	if "$("tests":T=FD)"
		.SOURCE : tests
	end
	P := $(>:O=1)
	if "$(P:N=*.tst)" && ! "$(@:V)"
		B := $(P:B)
		if ! ( T = "$(<:V)" )
			T := $(B)
		end
		test : - test.$(T)
		eval
			test.$$(T) : $$(B).tst
				$$(REGRESS) $$(REGRESSFLAGS) $$(*) $(>:V:O>1)
			:SAVE: $$(B).tst
		end
	elif "$(P:N=*@(.sh|$(.SUFFIX.c:/ /|/G)|$(.SUFFIX.C:/ /|/G)))"
		B := $(P:B)
		if ! ( T = "$(<:V)" )
			T := $(B)
		end
		:INSTALLDIR: $(B)
		$(B) :: $(P) $(*:-l*|*$(CC.SUFFIX.ARCHIVE))
		if "$(P:N=*.sh)"
			TESTCC == $(CC)
			$(B) : (TESTCC)
		end
		test : - test.$(T)
		if "$(@:V)"
			eval
				test.$$(T) : $$(B) $(>:V:O>1)
					set +x; (ulimit -c 0) >/dev/null 2>&1 && ulimit -c 0; set -x
					$(@:V)
			end
		elif "$(>:V:O>1)"
			local I A V X S R=0
			for A $(>:V:O>1)
				if A == "::"
					let R = !R
				elif A == ":"
					let I = I + 1
					test.$(T).$(I) := $(V:V)
					V =
					X := $(X:V)$(S)$$(*) $$(test.$(T).$(I):T=*)
					S = $("\n")
				elif A != "-l*|*$(CC.SUFFIX.ARCHIVE)"
					if R
						test.$(A) : .VIRTUAL .FORCE
						test.$(T) : test.$(A)
					else
						V += $(A:V)
					end
				end
			end
			if V
				let I = I + 1
				test.$(T).$(I) := $(V:V)
				X := $(X:V)$(S)$$(*) $$(test.$(T).$(I):T=*)
			end
			eval
				test.$$(T) : $$(B)
					set +x; (ulimit -c 0) >/dev/null 2>&1 && ulimit -c 0; set -x
					$(X:V)
			end
		else
			eval
				test.$$(T) : $$(B)
					set +x; (ulimit -c 0) >/dev/null 2>&1 && ulimit -c 0; set -x
					$$(*)
			end
		end
	elif ! "$(<:V)"
		G = 1
		for B $(>)
			if B == "-|--"
				let G = !G
			else
				if ! G
					T =
				elif ! ( T = "$(B:A=.COMMAND)" ) && ! "$(B:A=.TARGET)"
					for S .c .sh
						if "$(B:B:S=$(S):T=F)"
							:INSTALLDIR: $(B)
							$(B) :: $(B:B:S=$(S))
							T := $(B)
							break
						end
					end
				end
				test : - test.$(B)
				test.$(B) : $(T) - $(B).tst
					$(REGRESS) $(REGRESSFLAGS) $(*:N=*.tst) $(*:N!=*.tst)
				:SAVE: $(B).tst
			end
		end
	else
		if "$(>:V)" || "$(@:V)"
			P := $(>)
			T := $(P:O=1)
			B := $(T:B)
			if "$(T)" != "$(B)" && "$(T:G=$(B))"
				:INSTALLDIR: $(B)
				$(B) :: $(T) $(P:O>1:N=-*)
				T := $(B)
				P := $(B) $(P:O>1:N!=-*)
			end
			if "$(<:V)"
				T := $(<:V)
			end
			test : - test.$(T)
			if "$(@:V)"
				eval
				test.$$(T) : $$(P) $(>:V:O>1)
					set +x; (ulimit -c 0) >/dev/null 2>&1 && ulimit -c 0; set -x
					$(@:V)
				end
			else
				test.$(T) : $(P)
					set +x; (ulimit -c 0) >/dev/null 2>&1 && ulimit -c 0; set -x
					$(*)
			end
		else
			test : - test.$(<)
			test.$(<) : $(<).tst $(<:A=.COMMAND)
				$(REGRESS) $(REGRESSFLAGS) $(*)
		end
	end

.TESTINIT : .MAKE .VIRTUAL .FORCE .REPEAT
	if VARIANT == "DLL"
		error 1 :DLL: tests skipped
		exit 0
	end
	set keepgoing
	REGRESSFLAGS &= $(TESTS:@/ /|/G:/.*/--test=&/:@Q)

.SCAN.tst : .SCAN
	$(@.SCAN.sh)
	I| INCLUDE@ % |

.ATTRIBUTE.%.tst : .SCAN.tst

MKTEST = mktest
MKTESTFLAGS = --style=regress

/*
 * test scripts are only regenerated from *.rt when --force
 * is specified or the .rt file is newer than the script
 * otherwise the script is accepted if it exists
 *
 * this avoids the case where a fresh build with no state
 * would regenerate the test script and capture current
 * behavior instead of expected behavior
 */

%.tst : %.rt
	if	[[ "$(-force)" || "$(>)" -nt "$(^|<)" ]]
	then	$(MKTEST) $(MKTESTFLAGS) $(>) > $(<)
	fi

test%.sh test%.out : %.rt
	if	[[ "$(-force)" || "$(>)" -nt "$(^|<:O=1)" ]]
	then	$(MKTEST) --style=shell $(>) > $(<:N=*.sh)
		$(SHELL) $(<:N=*.sh) --accept > $(<:N=*.out)
	fi
