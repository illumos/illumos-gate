# : : generated from ksh-regress.rt by mktest : : #

# regression tests for --regress enabled ksh

UNIT ksh-regress

EXPORT HOME=. ENV=.env.sh LC_ALL=C HISTFILE=''

TEST 01 'mode suid/sgid combinations'

	EXEC	--regress=etc=. --regress=source
		INPUT - 'set --state'
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --noprivileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --noprivileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --noprivileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --noprivileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --noprivileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --noprivileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --privileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --privileged
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --privileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --privileged --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --privileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --privileged --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --privileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --privileged --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nologin
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --noprivileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --noprivileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --noprivileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --noprivileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nologin --noprivileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nologin --noprivileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nologin --privileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --privileged
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nologin --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nologin --privileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --privileged --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nologin --privileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --privileged --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nologin --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nologin --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nologin --privileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --privileged --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nologin --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nologin --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nologin --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --login
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --noprivileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --noprivileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --noprivileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --noprivileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --noprivileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --noprivileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --privileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --privileged
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --privileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --privileged --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --privileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --privileged --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --privileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --privileged --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --login --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --login --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --noprivileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --noprivileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --noprivileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --noprivileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --noprivileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --noprivileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --privileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --privileged
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --privileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --privileged --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --privileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --privileged --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --privileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --privileged --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --noprivileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --noprivileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --noprivileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --noprivileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --noprivileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --noprivileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --privileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --privileged
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --privileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --privileged --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --privileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --privileged --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --privileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --privileged --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --nologin --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --nologin --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid'

	EXEC	--regress=etc=. --regress=source --nointeractive --login
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --noprivileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --noprivileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --noprivileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --noprivileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --noprivileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --noprivileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --privileged
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --privileged
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --privileged --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --privileged --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --privileged --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --privileged --norc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --privileged --norc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --privileged --norc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --privileged --norc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --privileged --rc
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --privileged --rc
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --privileged --rc --norestricted
		OUTPUT - 'set --default --braceexpand --privileged --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --nointeractive --login --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --nointeractive --login --privileged --rc --restricted
		OUTPUT - 'set --default --braceexpand --privileged --restricted --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --nointeractive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --nointeractive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --nointeractive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --nointeractive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --nointeractive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --nointeractive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --nointeractive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --nointeractive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT'

	EXEC	--regress=etc=. --regress=source --interactive
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --noprivileged
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --noprivileged --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --noprivileged --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --interactive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --interactive --noprivileged --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --interactive --noprivileged --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --noprivileged --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --privileged
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --privileged
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --privileged --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --privileged --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --privileged --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --privileged --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --privileged --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --privileged --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --privileged --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --privileged --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --privileged --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --privileged --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --privileged --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --privileged --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --privileged --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --privileged --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --privileged --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --privileged --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --noprivileged
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --noprivileged --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --noprivileged --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --noprivileged --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --noprivileged --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --noprivileged --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --privileged
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --privileged
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --privileged --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --privileged --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --privileged --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --privileged --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --privileged --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --privileged --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --privileged --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --privileged --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --privileged --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --privileged --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --privileged --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --privileged --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --privileged --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --privileged --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --nologin --privileged --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.\nksh:REGRESS:source:__regress__:on\n'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --nologin --privileged --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --nologin --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --noprivileged
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --noprivileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --noprivileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --noprivileged --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --noprivileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --noprivileged --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --noprivileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --noprivileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --noprivileged --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --noprivileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --noprivileged --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --noprivileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --noprivileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --noprivileged --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:0
ksh:REGRESS:egid:setgid:egid==rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --noprivileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:p_suid:SHOPT_P_SUID:99999
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:source:sh_source:./.profile:ENOENT
ksh:REGRESS:source:sh_source:.profile:ENOENT
ksh:REGRESS:source:sh_source:.env.sh:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --privileged
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --privileged
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --privileged
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --privileged --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --privileged --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --privileged --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --privileged --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --privileged --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --privileged --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --privileged --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --privileged --norc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --privileged --norc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --privileged --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --privileged --norc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --privileged --norc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --privileged --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --privileged --norc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --privileged --norc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --privileged --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --privileged --rc
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --privileged --rc
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --privileged --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --privileged --rc --norestricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --privileged --rc --norestricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --interactive --login --privileged --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --restricted --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --interactive --login --privileged --rc --restricted
		OUTPUT - 'set --default --bgnice --braceexpand --monitor --privileged --restricted --v'\
'i --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=0 --interactive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=0 --regress=p_suid=99999 --interactive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:0
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --interactive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=0 --interactive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=euid=1 --regress=p_suid=99999 --interactive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --interactive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=0 --interactive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:0
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

	EXEC	--regress=etc=. --regress=source --regress=egid=1 --regress=p_suid=99999 --interactive --login --privileged --rc --restricted
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:source:__regress__:on
ksh:REGRESS:egid:__regress__:1
ksh:REGRESS:p_suid:__regress__:99999
ksh:REGRESS:egid:getegid:egid!=rgid
ksh:REGRESS:etc:sh_open:/etc/profile => ./profile
ksh:REGRESS:source:sh_source:/etc/profile:ENOENT
ksh:REGRESS:etc:sh_open:/etc/suid_profile => ./suid_profile
ksh:REGRESS:source:sh_source:/etc/suid_profile:ENOENT
'

TEST 02 'privileged/noprivileged sequence'

	EXEC	--regress=etc=. --regress=euid=1 --privileged
		INPUT - 'set --state; set --noprivileged; set --state; set --privileged; set --state;'\
' set --noprivileged; set --state'
		OUTPUT - $'set --default --braceexpand --privileged --trackall --vi --viraw
set --default --braceexpand --trackall --vi --viraw
set --default --braceexpand --privileged --trackall --vi --viraw
set --default --braceexpand --trackall --vi --viraw'
		ERROR - $'ksh:REGRESS:etc:__regress__:.
ksh:REGRESS:euid:__regress__:1
ksh:REGRESS:euid:geteuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid
ksh:REGRESS:euid:setuid:euid!=ruid
ksh:REGRESS:euid:setuid:euid==ruid'
