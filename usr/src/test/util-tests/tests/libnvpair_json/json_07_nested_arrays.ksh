#!/bin/ksh

DIR=$(dirname $(whence $0))
. ${DIR}/json_common

BASELINE="$(cat <<EOF
{\
"event_store":{\
"name":"Occurences",\
"events":[\
{"time":489715200,"desc":"inception"},\
{"time":1057708800,"desc":"maturation"},\
{"time":1344816000,"desc":"migration"},\
{"time":1405296000,"desc":"integration"},\
{}\
]\
},\
"first level":[\
{"second_level_0":[{\
"sl0_a":true,\
"sl0_b":"aaaa"\
},\
{"x":1234}\
],\
"second_level_1":[{}],\
"second_level_2":[\
{"alpha":"a"},\
{"beta":"b"},\
{"gamma":"c"},\
{"delta":"d"},\
{"order":["a","b","c","d"]}\
]\
}\
]\
}
EOF)"

OUTPUT="$(${DIR}/../../bin/print_json <<'EOF'
add_object "event_store";
	add_string "name" "Occurences";
	add_object_array "events";
		add_uint32 "time" "489715200";
		add_string "desc" "inception";
		next;

		add_uint32 "time" "1057708800";
		add_string "desc" "maturation";
		next;

		add_uint32 "time" "1344816000";
		add_string "desc" "migration";
		next;

		add_uint32 "time" "1405296000";
		add_string "desc" "integration";
		next;
	end;
end;
add_object_array "first level";
	add_object_array "second_level_0";
		add_boolean "sl0_a";
		add_string "sl0_b" "aaaa";
		next;
		add_int32 "x" "1234";
	end;
	add_object_array "second_level_1";
	end;
	add_object_array "second_level_2";
		add_string "alpha" "a";
		next;
		add_string "beta" "b";
		next;
		add_string "gamma" "c";
		next;
		add_string "delta" "d";
		next;
		add_string_array "order" "a" "b" "c" "d";
	end;
end;
EOF)"

complete
