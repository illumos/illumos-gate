#!/bin/ksh

DIR=$(dirname $(whence $0))
. ${DIR}/json_common

BASELINE="$(cat <<EOF
{\
"a":{},\
"b":{\
"name":"Roger","age":35\
},\
"c":{\
"d":{\
"name":"Stephen","age":27},\
"e":{\
"name":"Roberta","age":43,"pet":{\
"name":"Mister Bumberscratch",\
"species":"cat",\
"alive":true,\
"available_legs":[1,2,3,4]\
}\
}\
}\
}
EOF)"

OUTPUT="$(${DIR}/../../bin/print_json <<'EOF'
add_object "a";
end;

add_object "b";
	add_string "name" "Roger";
	add_uint16 "age" "35";
end;

add_object "c";
	add_object "d";
		add_string "name" "Stephen";
		add_uint16 "age" "27";
	end;
	add_object "e";
		add_string "name" "Roberta";
		add_uint16 "age" "43";
		add_object "pet";
			add_string "name" "Mister Bumberscratch";
			add_string "species" "cat";
			add_boolean_value "alive" "true";
			add_uint8_array "available_legs" "1" "2" "3" "4";
		end;
	end;
end;
EOF)"

complete
