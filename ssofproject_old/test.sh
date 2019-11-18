#Sample 23 done
#Sample 26 done

#!/bin/sh

dirs=("Tests/public_basic_tests" "Tests/public_advanced_tests")

output=output
for dir in "${dirs[@]}"
do	
	search_dir=${dir}
	for entry in "$search_dir"/*.json
	do 
		if [ ! "${entry#*output}" != "$entry" ]
		then
			echo "$entry"
			python3 bo-analyser.py $entry
			name=$(echo "$entry" | cut -f 1 -d '.')
			name1=$(echo "$name" | cut -d '/' -f 3 )".output.json"
					real_output=$name".output.json"
			value=`python3 Script/test.py $real_output $name1`
			echo $value
		fi
	done
done

rm *.json
