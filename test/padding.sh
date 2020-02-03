#!/bin/bash
# Test padded lengths

failed=0

for f in ./test/efile*;
do
	padding_len=$(./ft_ssl md5 -s $(cat ${f}) | wc -c);
	isnotok=$(( (padding_len + 64) % 512 ))
	printf "%s: %s\t" "$(basename ${f})" ${padding_len}
	if [ $isnotok -eq 0 ]; then
		echo "OK"
	else
		echo "Fail"
		failed=1
	fi
done
exit $failed
