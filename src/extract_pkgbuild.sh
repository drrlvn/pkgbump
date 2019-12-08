#!/usr/bin/bash

. /usr/share/makepkg/util.sh
. /usr/share/makepkg/integrity.sh

known_hash_algos=('md5' 'sha1' 'sha224' 'sha256' 'sha384' 'sha512')

. /dev/stdin
echo -n '{"sources":['
comma=false
for source in "${source[@]}"; do
    if [[ $comma == "true" ]]; then
        echo -n ','
    fi
    comma=true
    echo -n "{\"filename\":\"$(get_filename "$source")\",\"url\":\"$(get_url "$source")\"}"
done

echo -n '],"hashes":['
comma=false
for integ in $(get_integlist); do
    if [[ $comma == "true" ]]; then
        echo -n ','
    fi
    comma=true
    echo -n "\"$integ\""
done
echo ']}'
