#!/bin/bash
rm -rf ./misc_files/opensquat_first_iteration.txt
cd ./opensquat
python3 opensquat.py -d ../misc_files/domain_list.txt -k ../keyword_files/initial_filter_keywords.txt -o ../misc_files/opensquat_first_iteration.txt
cd ../
