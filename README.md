# CyberSquat Monitoring System
## Download List
The first thing the system does is ingest a csv file of all newly-registered-domains for the previous day

## First Iteration
With this list of domains the system uses an initial keyword list to determine what domains may be suspicious. After the suspicious domains are collected, additional information is collected as well, including all subdomains, using Sublist3r, and the full-database.csv rows will be stored in a sqlite3 database in a table called first_iteration.

## Second Iteration
Once the first iteration is done, the all collected domains are sent through OpenSquat again with a different, more specific, wordlist to help determine suspicious domains. The results for this are stored in the same DB as before in a separate table called second_iteration

## Enrichment Phase
After the second iteration is finished and the list is relatively small and filtered the system moved onto enriching the data in the database in a third table called enriched_data. Some current enriched fields are the entropy, levenshtein distance, ip address, tld. Will be looking to add more in the future by request.

# Recommended Project Setup
Install python3 virtual env:
~~~
python3 -m venv /path/to/project/env
~~~
Activate Virtual Environment:
~~~
source /path/to/venv/bin/activate
~~~
Download Project Dependencies to venv:
~~~
python3 -m pip install -r requirements.txt
~~~
Deactivate venv:
~~~
deactivate
~~~
