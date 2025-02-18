import os
import re
import math
import socket
import time
from math import log2
from lib import config

def update_keywords():
	query = "SELECT initial_keywords FROM Clients;"
	initial_results = config.db.execute(query).fetchall()
	query = "SELECT final_keyword FROM Clients;"
	final_results = config.db.execute(query).fetchall()

	with open("./keyword_files/initial_filter_keywords.txt", "w") as initial_keyword_file, \
	open("./keyword_files/final_filter_keywords.txt", "w") as final_keyword_file:
		for value in initial_results:
			for keywords in value:
				keywords = keywords.split(",")
				for keyword in keywords:
					initial_keyword_file.write(keyword + "\n")
		for value in final_results:
			for keywords in value:
				keywords = keywords.split(",")
				for keyword in keywords:
					final_keyword_file.write(keyword + "\n")

def gather_keywords():
	query = "SELECT client_id, initial_keywords FROM Clients;"
	results = config.db.execute(query).fetchall()
	data = []
	for value in results:
		data.append({"id":value[0],
					"keywords":value[1]
			})
	return data

def gather_ids():
	query = "SELECT client_id, final_keyword FROM Clients;"
	results = config.db.execute(query).fetchall()
	data = []
	for value in results:
		data.append({"name":value[1],
					"id":value[0]
			})
	return data

"""
levenshtein(keyword, domain)
Function to determine the levenshtein distance
between our keyword and the associated domain
@param keyword The keyword that we are checking
			   ex: pegasystems, nuharbor, etc.
@param domain The domain that was registered and
			  has been deemed suspicious
return levenshtein The difference between the two
				   words
"""
def levenshtein(keyword, domain):
	if not keyword: return len(domain)
	if not domain: return len(keyword)
	return min(levenshtein(keyword[1:], domain[1:])+(keyword[0] != domain[0]),
				levenshtein(keyword[1:], domain)+1,
				levenshtein(keyword, domain[1:])+1)

"""
reverse_dns(domain)
Function to enrich our dataset by performing socket.gethostbyname
on our domain to reveal the IP address. If this address is not found 
for any reason we return [IP NOT FOUND]
@param domain Domain to be enriched
@return ip address or [IP NOT FOUND]
"""
def reverse_dns(domain):
	try:
		data = socket.gethostbyname(domain)
		ip = repr(data)
		return ip.replace("'", "")
	except:
		return "[IP NOT FOUND]"

"""
add_levenshtein_field(keyword_file_location, db_file_location, output_file_location)
Function to append the levenshtein distance onto each
row in the full database, at this point that will be
the added_entropy.txt file
@param keyword_file_location The location of our final keyword
							 file
@param db_file_location The location of the most recent db file
						in this case it will be added_entropy.txt
@param output_file_location The location of our write file for the 
							updated db: added_levenshtein.txt
"""
def collect_levenshtein_field(domain, keyword_list):
	print("""
			ADDING LENENSHITEIN DISTANCE FIELD
			""")
	for keyword in keyword_list:
		keyword = keyword.replace("\n", "")
		if keyword in domain:
			return levenshtein(keyword, domain.split(".")[0])
	return 0

"""
shannon(word)
Function to determine the shannon entropy of a byte-string
@param word The word which is having its entropy caluclated
@return entropy The entropy of the word sent to the function
"""
def shannon(domain):
	prob = [ float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain)) ]

	entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

	return float(round(entropy, 3))

"""
Both of the functions below are used for running
opensquat for the first and second iteration.
Attempting to turn thiese from bash files into
actual python functions.
"""
def opensquat_first_iteration():
	os.system("./bash_files/./opensquat_first.sh")

def opensquat_second_iteration():
	os.system("./bash_files/./opensquat_second.sh")

