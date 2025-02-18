import zipfile
import time
import requests
import io
import multiprocessing
import csv
import difflib

from datetime import date, timedelta

from lib import extra_functions, config

from multiprocessing import Pool

"""
add_row_to_db(domain)
Function that is ran parallel for the sake of computation time
and adds the enriched row to the database
@param domain The domain that is being added to the database
"""
def add_row_to_db(domain):
	existing_keywords = extra_functions.gather_keywords()

	client_id_list = extra_functions.gather_ids() 

	keyword_list = [keyword.replace("", "") for keyword in open("./keyword_files/final_filter_keywords.txt", "r")]
	keywords = ""
	key_list = []
	for key_dict in existing_keywords:
		for keyword in str(key_dict['keywords']).split(","):
			key_list.append(keyword)
			if keyword in domain or domain in keyword:
				keywords = key_dict['keywords']
	
	if keywords == "":		
		key = difflib.get_close_matches(domain, key_list)
		key = str(key[0])
		for key_dict in existing_keywords:
			for keyword in str(key_dict['keywords']).split(","):
				if key in keyword or keyword in key:
					keywords = key_dict['keywords']


	row_id = ""
	for client_id_dict in client_id_list:
		if client_id_dict['name'] in domain:
			row_id = client_id_dict['id']

	if len(domain.split(".")) == 2:
		search = "SELECT * FROM second_iteration WHERE domain_name = '{}'".format(domain)
	if len(domain.split(".")) == 3:
		domain = str(domain.split(".")[1]) + "." + str(domain.split(".")[2])
		search = "SELECT * FROM enriched_data WHERE domain_name = '{}'".format(domain)
		config.db.execute(search)
		if config.db.fetchone() != None or config.db.fetchone() != "":
			search = "NULL"
		else:
			search = "SELECT * FROM second_iteration WHERE domain_name = '{}'".format(domain)
	if search != "NULL":
		config.db.execute(search)
		line = config.db.fetchone()
	
		entropy = str(extra_functions.shannon(str(line[0])))
		levenshtein = str(extra_functions.collect_levenshtein_field(str(line[0]), keyword_list))
		tld = str("." + str(line[0]).split(".")[1])
		ip_addr = str(extra_functions.reverse_dns(domain))
		
		line = list(line)
		query = str("INSERT OR REPLACE INTO enriched_data VALUES ('")
		for value in line:
			query += (str(value) + "','")
		query += (str(entropy) + "','")
		query += (str(levenshtein) + "','")
		query += (str(ip_addr) + "','")
		query += (str(tld) + "','")
		query += (str(keywords) + "','")
		query += (str(row_id) + "');")
		print("""
			WRITING ROW TO DATABASE
			""")
		config.db.execute(query)
		time.sleep(3)
		config.conn.commit()
	
"""
pull_proper_rows_second_iteration(domain_file)
Function used to pull the subdomain enumerated rows from the second iteration table 
and adds necessary rows to the enriched_data table with additional information
@param domain_file File with the list of suspicious domains
"""
def pull_proper_rows_second_iteration(domain_file):
	print("""
			PULLING ROWS FOR SECOND OPENSQUAT ITERATION
			""")
	
	domains = [domain.rstrip() for domain in open(domain_file, "r")]

	max_proc = multiprocessing.cpu_count()
	with Pool(max_proc) as p:
		p.map(add_row_to_db, domains)

"""
pull_proper_rows_from_db(db_file_location, domain_file_location, write_file_location)
Function to pull rows from the database file.
The proper row will be dependent upon a domain
that is deemed potentially suspicious during either
the first or second iteration.
@param db_file_location The location of full-database.csv
@param domain_file_location File containing only domains that are deemed 
							potentially suspicious
@param write_file_location File that will be written to. It will contain
							all of the information provided by the full-database.csv 
							file
"""
def pull_proper_rows_first_iteration(db_file_location, domain_file_location):
	print("""
			PULLING FULL ROWS FROM DB
			""")

	domains = [domain.rstrip() for domain in open(domain_file_location, "r")]

	with open("./misc_files/cleaned_database.csv", "w") as cleaned_file, \
	open(db_file_location, "r") as db_file:
		for line in db_file:
			line = str(line).replace("'","")
			cleaned_file.write(line)
	
	#O(n^2) :(((
	for line in csv.reader(open("./misc_files/cleaned_database.csv", "r"), delimiter=","):
		for domain in domains:
			if domain == str(line[1]).replace('"',''):
				db_line = ("INSERT INTO first_iteration VALUES ('" + line[1] + "','" +
																line[2] + "','" +
																line[3] + "','" +
																line[4] + "','" +
																line[5] + "','" +
																line[6] + "','" +
																line[7] + "','" +
																line[8] + "','" +
																line[9] + "','" +
																line[10] + "','" +
																line[11] + "','" +
																line[12] + "','" +
																line[13] + "','" +
																line[14] + "','" +
																line[15] + "','" +
																line[16] + "','" +
																line[17] + "','" +
																line[18] + "','" +
																line[19] + "','" +
																line[20] + "','" +
																line[21] + "','" +
																line[22] + "','" +
																line[23] + "','" +
																line[24] + "','" +
																line[25] + "','" +
																line[26] + "','" +
																line[27] + "','" +
																line[28] + "','" +
																line[29] + "','" +
																line[30] + "','" +
																line[31] + "','" +
																line[32] + "','" +
																line[33] + "','" +
																line[34] + "','" +
																line[35] + "','" +
																line[36] + "','" +
																line[37] + "','" +
																line[38] + "','" +
																line[39] + "','" +
																line[40] + "','" +
																line[41] + "','" +
																line[42] + "','" +
																line[43] + "','" +
																line[44] + "','" +
																line[45] + "','" +
																line[46] + "','" +
																line[48] + "','" +
																line[49] + "','" +
																line[50] + "','" +
																line[51] + "','" +
																line[52] + "','" +
																line[53] + "','" +
																line[54] + "','" +
																line[55] + "','" +
																line[56] + "','" +
																line[57] + "');")
				config.db.execute(db_line)
				config.conn.commit()
	time.sleep(2)

"""
initialize_db()
Function used to initialize the cybermonitoring Database by clearing the 
first and second iteration tables for efficiency.
"""
def initialize_db():
	#Clear the iteration tables to keep them clean
	config.db.execute("DELETE FROM first_iteration;")
	config.db.execute("DELETE FROM second_iteration;")
	config.conn.commit()

"""
get_yesterdays_date()
Function to get the previous days date. This 
is necessary when forming the URL to download
the full-database.csv as this URL requires the
date
@return date previous days date in the proper form
"""
def get_yesterdays_date():
	return (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")

"""
download_list()
Function to download the full-database.csv file
This is the file that contains all of the newly-registered
Domains in the previous day. The database contains additional
Information about each domain
"""
def download_list():
	print("""
			DOWNLOADING FULL-DATABASE.CSV
			""")
	date = get_yesterdays_date()
	creds = str(open("./creds.txt").readline()).split(",")
	user = str(creds[0])
	passw = str(creds[1]).strip("\n")
	data_type = "fldb"

	url = "https://www.whoisds.com/your-download/direct-download-file/" + user + "/" + passw + "/" + date + ".zip/" + data_type + "/home"

	zipped_daily_list = requests.post(url)
	
	zipped_list = zipfile.ZipFile(io.BytesIO(zipped_daily_list.content))
	try:
		zipped_list.extractall("/home/ubuntu/cybermonitoring/monitoring_system/misc_files/")
	except:
		print("DIRECTORY NOT FOUND OR FILE DOWNLOAD FAILURE")
	time.sleep(5)
