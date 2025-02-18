import time
import os
from lib import config

"""
combine_subdomains_and_domains(read_file_location, write_file_location)
Function that combines the domains and subdomains into a single file
for the sake of adding them to the full database
"""
def combine_subdomains_and_domains(write_file_location):
	print("""
			COMBINING SUBDOMAINS AND DOMAINS INTO SINGLE FILE
			""")
	with open(write_file_location, "w") as write_file:
		for row in config.db.execute("SELECT domain_name, subdomain_list FROM second_iteration;"):
			write_file.write(str(row[0]).replace("'","") + "\n" + row[1].replace("#", "\n").replace("'",""))
