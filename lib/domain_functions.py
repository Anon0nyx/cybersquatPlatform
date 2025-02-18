import time
import os
from lib import config

"""
Domain
Object used during the first iteration to easily
collect each suspicious domains associated subdomains
in the form of an Object List which is then written 
into the database file.
"""
class Domain:
	"""
	__init__(self, row_number, domain_name)
	Method which initializes each Domain to collect their subdomains
	@param self Current domain which was deemed suspicious
	@param row_number The row number associated with the 
					  domain in the full-database.csv file
	@param domain_name The domain which is being investigated
	"""
	def __init__(self, domain_name):
		self.domain = domain_name
		self.subdomain_list = []

	"""
	collect_subdomains(self)
	Method used for collecting the subdomains of the
	current domain after the first iteration of 
	opensquat but before the second.
	@param self The current Domain Object
	"""
	def collect_subdomains(self):
		cmd = "touch ./misc_files/subdomains.txt;cd ./sublist3r;python3 sublist3r.py -n -d {} -o ../misc_files/subdomains.txt;cd ../".format(self.domain)
		os.system(cmd)

		self.subdomain_list = [subdomain for subdomain in open("./misc_files/subdomains.txt", "r")]
		os.system("rm ./misc_files/subdomains.txt")

	"""
	show_data_debug(self)
	Method used for debugging during the subdomain portion
	of execution
	@param self The current Domain object
	"""
	def show_data_debug(self):
		print(self.row + ", " + self.domain + "\n" + "Subdomain List: ")
		for domain in self.subdomain_list:
			print(domain)

"""
parse_csv(file_location)
Function used to create the Domain Objects
that are used for subdomain collection between
the first and second iterations
@param file_location The location of our db file which is 
					 being parsed 
"""
def subdomain_enumeration():
	print("""
			PARSING DATABASE & COLLECTING SUBDOMAINS
			""")
	db_rows = config.db.execute("SELECT * FROM first_iteration;").fetchall()
	i = 1
	length = len(db_rows)
	for line in db_rows:
		row = []
		for value in line:
			if "," in str(value):
				value = value.replace(",","")
			row.append(value)
		row = str(row).replace("[", "").replace("]", "")
		row = row.split(",")
		domain = Domain(str(row[0]).replace("'", ""))
		domain.collect_subdomains()
		time.sleep(2)
		subdomain_line = ""
		for value in domain.subdomain_list:
			subdomain_line += (str(value)+"#".rstrip())
		subdomain_line = ",'" + subdomain_line.replace("\n", "") + "'"
		row = str(row).replace("  ", "")
		row = row.replace("(","").replace(")","")
		row = row.replace('"', '')
		row = row.replace("\\n", "")
		row = row.replace("\\", "")
		row = row.replace("[", "")
		row = row.replace("]", "")
		row = row + subdomain_line
		db_cmd = ("INSERT INTO second_iteration VALUES (" + str(row) + ")")
		config.db.execute(db_cmd)
		config.conn.commit()
		if i%5 == 0: 
			print("Progress: %" + str((i/length) * 100))
		i -= -1

"""
create_domain_only_list(file_location)
Function used to pull only the domains from
the full db for the sake of running these domains
through opensquat
@param file_location The location of the db file
@param write_file_location The location of the write file
"""
def create_domain_only_list(file_location, write_file_location):
	print("""
			CREATING DOMAIN ONLY LIST
			""")
	with open(file_location, "r") as read_file, \
		open(write_file_location, "w") as write_file:
		first_line = read_file.readline()
		for line in read_file:
			write_file.write(str(line.replace('"', '').split(",")[1]) + "\n")
