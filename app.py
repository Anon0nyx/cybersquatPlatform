#!/usr/bin/python3
import multiprocessing

from lib import config, domain_functions, db_functions, subdomain_functions, extra_functions, nrd_download

# Main serves the purpose of testing the modules created 
def main():
	"""
		INITIALIZE DB
	"""
	print("""
			RUNNING ON """ + str(multiprocessing.cpu_count()) + """ CORES""")	
	db_functions.initialize_db()

	"""
		BEGIN FIRST ITERATION
	"""
	#db_functions.download_list()
	nrd_download.download_list("free")
	#domain_functions.create_domain_only_list("./misc_files/full-database.csv", "./misc_files/domain_list.txt")
	#extra_functions.update_keywords()
	#extra_functions.opensquat_first_iteration()
	#db_functions.pull_proper_rows_first_iteration("./misc_files/full-database.csv", "./misc_files/opensquat_first_iteration.txt")	

	"""
		BEGIN SECOND ITERATION
	"""
	#domain_functions.subdomain_enumeration()	
	#subdomain_functions.combine_subdomains_and_domains("./misc_files/domain_list.txt")
	#extra_functions.opensquat_second_iteration()
	#db_functions.pull_proper_rows_second_iteration("./misc_files/opensquat_second_iteration.txt")


	print("""
			SCAN COMPLETE
			""")

if __name__ == "__main__":
	main()
