from flask import Flask, request, url_for, render_template

app = Flask(__name__)

import sys
import sqlite3

def levenshtein(keyword, domain):
	if not keyword: return len(domain)
	if not domain: return len(keyword)
	return min(levenshtein(keyword[1:], domain[1:])+(keyowrd[0] != domain[0]),
				levenshtein(keyword[1:], domain)+1,
				levenshtein(keyword, domain[1:])+1)

@app.route("/")
def main():
	return render_template("search.html")

@app.route("/domain_report", methods=["POST"])
def domain_form():
	conn = sqlite3.connect("../cybermonitoring.db")
	db = conn.cursor()

	keyword = request.form["value"]
	
	id_tags = ["edu","med","pub","gov", "res", "com", "fin", "sec"]
	
	db_query = ""
	info_query = ""

	client_id = ""
	data = []

	for tag in id_tags:
		if tag == keyword[:3]:
			db_query = "SELECT domain_name, tld, entropy, levenshtein_distance, subdomain_list, create_date, expiry_date, domain_registrar_name, domain_registrar_whois, domain_registrar_url, registrant_name, registrant_company, registrant_country, client_id FROM enriched_data WHERE client_id = '" + keyword +"';"
			info_query = "SELECT client_id, initial_keywords, final_keyword FROM Clients WHERE client_id = '" + keyword + "';"
			data = db.execute(db_query).fetchall()
	if not db_query:
		db_query = "SELECT domain_name, tld, entropy, levenshtein_distance, subdomain_list, create_date, expiry_date, domain_registrar_name, domain_registrar_whois, domain_registrar_url, registrant_name, registrant_company, registrant_country, client_id FROM enriched_data WHERE ',' || keywords || ',' LIKE '%" + keyword + "%';"
		data = db.execute(db_query).fetchall()

	if not data or data == None or not len(data):
		db_query = "SELECT domain_name, tld, entropy, levenshtein_distance, subdomain_list, create_date, expiry_date, domain_registrar_name, domain_registrar_whois, domain_registrar_url, registrant_name, registrant_company, registrant_country, client_id FROM enriched_data WHERE domain_name LIKE '" + keyword + "';"
		data = db.execute(db_query).fetchall()
	
	client_data = db.execute(info_query).fetchone()
	data_list = []
	if client_data:
		data_dict = {"id":client_data[0],
					"initial_keywords":client_data[1],
					"final_keyword":client_data[2]
		}
	else:
		data_dict = {"id":"[UNKNOWN]",
					"initial_keywords":keyword,
					"final_keywords":"[UNKNOWN]"
		}
	data_list.append(data_dict) 
	for row in data:
		data_dict = {"domain":row[0],
					"tld":row[1],
					"entropy":row[2],
					"levenshtein":row[3],
					"subdomains":row[4],
					"create_date":row[5],
					"expiry_date":row[6],
					"domain_registrar_name":row[7],
					"domain_registrar_whois":row[8],
					"domain_registrar_url":row[9],
					"registrant_name":row[10],
					"registrant_company":row[11],
					"registrant_country":row[12],
					"client_id":row[13]
					}
		for value in data_dict:
			if not len(str(data_dict[value])):
				data_dict[value] = "[NO VALUE]"
		data_list.append(data_dict)
	return render_template("report.html", data=data_list)

@app.route("/display_domains", methods=["GET"])
def display_domains():
	conn = sqlite3.connect("../monitoring_system/cybermonitoring.db")
	db = conn.cursor()

	search = "SELECT domain_name FROM enriched_data ORDER BY domain_name DESC;"

	db.execute(search)

	first_list = db.fetchall()

	domain_list = []
	for domain in first_list:
		domain = str(domain).replace("(","").replace(")","")
		domain = domain.replace("'", "")
		domain = domain.replace(",", "")
		domain_list.append(domain)

	return render_template("display_domains.html", domain_list=domain_list)

@app.route("/update_keywords", methods=["GET", "POST"])
def update_keywords():
	if request.method == "GET":
		return render_template("update_keywords.html", data=None)
	if request.method == "POST":
		conn = sqlite3.connect("../monitoring_system/cybermonitoring.db")
		db = conn.cursor()
		
		id_tag = str(request.form["id_tag"])
		initial_keywords = str(request.form["initial_keywords"])
		final_keywords = str(request.form["final_keyword"])

		if len(final_keywords.split(",")) > 1:
			return render_template("update_keywords.html", data="Only One Final Keyword is Allowed for Levenshtein Distance Calculation")

		# Test for update or add
		query = ("SELECT * FROM Clients WHERE client_id = '" + id_tag + "';")
		if len(db.execute(query).fetchall()) == 0:
			query = ("INSERT INTO Clients(client_id, initial_keywords, final_keyword) VALUES ('" + 
																				id_tag + "', '" +
																				initial_keywords + "','" +
																				final_keywords + "');")
			db.execute(query)
			conn.commit()
			return render_template("update_keywords.html", data="Keywords Added to Database")
		query = ("UPDATE Clients SET initial_keywords = '" + initial_keywords + "', final_keyword = '" + final_keywords + "' WHERE client_id = '" + id_tag + "';")
		db.execute(query)
		conn.commit()
		return render_template("update_keywords.html", data="Keywords Updated")
	return "Page Unavailable"

@app.route("/delete_keywords", methods=["GET", "POST"])
def delete_keywords():
	if request.method == "GET":
		return render_template("delete_keywords.html", data=None)
	if request.method == "POST":
		conn = sqlite3.connect("../monitoring_system/cybermonitoring.db")
		db = conn.cursor()

		id_to_remove = request.form['id_tag']

		query = ("DELETE FROM Clients WHERE client_id = '" + id_to_remove + "';")
		db.execute(query)
		conn.commit()
		return render_template("delete_keywords.html", data="Keywords Removed From Database")

@app.route("/display_keywords", methods=["GET"])
def display_keywords():
	conn = sqlite3.connect("../monitoring_system/cybermonitoring.db")
	db = conn.cursor()

	query = "SELECT client_id, initial_keywords, final_keyword FROM Clients;"
	results = db.execute(query).fetchall()
	data = []
	for value in results:
		data.append({"name":value[0],
					"initial_keywords":str(value[1]).split(","),
					"final_keyword":str(value[2]).split(",")
					})
		#print(value[0], file=sys.stdout)
	return render_template("display_keywords.html", data=data)

@app.route("/all_keyword_functions", methods=["GET"])
def keyword_functions():
	conn = sqlite3.connect("../monitoring_system/cybermonitoring.db")
	db = conn.cursor()

	query = "SELECT client_id, initial_keywords, final_keyword FROM Clients;"
	results = db.execute(query).fetchall()
	data = []
	for value in results:
		data.append({"name":value[0],
					"initial_keywords":str(value[1]).split(","),
					"final_keyword":str(value[2]).split(",")
					})
		#print(value[0], file=sys.stdout)
	return render_template("all_keyword_functions.html", data=data)

@app.route("/beginner_guide", methods=["GET"])
def beginners_guide():
	return render_template("/beginner_guide.html")
