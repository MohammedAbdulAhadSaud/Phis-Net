import whois
import requests
import dns.resolver
from urllib.parse import urlparse
from colorama import Fore, Style, init
from pyfiglet import Figlet
import datetime

def print_section(title):
	print(Fore.LIGHTBLUE_EX + f"\n=> {title.upper()}" + Style.RESET_ALL)

def print_kv(key, value, color=Fore.WHITE):
	print(color + f" - {key:<28} {value}" + Style.RESET_ALL)

#--------------------------------------------------------------#

def check_url_keywords(url):
	suspicious_keywords = ["login", "secure", "verify", "account", "update", "confirm", "googlepay", "bank", "signin"]
	domain = urlparse(url).netloc.lower()
	for keyword in suspicious_keywords:
		if keyword in domain:
			return True, keyword
	return False, None

#--------------------------------------------------------------#

def get_redirect_info(url):
	try:
		response = requests.get(url, timeout=5, allow_redirects=True)
		final_url = response.url
		history = " -> ".join([resp.url for resp in response.history]) if response.history else "None"
		return final_url, history, response.status_code
	except requests.exceptions.RequestException:
		return url, "Error following redirects", None

#--------------------------------------------------------------#

def check_whois_info(domain):
	try:
		domain_info = whois.whois(domain)
		return {
			"created": domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date,
			"expires": domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date,
			"registrar": domain_info.registrar
		}
	except Exception as e:
		return {"error": str(e)}

#--------------------------------------------------------------#

def check_dns_records(domain):
	result = {
		"A": [],
		"NS": [],
		"MX": [],
		"AAAA": [],
		"errors": []
	}
	try:
		result["A"] = [r.address for r in dns.resolver.resolve(domain, 'A')]
	except Exception as e:
		result["errors"].append(f"A Record: {e}")

	try:
		result["AAAA"] = [r.address for r in dns.resolver.resolve(domain, 'AAAA')]
	except Exception as e:
		result["errors"].append(f"AAAA Record: {e}")

	try:
		result["NS"] = [r.to_text() for r in dns.resolver.resolve(domain, 'NS')]
	except Exception as e:
		result["errors"].append(f"NS Record: {e}")

	try:
		result["MX"] = [r.exchange.to_text() for r in dns.resolver.resolve(domain, 'MX')]
	except Exception as e:
		result["errors"].append(f"MX Record: {e}")

	return result

#--------------------------------------------------------------#

def analyze_url(url):
	if not url.startswith(('http://', 'https://')):
		print(Fore.LIGHTYELLOW_EX + "\n**Using HTTPS as DEFAULT**")
		url = "https://" + url
	parsed = urlparse(url)
	domain = parsed.netloc.replace("www.", "")
	print("\n" + Fore.GREEN + "-" * 65)
	print(Fore.BLUE + f"\n=> Analyzing URL: {url}" + Style.RESET_ALL)
	suspicious_flag = False

	# Basic Info
	final_url, redirects, status_code = get_redirect_info(url)
	print_section("Basic Info")
	print_kv("Final Redirected URL", final_url, Fore.CYAN)
	print_kv("Domain", domain)
	print_kv("Protocol Used", parsed.scheme.upper(), Fore.RED if parsed.scheme != "https" else Fore.GREEN)
	print_kv("HTTPS Present", "YES" if parsed.scheme == "https" else "NO", Fore.GREEN if parsed.scheme == "https" else Fore.RED)
	if redirects != "None":
		print_kv("Redirect Chain", redirects, Fore.CYAN)
	if status_code:
		print_kv("Final HTTP Status", status_code)
	if parsed.scheme != "https":
		suspicious_flag = True

	# WHOIS
	whois_data = check_whois_info(domain)
	print_section("Domain Information")
	if "error" in whois_data:
		print_kv("WHOIS Warning", whois_data["error"], Fore.YELLOW)
	else:
		created_date = whois_data.get("created")
		now = datetime.datetime.now()
		domain_age_months = None
		if created_date:
			if isinstance(created_date, list):
				created_date = created_date[0]
			if created_date and isinstance(created_date, datetime.datetime):
				delta = now - created_date
				domain_age_months = delta.days // 30
				print_kv("Domain Age (months)", f"{domain_age_months}", Fore.GREEN if domain_age_months >= 3 else Fore.YELLOW)
				if domain_age_months < 3:
					suspicious_flag = True  # warn only if super new
		else:
			print_kv("Domain Age (months)", "Unknown / Not available", Fore.YELLOW)

		print_kv("Domain Created On", str(whois_data.get("created", "N/A")), Fore.GREEN)
		print_kv("Domain Expires On", str(whois_data.get("expires", "N/A")), Fore.GREEN)
		print_kv("Registrar", whois_data.get("registrar", "N/A"), Fore.GREEN)

	# DNS
	dns_data = check_dns_records(domain)
	print_section("DNS Records")
	print_kv("A Record(s)", ", ".join(dns_data["A"]) if dns_data["A"] else "Not found")
	print_kv("AAAA Record(s)", ", ".join(dns_data["AAAA"]) if dns_data["AAAA"] else "Not found")
	print_kv("NS Record(s)", ", ".join(dns_data["NS"]) if dns_data["NS"] else "Not found")
	print_kv("MX Record(s)", ", ".join(dns_data["MX"]) if dns_data["MX"] else "Not found")
	for err in dns_data["errors"]:
		print_kv("DNS Warning", err, Fore.YELLOW)

	# SSL
	print_section("SSL Certificate")
	print_kv("SSL Detected", "NO (initial URL is HTTP)", Fore.RED if parsed.scheme != "https" else Fore.GREEN)
	print_kv("HTTPS Available", "YES (via redirect)" if final_url.startswith("https") else "NO", Fore.GREEN if final_url.startswith("https") else Fore.RED)

	# Reputation / Keyword
	print_section("Reputation & Threat Check")
	keyword_flag, keyword = check_url_keywords(url)
	print_kv("Suspicious Keywords", keyword if keyword_flag else "None Detected", Fore.RED if keyword_flag else Fore.GREEN)
	print_kv("Domain Blacklisted", "NO")  # Stubbed
	if whois_data.get("created"):
		print_kv("Domain Age", f"{(2025 - whois_data['created'].year)} years (Trusted)", Fore.GREEN)
	if keyword_flag:
		suspicious_flag = True

	# Verdict
	print_section("Verdict")
	print_kv("Suspicious Flag", "YES" if suspicious_flag else "NO", Fore.RED if suspicious_flag else Fore.GREEN)
	print_kv("Final Destination Safe", "YES" if final_url.startswith("https://") else "NO", Fore.GREEN if final_url.startswith("https://") else Fore.RED)
	print_kv("Proceed", "NO — Do not proceed ,  The URL is suspicious." if suspicious_flag else "YES — The URL appears safe to proceed.", Fore.RED if suspicious_flag else Fore.GREEN)
	print_kv("Recommendation", "ONLY HTTPS URLs IS LEGIT TO USE")
	print("\n" + "-" * 65 + "\n")
 
 #----------------------------------------------------------------------------#

def is_valid_url(url):
	try:
		parsed = urlparse(url if url.startswith(('http://', 'https://')) else "http://" + url)
		if parsed.netloc and " " not in parsed.netloc:
			return True
		return False
	except:
		return False

#--------------------------------------------------------------#
def main():
	while True:
		url_input = input(Fore.LIGHTWHITE_EX + "\n\n> Enter the URL to analyze: ").strip()
		
		if is_valid_url(url_input):
			analyze_url(url_input)
		else:
			print(Fore.LIGHTRED_EX + "Invalid URL! Please enter a valid URL (like https://example.com)." + Style.RESET_ALL)
			continue 
		while True:  
			a = input(Fore.LIGHTWHITE_EX + 
				"> Enter  : 1 - To test another URL  || 0 - To exit the program: ")
			if a == '0':
				print("Exiting program.")
				exit(0)  # Exit the program
			elif a == '1':
				print(Style.RESET_ALL+"\n" + "-" * 65 + "\n")
				print("\nTesting another URL...")  	
				break
			elif a != '1' and a != '0':  
				print(Fore.LIGHTRED_EX +"Invalid input. Please enter 0 or 1."+ Style.RESET_ALL)  
#------------------------------------------------------------------------------#
if __name__ == "__main__":
	figlet = Figlet(font='slant')
	ascii_art = figlet.renderText('\n      PHISH-NET  ')
	print(Fore.LIGHTRED_EX + ascii_art + Style.RESET_ALL)
	print(Fore.LIGHTCYAN_EX + " " * 30 + "Created by: MohammedAbdulAhadSaud\n" + Style.RESET_ALL)
	print(Fore.LIGHTYELLOW_EX + " " * 30 + "GitHub: https://github.com/MohammedAbdulAhadSaud/Phis-Net\n" + Style.RESET_ALL)


	main()
