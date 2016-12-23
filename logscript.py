#!/usr/bin/env python3

import re, os, geoip, collections

def get_country(ip):
    country = geoip.country(ip.strip())
    if len(country) == 0:
        return "Private Address"
    return country

def init():
    rgxip = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    countries = {}
    hits = {}
    activities = {}

    # note that log file has multiple IP addresses within 
    # a single line, some addresses are proxy address
    with open("CTF1.log") as infile:
        for line in infile:

            # assuming all ip addresses are legitimate
            # where the 4 sections do not surpass 255
            data = re.findall(rgxip, line)

            try:
                host = data[1]

                if host not in hits:
                    countries[host] = get_country(host)
                    hits[host] = 1
                    activities.setdefault(host, [])
                    
                else:
                    hits[host] += 1

                # append all activities done by current 
                # unique IP address
                activities[host].append(line)

            except Exception:
                continue

    return countries, hits, activities

def detection():
    rgxsqli = re.compile('(SELECT|UNION|INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)', re.IGNORECASE)
    rgxincl = re.compile('(https\?|ftp\:|php\:|data\:|\\passwd|system32)', re.IGNORECASE)
    rgxsh = re.compile('OPTIONS|GET.*\s80\s')

    for infile in os.listdir('.'):
        if infile.startswith("activity"):
            with open(infile) as datafile:
                for line in datafile:
                    """
                    https://www.sans.org/reading-room/whitepapers/logging/detecting-attacks-web-applications-log-files-2074
                    detect sql injections & file inclusion in found entries (activities of IP)
                    """
                    # SQL injection detection (going by sql keywords)
                    for sqli in re.findall(rgxsqli, line):
                        with open("report_sqli.txt", "+a") as outfile:
                            print("File IP: " + infile[9:] + " -> " + line, file = outfile)

                    # check for file inclusions
                    for incl in re.findall(rgxincl, line):
                        with open("report_inclusion.txt", "+a") as outfile:
                            print("File IP: " + infile[9:] + " -> " + line, file = outfile)

                    """
                    http://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/
                    detect web shells in found entries (activities of IP)
                    """
                    # check for web shells
                    for shget in re.findall(rgxsh, line):
                        with open("report_shells.txt", "+a") as outfile:
                            print("File IP: " + infile[9:] + " -> " + line, file = outfile)

def results(w, x, y):
    with open("unique_ip.txt", "w") as outfile:
        print("\n".join(w), file = outfile)
    
    with open("unique_ip_country_count.txt", "w") as outfile:
        for ip in w:
            print(ip + ",\t" + w[ip] + ",\t" + str(x[ip]), file = outfile)

    for ip in w:
        for activity in y[ip]:
            with open("activity_" + ip + ".txt", "a+") as outfile:
                print(activity, file = outfile)

if __name__=='__main__':
    country, hit, activity = init()
    print("Data Loaded ...")
    results(country, hit, activity)
    print("Processing Done ...")
    detection()
    print("File Reports Done ...")
    
