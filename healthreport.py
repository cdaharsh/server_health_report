#!/usr/bin/env python

import time
import sh
import socket
import re
import sys
import threading


#allows you give the hostname when you're running the script from the command line
#ex. python healthreportv4.py aeyxa.com. If you don't specify the hostname at the
#command line you will be prompeted for it when the script begins to execute.
def get_target():
    if len(sys.argv) == 2:
        return sys.argv[1]
    return raw_input("Enter the hostname: ")

hostname = get_target()

threads = []

def threaded(func):
    def wrapper(*args, **kwargs):
        t = threading.Thread(target=func, args=args, kwargs=kwargs)
        threads.append(t)
        t.start()
    return wrapper

def timed(func):
    def wrapper(*args, **kwargs):
        t1 = time.time()
        x = func(*args, **kwargs)
        t2 = time.time()
        print "Time it took to run the function " + str((t2 - t1)) + "\n"
        return x
    return wrapper

#regular expressions to extract data from whois and curl. regex1 and regex2
#grab lines matching Name Server and Registrar in whois, respectively.
#regex3 grabs lines matching Server. regex4 helps determine if recursion is enabled
regex1 = "Name Server:\s.*"
regex2 = "Registrar[^s].*"
regex3 = "Server:\s.*"
regex4 = "WARNING:\srecursion\srequested\sbut\snot\savailable"

#function that runs curl and uses regex1 and regex2 to find lines matching
#"Name Server: " and "Registar"
@threaded
#@timed
def whois_function(hostname):
    try:
        whois = sh.whois(hostname)
        print"\nwhois lookup successful! Looking for name server and registrar info...\n"
        matches1 = re.findall(regex1, "%s" % whois)
        if matches1:
            print "\n".join(matches1)
        else:
            print "\nunable to find name servers for this host!\n"

        matches2 = re.findall(regex2, "%s" % whois)
        if matches2:
            print "\n".join(matches2)
        else:
            print "\nunable to find registrar information for this host!\n"
    except sh.ErrorReturnCode:
        print "\nwhois did not work for this host!\n"

#function that runs curl and uses regex3 to find lines matching "Server: "
@threaded
#@timed
def curl_function(hostname):
    try:
        curl = sh.curl("-I", hostname)
        print "\ncurl successful! looking for web server information...\n"
        matches3 = re.findall(regex3, "%s" % curl)
        web_server = " ".join(matches3)
        if matches3:
                print web_server
        else:
                print "could not find what type of web server is running!\n"
    except sh.ErrorReturnCode:
        print "\ncurl did not work for this host!\n"

@threaded
#@timed
def ping_function(hostname):
    try:
        ping = sh.ping(hostname, c=4)
        print ping
    except sh.ErrorReturnCode:
        print "\nping did not work for this host!\n"

@threaded
#@timed
def nmap_function(hostname):
    try:
        nmap = sh.nmap("-sT", hostname)
        print nmap
    except sh.ErrorReturnCode:
        print  "\nnmap did not work for this host!\n"

@threaded
#@timed
def dig_function(hostname):
    try:
        dig = sh.dig("+nocmd", "+nocomments", "+nostats", hostname)
        print dig
    except sh.ErrorReturnCode:
        print  "\ndig did not work for this host!\n"

@threaded
#@timed
def recursion_check(hostname):
    try:
        recur = sh.dig("google.com", "@" + hostname)
        matches4 = re.findall(regex4, "%s" % recur)
        if matches4:
            print "\nrecursion disabled on this host!\n"
        else:
            print "\nrecursion enabled on this host!\n"
    except sh.ErrorReturnCode:
        print  "\nrecursion disabled on this host!\n"

#dictionary containing all the ports to evalaute from the successful_ports and
#failed_ports lists
port_dict = {'http':80, 'https':443, 'plesk':8443, 'cpanel':2087,
 'dns':53, 'ftp':21, 'ssh':22, 'rdp':3389, 'mysql':3306, \
 'pop':110, 'popsec':995, 'smtp':25,'smtpsec':465, 'imap':143, 'imapsec':993}

#empty dictionary that will be populated by the check_port function
port_report = {}

#function to allow use of the socket.create_connection and return its results
#to the port_report dictionary
@threaded
def check_port(hostname, ports):
    for port in ports:
        try:
                conn = socket.create_connection( (hostname, port), timeout=3 )
                while True:
                        if conn != 1:
                                success = True
                                break
        except socket.error, exc:
                        success = False
        port_report[ port ] = success

check_port(hostname, port_dict.values())

[x.join() for x in threads]

#function that allows True and False values to be extracted from the port_report
#dictionary so that they're True/False values can be used for "if" statements
def ports(*args):
        """
                given port_report = { 80: True, 443: False}
                ports(80) => [ True ]
                ports(443) => [ False ]
                ports(80, 443) => [ True, False ]
                ports(80, 110) => [ True, None ]
        """
        return [ port in port_report and port_report[port] or None for port in args ]

#successful_ports and failed_ports list comprehensions that generate two seperate
#lists. successful_ports grabs all the ports that evaluate to True, which means
#a connection to that port was able to be established. failed_ports is a list for
#ports where a connection to the port could not be established
successful_ports = [ key for key,value in port_report.items() if value ]
failed_ports = [ key for key,value in port_report.items() if not value ]

#defining variables for the red and green (high intensity!) ANSI  escape codes.
#the end_color variable terminates the escape code for whatever is printed.
#the check_mark variable is the ASCII code for a check mark
#the x_mark variable is the ASCII code for the multiplication sign, which servers
#as an indicator that a port did not connect succesfully
red = "\033[91m"
green = "\033[92m"
end_color = "\033[0m"
check_mark = u"\u2713"
x_mark = u"\u2715"

#loop that looks at the value (True or False) for each key in the dictionary.
#It print the key along with "failed" or "succeeded" based on which list the port
#was in (successful_ports or failed_ports). ex. "http succeeded" if port 80 was
#in the successful_ports list
for k, v in port_dict.iteritems():
    if v in failed_ports:
        print red + k.ljust(10) + x_mark + end_color
    elif v in successful_ports:
        print green + k.ljust(10) + check_mark + end_color

#plesk
if 8443 in successful_ports and 80 in failed_ports:
   print "web Server not available on Plesk Server"

#cpanel
if 2087 in successful_ports and not 80:
    print "\nWeb Server not available on cPanel Server"

#dns
if 53 in failed_ports:
    print "\nDNS is not either not running or port is blocked\
 on this server\nPlease check if DNS is intended\
 to run on this server\n"

#check for recursion if connection to port 53 was successful
if 53 in successful_ports:
    recursion_check(hostname)

#run curl if connection to port 80 was succesful
if 80 in successful_ports:
    curl_function(hostname)

#pop and not smtp
if any ( ports(110, 995) ) and not all ( ports (25, 465) ):
    print "POP is running, but SMTP did not respond\n\
 Check if this server is intended to send mail"

#imap and not smtp
if any ( ports(143, 993) ) and not all ( ports (25, 465) ):
    print "IMAP is running, but SMTP did not respond\n\
  Check if this server is intended to send mail"

#smtp and not pop or imap
if any ( ports(25, 465) ) and not all ( ports (110, 995, 143, 993) ):
    print "SMTP is running, but POP and IMAP did not respond\n\
  Check if this server is intended to receive mail"

#puts all shell functions in a list and executes them in the list comprehension below
shell_functions = [ping_function, nmap_function, dig_function, whois_function]

[f(hostname) for f in shell_functions]
