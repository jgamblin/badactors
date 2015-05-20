#!/usr/bin/env python
# Name:     twostrikes.py
# Purpose:  Creates a list of BadIP Addresses that are on multiple lists.
# By:       Jerry Gamblin
# Date:     20.05.15
# Modified  20.05.15
# Rev Level 0.5
# -----------------------------------------------

from contextlib import closing
from urllib import urlopen
import os
import re
import time
import sys
import fileinput


def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text

    return '\x1b[%dm%s\x1b[0m' % (color_code, text)


def red(text):
    return color(text, 31)

def blue(text):
    return color(text, 34)
try:
    os.remove('twostrikes.txt')
except OSError:
    pass 

fo = open('twostrikesunclean.txt', 'w+')

print'\n'

urlss = ["http://rules.emergingthreats.net/blockrules/compromised-ips.txt",
         "http://www.blocklist.de/lists/bruteforcelogin.txt",
         "http://dragonresearchgroup.org/insight/sshpwauth.txt",
         "http://dragonresearchgroup.org/insight/vncprobe.txt",
         "http://www.openbl.org/lists/base.txt",
         "http://www.nothink.org/blacklist/blacklist_malware_http.txt",
         "http://www.nothink.org/blacklist/blacklist_ssh_all.txt",
         "http://antispam.imp.ch/spamlist",
         "http://www.dshield.org/ipsascii.html?limit=10000",
         "http://malc0de.com/bl/IP_Blacklist.txt",
         "http://hosts-file.net/rss.asp",
         "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist"] 


for urls in urlss:
        copy = urlopen(urls)
        ips = []
        count = 0
        start = time.time()
        print ('Checking %s') % (urls)

        with closing(copy):
            for text in copy.readlines():
                   text = text.rstrip()
                   regex = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', text)
                   if regex is not None and regex not in ips:
                       ips.append(regex)

            for ip in ips:
                   ipaddress = "".join(ip)
                   if ipaddress is not '':
                    count = count+1
                    #print (ipaddress)
                    fo.write(ipaddress)
                    fo.write("\n")
            fo.write("\n")
        end = time.time()
        elpased = end-start
        print(blue("\t\t Found %s addresses in %.2f seconds.")) %(count,elpased)

fo.close()


print('\nFinding IPs on multiple lists\n')


fo = open('twostrikes.txt', 'w+')
with open('twostrikesunclean.txt') as f:
    seen = set()
    for line in f:
        line_lower = line.lower()
        if line_lower in seen:
            fo.write(line)
        else:
            seen.add(line_lower)

fo.close()

try:
    f = open("twostrikes.txt", "r")

    try:
        lines = f.readlines()
        lines.sort(reverse=True)
        f.close()
        f = open('twostrikes.txt', 'w')
        f.writelines(lines) 
       
    finally:
        f.close()
except IOError:
    pass

with open('twostrikes.txt') as ips:
    ipcount = sum(1 for _ in ips)

print ("\nFound %s IP addresses on more than one list. \n") %ipcount
os.remove("twostrikesunclean.txt")
os.system("open " + "twostrikes.txt")
