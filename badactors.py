#!/usr/bin/env python
# Name:     badactors
# Purpose:  Creates a list of BadIP Addresses
# By:       Jerry Gamblin
# Date:     16.05.15
# Modified  16.05.15
# Rev Level 0.5
# -----------------------------------------------

from contextlib import closing
from urllib import urlopen
import os
import re
import time
import sys

def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text

    return '\x1b[%dm%s\x1b[0m' % (color_code, text)


def red(text):
    return color(text, 31)

def blue(text):
    return color(text, 34)
try:
    os.remove('badactors.txt')
except OSError:
    pass 

fo = open('badactorsunclean.txt', 'w+')

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


print('\nRemoving duplicates from the list!')

lines_seen = set()  # holds lines already seen
outfile = open("badactors.txt", "w+")
for line in open("badactorsunclean.txt", "r"):
    if line not in lines_seen:  # not a duplicate
        outfile.write(line)
        lines_seen.add(line)
outfile.close()

with open('badactorsunclean.txt') as ucips:
    ucbadips = sum(1 for _ in ucips)

with open('badactors.txt') as ips:
    badips = sum(1 for _ in ips)

dupeips = (ucbadips-badips)

print ("\nFound and removed %s duplicate IP addresses \n") %dupeips

print ('The are %s bad ip addresses in badactors.txt') % badips

os.remove("badactorsunclean.txt")
os.system("open " + "badactors.txt")
