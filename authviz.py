#!/usr/bin/python
import argparse
import operator
import re

from collections import Counter

import matplotlib.pyplot as plt
import GeoIP

# Regex to match failed attempts
allowedusers_regex = re.compile('User (\D+) from ([\.|0-9]+) not allowed because not listed in AllowUsers')
invaliduser_regex = re.compile('Invalid user (\D+) from ([\.|0-9]+)')

# XXX: Journald support https://tim.siosm.fr/blog/2014/02/24/journald-log-scanner-python/
FILE = '/var/log/auth.log'

# GeoIP db
gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)

parser = argparse.ArgumentParser()
parser.add_argument("--logfile", help="the fullpath and filename to your auth.log file")
parser.add_argument("--save", help="save result as an image (png)")
args = parser.parse_args()
if args.logfile:
    FILE = args.logfile

countries = Counter()

for line in open(FILE).readlines():
    matches = invaliduser_regex.search(line)
    if matches:
        user, ip = matches.groups()
        country = gi.country_code_by_addr(ip)
        countries[country] += 1
    matches = allowedusers_regex.search(line)
    if matches:
        user, ip = matches.groups()
        country = gi.country_code_by_addr(ip)
        countries[country] += 1

countries = sorted(countries.items(), key=operator.itemgetter(1), reverse=True)
width = 0.3
fig, ax = plt.subplots()
ax.set_title('Number of SSH login attempts per country')
ind = range(0, len(countries))
data = [entry[1] for entry in countries]
ax.set_xticks([offset + width for offset in ind])
rects = ax.bar(ind, data, width, color='r')

# Only show ticks on the left and bottom spines
ax.spines['right'].set_visible(False)
ax.spines['top'].set_visible(False)
ax.yaxis.set_ticks_position('left')
ax.xaxis.set_ticks_position('bottom')

ax.set_xticklabels([entry[0] for entry in countries])
if args.save:
    plt.savefig(args.save)
else:
    plt.show()
