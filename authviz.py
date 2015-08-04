#!/usr/bin/python
import argparse
import operator
import re

from datetime import datetime, timedelta
from collections import Counter

import matplotlib.pyplot as plt
import GeoIP
import numpy as np

# GeoIP db
gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)

# Regex to match failed attempts
allowedusers_regex = re.compile('User (\D+) from ([\.|0-9|\D]+) not allowed because not listed in AllowUsers')
invaliduser_regex = re.compile('Invalid user ([\D|0-9]+) from ([\.|0-9]+)')
date_regex = re.compile('\D+ [0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}')

# XXX: Journald support https://tim.siosm.fr/blog/2014/02/24/journald-log-scanner-python/
FILE = '/var/log/auth.log'

parser = argparse.ArgumentParser()
parser.add_argument("--logfile", help="the fullpath and filename to your auth.log file")
parser.add_argument("--country", help="plot login attempts per country", action='store_true')
parser.add_argument("--heatmap", help="show a heatmap of login attempts", action='store_true')
parser.add_argument("--save", help="save result as an image (png)")
args = parser.parse_args()

if args.logfile:
    FILE = args.logfile

class LoginAttempt(object):

    def __init__(self, line, gi):
        self.user, self.ip = self.extract_data(line)
        if self.user or self.ip:
            self.country = gi.country_code_by_addr(self.ip)
            if not self.country: # TODO: Might be a domain
                self.country = 'Unknown'
        date_match = date_regex.search(line)
        # FIXME: the year of the date
        self.date = datetime.strptime(date_match.group(), '%b %d %H:%M:%S')
        self.line = line

    def extract_data(self, line):
        matches = invaliduser_regex.search(line)
        if matches:
            return matches.groups()
        else:
            matches = allowedusers_regex.search(line)
            if matches:
                return matches.groups()
            else: # Unhandled
                return None, None

    def __repr__(self):
        return 'LoginAttempt(%s, %s, %s)' % (self.user, self.ip, self.date)

data = []
for line in open(FILE).readlines():
    line = line.rstrip()
    if 'Invalid user' in line or 'not allowed because not listed' in line:
        data.append(LoginAttempt(line, gi))

if args.country:
    countries = Counter()
    for d in data:
        countries[d.country] += 1

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

elif args.heatmap:
    # Matplotlib heatmap borrowed from
    # http://www.bertplot.com/visualization/?p=292
    logins = Counter()

    cur_date = data[0].date
    next_date = cur_date + timedelta(days=1)
    prev_hour = cur_date.hour

    heatmap_dict = {}
    for d in data:
        if d.date > next_date:
            # FIXME: we are skipping the initial date here.
            heatmap_dict[d.date.day] = logins
            logins = Counter()
            next_date = d.date + timedelta(days=1)
        else:
            logins[d.date.hour] += 1

    matrix = [[] for i in range(0,25)]
    for i, sublist in enumerate(matrix):
        for j in heatmap_dict.keys():
            sublist.append(heatmap_dict[j][i])

    fig, ax = plt.subplots()
    plot = ax.pcolor(np.array(matrix), cmap=plt.cm.Reds,edgecolors='k')

    ax.set_xticks(np.arange(0, len(heatmap_dict.keys())) + 0.5)
    ax.set_yticks(np.arange(0,25) + 0.5)
    ax.xaxis.tick_top()
    ax.yaxis.tick_left()
    columns = list(heatmap_dict.keys())
    rows = list(range(0,25))
    ax.set_xticklabels(columns,minor=False,fontsize=20)
    ax.set_yticklabels(rows,minor=False,fontsize=20)

    plt.text(0.5,1.08,'SSH failed login attempt heatmap',
        fontsize=20,
        horizontalalignment='center',
        transform=ax.transAxes
    )
    plt.colorbar(plot)

    # standard axis elements
    plt.ylabel('Hour',fontsize=20)
    plt.xlabel('Day',fontsize=20)
    if args.save:
        plt.savefig(args.save)
    else:
        plt.show()
