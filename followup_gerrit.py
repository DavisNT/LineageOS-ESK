#!/usr/bin/python2.7

#    LineageOS Enthusiast's Security Kitchen
#    Copyright (C) 2017 Davis Mosenkovs
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see https://www.gnu.org/licenses/

import requests
import sys

gerrit_user = subprocess.check_output("git config --global --get review.review.lineageos.org.username", shell=True).strip()
if gerrit_user=="":
  raise EnvironmentError("Git global setting review.review.lineageos.org.username not configured")

openreqstr = requests.get("https://review.lineageos.org/changes/?q=status:open+owner:"+gerrit_user+"&n=1000&o=MESSAGES&o=LABELS").content
assert(openreqstr.startswith(")]}'"))
openreqs = json.loads(openreqstr[4:])

cvereqs = filter(lambda r: 'topic' in r and r['topic'].upper().startswith("CVE-"), openreqs)

print "Number of opened CVE review requests: "+repr(len(cvereqs))
