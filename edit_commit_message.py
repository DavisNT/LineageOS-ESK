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

import os
import sys

note = os.environ['ESK_COMMIT_NOTE']

if len(note)<1:
  sys.exit(1)

with open(sys.argv[1], "rb+") as f:
  s = f.read()
  if s.find(note) != -1:
    sys.exit(0)
  f.seek(0)
  f.truncate(0)
  f.write(s.replace(os.linesep, os.linesep+os.linesep+note+os.linesep, 1))
