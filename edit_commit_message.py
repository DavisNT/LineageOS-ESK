#!/usr/bin/python2.7

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
