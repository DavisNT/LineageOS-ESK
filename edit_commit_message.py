#!/usr/bin/python2.7

import os
import sys

note = os.environ['ESK_COMMIT_NOTE']

if len(note)<1:
  sys.exit(1)

with open(sys.argv[1], "r+") as f:
  s = f.read()
  if s.find(note) != -1:
    sys.exit(0)
  f.seek(0)
  f.truncate(0)
  f.write(s.replace("\n", "\n\n"+note+"\n", 1))
