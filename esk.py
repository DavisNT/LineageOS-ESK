#!/usr/bin/python2.7

import requests
import csv
import re
import json
import os
import time
import itertools
import sys
import argparse
import getpass
import time
import subprocess
import hashlib

MAX_CACHE_SECONDS = 60*60*24*14
BASEDIR = os.path.dirname(os.path.abspath(__file__))

class colors:
  BLUE = '\033[94m'
  GREEN = '\033[92m'
  YELLOW = '\033[93m'
  RED = '\033[91m'
  ENDC = '\033[0m'

def getReposAndBranches():
  if os.path.isfile(absPathTo("repos.cache")) and time.time()-os.path.getmtime(absPathTo("repos.cache"))<MAX_CACHE_SECONDS:
    with open(absPathTo("repos.cache"), "r") as f:
      return json.loads(f.read())

  # Prompt for GitHub credentials
  auth = False
  user = raw_input("Enter GitHub username to access LineageOS repos with better ratelimit: ")
  passwd = getpass.getpass("Enter GitHub password: ")
  if user and passwd:
    auth = (user, passwd)

  print "Getting repos, branches and kernel versions from GitHub... This will take several minutes..."

  page = 1
  repos = list()
  kvexp = re.compile("^VERSION\s*=\s*(\d+)\s*$", re.MULTILINE)
  kplexp = re.compile("^PATCHLEVEL\s*=\s*(\d+)\s*$", re.MULTILINE)
  while True:
    s = requests.get("https://api.github.com/search/repositories?q=user:LineageOS+kernel+in:name&per_page=100&page="+repr(page), auth=auth).json()
    repos.extend(s['items'])
    if len(repos) == s['total_count']:
      break
    page = page + 1
  ret = list()
  for repo in repos:
    print "Getting branches and kernel versions for "+repo['full_name']+"..."
    branches = requests.get(repo['branches_url'].replace("{/branch}", "")+"?per_page=100", auth=auth).json()
    for branch in branches:
      mfs = requests.get("https://raw.githubusercontent.com/"+repo['full_name']+"/"+branch['name']+"/Makefile").content
      kvm = kvexp.search(mfs)
      kplm = kplexp.search(mfs)
      kversion = 'UNKNOWN'
      if kvm and kplm:
        kversion = kvm.group(1)+"."+kplm.group(1)
      ret.append({'name': repo['name'], 'full_name': repo['full_name'], 'clone_url': repo['clone_url'], 'branch': branch['name'], 'branch_default': branch['name'] == repo['default_branch'], 'kernel_version': kversion})

  with open(absPathTo("repos.cache"), "w") as f:
    f.write(json.dumps(ret))

  return ret

def addReposExtras(repos):
  extras = {}
  with open(absPathTo("repos_extras.txt"), "r") as f:
    reader = csv.reader(f, delimiter=" ")
    for row in reader:
      if len(row) == 0 or row[0] == '#':
        continue
      for r in repos:
        if r['name'] == row[0]:
          r['maintainers'] = row[2].split()
          if r['branch'] in row[1].split():
            r['include_branch'] = True

def getSubmitted():
  ret = list()
  if os.path.isfile(absPathTo("submitted.txt")):
    with open(absPathTo("submitted.txt"), "r") as f:
      reader = csv.reader(f, delimiter=" ")
      for row in reader:
        if len(row) == 0 or row[0] == '#':
          continue
        ret.append({'cve': row[0], 'repo': row[1], 'branch': row[2]})
  return ret

def getDefs(file):
  ret = {}
  reader = csv.reader(file, delimiter=" ")
  for row in reader:
    if len(row) == 0 or row[0] == '#':
      continue
    if row[0] not in ret:
      ret.update({row[0]: list()})

    blexp = False
    if row[3] != "":
      blexp = re.compile(row[3], re.MULTILINE)
    wlexp = False
    if row[4] != "":
      wlexp = re.compile(row[4], re.MULTILINE)
    if blexp == False and wlexp == False:
      raise ValueError("Blacklist OR whitelist expression MUST be specified!", row)

    ret[row[0]].append({'versions': list(row[1].split()), 'file': row[2], 'blexp': blexp, 'wlexp': wlexp, 'upstream': row[5], 'commits': list(row[6].split())})
  return ret

def determineVulnerableRepos(repos, defs):
  ret = list(repos)
  for repo in ret:
    repo.update({'cve_status': 'UNDETERMINED'})
    for d in defs:
      if d['versions'].count(repo['kernel_version']) == 0:
        continue
      s = requests.get("https://raw.githubusercontent.com/"+repo['full_name']+"/"+repo['branch']+"/"+d['file'])
      if s.status_code != 200:
        continue
      repo.update({'cve_status': 'UNDETERMINED_FILE_PRESENT'})

      blmatch = False
      wlmatch = False
      if d['blexp']:
        blmatch = d['blexp'].search(s.content) != None
      if d['wlexp']:
        wlmatch = d['wlexp'].search(s.content) != None
      if (wlmatch or d['wlexp'] == False) and not blmatch:
        repo.update({'cve_status': 'FIXED'})
      if (blmatch or d['blexp'] == False) and not wlmatch:
        repo.update({'cve_status': 'VULNERABLE'})
        repo.update({'cve_def': d})
        break
    #print repo['full_name']+" ("+repo['branch']+": "+repo['kernel_version']+"): "+repo['cve_status']
  return ret

def absPathTo(file):
  return os.path.join(BASEDIR, file)

def prepareRepo(repo, workdir, upstream):
  if not os.path.exists(workdir):
    os.makedirs(workdir)
  os.chdir(workdir)
  if os.getcwd() != workdir:
    return False

  if not os.path.exists(repo['name']):
    print "Cloning Git repo "+repo['name']+"..."
    if subprocess.call("git clone "+repo['clone_url'], shell=True) != 0:
      return False
  os.chdir(repo['name'])
  if os.getcwd() != os.path.join(workdir, repo['name']):
    return False

  if not os.path.isfile(".git/hooks/commit-msg"):
    print "Installing Git commit-msg hook..."
    chreq = requests.get("https://review.lineageos.org/tools/hooks/commit-msg")
    if chreq.status_code != 200:
      return False
    with open(".git/hooks/commit-msg", "w") as f:
      f.write(chreq.content)
    os.chmod(".git/hooks/commit-msg", int('0775', 8))

  upsrem = "ESK"+hashlib.sha1(upstream).hexdigest()
  remotes = subprocess.check_output("git remote -v", shell=True)
  if remotes.find(upsrem) == -1:
    print "Adding Git upstream "+upsrem+" ("+upstream+")..."
    if subprocess.call("git remote add "+upsrem+" "+upstream, shell=True) != 0:
      return False

  print "Fetching Git repo "+repo['name']+"..."
  if subprocess.call("git fetch origin", shell=True) != 0:
    return False
  print "Fetching Git upstream "+upsrem+" ("+upstream+")... This might take a while..."
  if subprocess.call("git fetch --quiet "+upsrem, shell=True) != 0:
    return False

  return True

def patchRepo(repo, upstream, cve, commits, gerrit_user):
  print "Preparing Gerrit review branch "+cve+"-"+repo['branch']+"..."
  if subprocess.call("git branch "+cve+"-"+repo['branch']+" --track origin/"+repo['branch'], shell=True) != 0:
    return False
  if subprocess.call("git checkout "+cve+"-"+repo['branch'], shell=True) != 0:
    return False

  for commit in commits:
    print "Cherry-picking "+commit+"..."
    if subprocess.call("git cherry-pick "+commit, shell=True) != 0:
      return False
    print "Updating commit message..."
    os.environ['EDITOR'] = absPathTo("edit_commit_message.py")
    os.environ['ESK_COMMIT_NOTE'] = "upstream "+commit+" from\n"+upstream
    status = subprocess.call("git commit --amend", shell=True)
    os.environ['EDITOR'] = "nano"
    os.environ['ESK_COMMIT_NOTE'] = ""
    if status != 0:
      return False
    print "Submitting change to Gerrit..."
    reviewers = ""
    if 'maintainers' in repo:
      for m in repo['maintainers']:
        reviewers = reviewers+",r="+m
    if subprocess.call("git push ssh://"+gerrit_user+"@review.lineageos.org:29418/"+repo['full_name']+".git HEAD:refs/for/"+repo['branch']+"%topic="+cve+reviewers, shell=True) != 0:
      return False

  with open(absPathTo("submitted.txt"), "a") as f:
    writer = csv.writer(f, delimiter=" ", quoting=csv.QUOTE_MINIMAL)
    writer.writerow([cve, repo['full_name'], repo['branch']])

  return True

# Main entry point - parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('--fix', action='store_true', help='Submit fix(es) for vulnerable repositories')
parser.add_argument('--defs', type=argparse.FileType('r'), default='cve_defs.txt', help='File with CVE definitions (default cve_defs.txt).')
parser.add_argument('--workdir', default='repos', help='Directory to clone Git repositories into. Must NOT be shared with Android build dir.')
parser.add_argument('--branches', default='cm-14.1 lineage-15.0', help='Branches to process (in addition to branches specified in repos_extras.txt).')
args = parser.parse_args()
branches = list(args.branches.split())

# Prepare CVE independent data
print "Reading definitions..."
defsAll = getDefs(args.defs)
print "Getting/reading repos and branches list..."
reposAll = getReposAndBranches()
addReposExtras(reposAll)
submitted = getSubmitted()

reposFiltered = filter(lambda r: branches.count(r['branch']) == 1 or 'include_branch' in r, reposAll)

print "Total repos/branches: "+repr(len(reposAll))
print "Repos/branches to be processed: "+repr(len(reposFiltered))
print ""

# Print kernel version stats
print "Kernel version stats:"
kvstats = {}
for r in reposAll:
  if r['kernel_version'] in kvstats:
    kvstats.update({r['kernel_version']: kvstats[r['kernel_version']]+1})
  else:
    kvstats.update({r['kernel_version']: 1})
for i in sorted(kvstats, key=kvstats.get, reverse=True):
  print "Kernel "+i+": "+repr(kvstats[i])
print ""

# Process each CVE from definitions file
for cve, defs in defsAll.iteritems():
  print "Determining vulnerable repos for "+cve+" (branches: "+args.branches+" + per-repo extra branches)... This might take a while..."
  repos = determineVulnerableRepos(reposFiltered, defs)
  reposToProcess = filter(lambda r: r['cve_status'] == 'VULNERABLE', repos)
  print "Vulnerable repos/branches to be patched: "+repr(len(reposToProcess))
  if args.fix:
    gerrit_user = subprocess.check_output("git config --global --get review.review.lineageos.org.username", shell=True).strip()
    workdir = os.path.abspath(args.workdir)
    for r in reposToProcess:
      if submitted.count({'cve': cve, 'repo': r['full_name'], 'branch': r['branch']}) > 0:
        print colors.YELLOW+"Already submitted "+cve+" for "+r['full_name']+" ("+r['branch']+")..."+colors.ENDC
        continue
      print colors.BLUE+"Fixing "+cve+" for "+r['full_name']+" ("+r['branch']+")..."+colors.ENDC
      for d in defs:
        if d['versions'].count(r['kernel_version']) == 0:
          continue
        if not prepareRepo(r, workdir, d['upstream']):
          print colors.RED+"FAILURE!!!"+colors.ENDC+" Skipping "+r['full_name']+" for "+cve
          continue
        print "Repository prepared."
        if not patchRepo(r, d['upstream'], cve, d['commits'], gerrit_user):
          print colors.RED+"FAILURE!!!"+colors.ENDC+" Skipping "+r['full_name']+" for "+cve
          continue
        print colors.GREEN+"Submitted "+cve+" fix for "+r['full_name']+" ("+r['branch']+")..."+colors.ENDC

