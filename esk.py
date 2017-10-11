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
import shutil

MAX_CACHE_SECONDS = 60*60*24*14
BASEDIR = os.path.dirname(os.path.abspath(__file__))
READY_UPSTREAMS = list()

class colors:
  BLUE = '\033[94m'
  GREEN = '\033[92m'
  YELLOW = '\033[93m'
  RED = '\033[91m'
  ENDC = '\033[0m'

def getReposAndBranches():
  if os.path.isfile(absPathTo("repos.cache")) and time.time()-os.path.getmtime(absPathTo("repos.cache"))<MAX_CACHE_SECONDS:
    with open(absPathTo("repos.cache"), "rb") as f:
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

  with open(absPathTo("repos.cache"), "wb") as f:
    f.write(json.dumps(ret))

  return ret

def addReposExtras(repos):
  extras = {}
  with open(absPathTo("repos_extras.txt"), "rb") as f:
    reader = csv.reader(f, delimiter=" ")
    for row in reader:
      if len(row) == 0 or len(row[0]) == 0 or row[0][0] == '#':
        continue
      for r in repos:
        if r['full_name'] == row[0]:
          r['maintainers'] = row[2].replace("OBFusCAAT", "@").split()
          if r['branch'] in row[1].split():
            r['include_branch'] = True

def getSubmitted():
  ret = list()
  if os.path.isfile(absPathTo("submitted.txt")):
    with open(absPathTo("submitted.txt"), "rb") as f:
      reader = csv.reader(f, delimiter=" ")
      for row in reader:
        if len(row) == 0 or len(row[0]) == 0 or row[0][0] == '#':
          continue
        ret.append({'cve': row[0], 'repo': row[1], 'branch': row[2]})
  return ret

def getDefs(file):
  ret = {}
  reader = csv.reader(file, delimiter=" ")
  for row in reader:
    if len(row) == 0 or len(row[0]) == 0 or row[0][0] == '#':
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
    if VERBOSE:
      print repo['full_name']+" ("+repo['branch']+": "+repo['kernel_version']+"): "+repo['cve_status']
  return ret

def absPathTo(file):
  return os.path.join(BASEDIR, file)

def prepareRepo(repo, workdir, upstream):
  if not os.path.exists(workdir):
    os.makedirs(workdir)

  upsrem,upspath = getCachedUpstream(upstream, workdir)
  if upsrem == False:
    print "Error caching upstream "+upstream
    return False

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

  remotes = subprocess.check_output("git remote -v", shell=True)
  if remotes.find(upsrem) == -1:
    print "Adding cached Git upstream "+upsrem+" ("+upstream+")..."
    if subprocess.call("git remote add "+upsrem+" "+upspath, shell=True) != 0:
      return False

  print "Fetching Git repo "+repo['name']+"..."
  if subprocess.call("git fetch origin", shell=True) != 0:
    return False
  print "Fetching cached Git upstream "+upsrem+" ("+upstream+")... This might take a while..."
  if subprocess.call("git fetch --quiet "+upsrem, shell=True) != 0:
    return False

  return True

def getCachedUpstream(upstream, workdir):
  global READY_UPSTREAMS
  alias = "ESK"+hashlib.sha1(upstream).hexdigest()
  cachepath = os.path.join(workdir, "upstreams", alias)

  if READY_UPSTREAMS.count(alias) == 0:
    print "Preparing Git mirror "+alias+" for "+upstream+"..."
    if not os.path.exists(cachepath):
      os.chdir(workdir)
      if os.getcwd() != workdir:
        return False,False
      os.makedirs(cachepath)
      print "Cloning upstream Git repo "+upstream+"..."
      if subprocess.call("git clone --mirror "+upstream+" "+cachepath, shell=True) != 0:
        return False,False
    else:
      os.chdir(cachepath)
      if os.getcwd() != cachepath:
        return False,False
      print "Fetching upstream Git repo "+upstream+"..."
      if subprocess.call("git fetch -p origin", shell=True) != 0:
        return False,False

    READY_UPSTREAMS.append(alias)
  return alias,cachepath

def autocleanRepo(index, repos, workdir):
  if (index+1 == len(repos) or repos[i]['full_name'] != repos[i+1]['full_name']) and os.path.exists(os.path.join(workdir, repos[i]['name'])):
    print "Deleting "+repos[i]['name']+" from disk..."
    os.chdir(workdir)
    if os.getcwd() != workdir:
      raise EnvironmentError("Cannot change directory to: "+workdir)
    shutil.rmtree(repos[i]['name'])

def patchRepo(repo, upstream, cve, commits, gerrit_user, dryrun):
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
    if not dryrun:
      if subprocess.call("git push ssh://"+gerrit_user+"@review.lineageos.org:29418/"+repo['full_name']+".git HEAD:refs/for/"+repo['branch']+"%topic="+cve+reviewers, shell=True) != 0:
        return False
    else:
      print colors.YELLOW+"DRYRUN! Nothing will be sent to Gerrit, submitted.txt not updated."+colors.ENDC

  if not dryrun:
    with open(absPathTo("submitted.txt"), "ab") as f:
      writer = csv.writer(f, delimiter=" ", lineterminator=os.linesep, quoting=csv.QUOTE_MINIMAL)
      writer.writerow([cve, repo['full_name'], repo['branch']])
  else:
    print "Deleting branch "+cve+"-"+repo['branch']+"..."
    if subprocess.call("git checkout "+repo['branch'], shell=True) != 0:
      return False
    if subprocess.call("git branch -D "+cve+"-"+repo['branch'], shell=True) != 0:
      return False

  return True

def updateReviewers():
  print colors.BLUE+"Update reviewers from Gerrit."+colors.ENDC
  print ""
  print "Getting/reading repos and branches list..."
  reposAll = getReposAndBranches()
  repos = [g.next() for k,g in itertools.groupby(reposAll, lambda r: r['full_name'])]
  print "Querying recent approvers in Gerrit... This might take a while..."
  for r in repos:
    chngreq = requests.get("https://review.lineageos.org/changes/?q=status:merged+project:"+r['full_name']+"&n=20&o=MESSAGES&o=LABELS").content
    assert(chngreq.startswith(")]}'"))
    chngs = json.loads(chngreq[4:])
    mids = set()
    for c in chngs:
      for m in c['messages']:
        if 'tag' in m and m['tag'] == "autogenerated:gerrit:merged":
          mids.add(m['author']['_account_id'])
      if 'Code-Review' in c['labels'] and 'approved' in c['labels']['Code-Review']:
        mids.add(c['labels']['Code-Review']['approved']['_account_id'])
    r['maintainers'] = list()
    for mid in mids:
      mreq = requests.get("https://review.lineageos.org/accounts/"+repr(mid)).content
      assert(mreq.startswith(")]}'"))
      m = json.loads(mreq[4:])
      r['maintainers'].append(m['email'].encode('ascii','ignore'))
    r['maintainers'].sort()
    sys.stdout.write('.')
    sys.stdout.flush()

  print ""
  print "Merging and updating file..."
  rows = list()
  with open(absPathTo("repos_extras.txt"), "rb") as f:
    reader = csv.reader(f, delimiter=" ")
    for row in reader:
      rows.append(row)
  for r in repos:
    if len(r['maintainers']) > 0:
      edited = False
      for row in rows:
        if len(row) == 0 or len(row[0]) == 0 or row[0][0] == '#':
          continue
        if r['full_name'] == row[0]:
          edited = True
          mset = set(row[2].replace("OBFusCAAT", "@").split())
          mset.update(set(r['maintainers']))
          row[2] = " ".join(sorted(list(mset))).replace("@", "OBFusCAAT")
      if not edited:
        rows.append([r['full_name'], "", " ".join(r['maintainers']).replace("@", "OBFusCAAT")])
  with open(absPathTo("repos_extras.txt"), "wb") as f:
    writer = csv.writer(f, delimiter=" ", lineterminator=os.linesep, quoting=csv.QUOTE_MINIMAL)
    for row in rows:
      writer.writerow(row)

  print colors.GREEN+"Done."+colors.ENDC
  sys.exit(0)


# Main entry point - parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('--fix', action='store_true', help='Submit fix(es) for vulnerable repositories')
parser.add_argument('--defs', type=argparse.FileType('r'), default='cve_defs.txt', help='File with CVE definitions (default cve_defs.txt).')
parser.add_argument('--workdir', default='repos', help='Directory to clone Git repositories into. Must NOT be shared with Android build dir.')
parser.add_argument('--branches', default='cm-14.1 lineage-15.0', help='Branches to process (in addition to branches specified in repos_extras.txt).')
parser.add_argument('--update-reviewers', action='store_true', help='Add recent reviewers/approvers from Gerrit to reviewers in repos_extras.txt. Skips CVE processing.')
parser.add_argument('--dryrun', action='store_true', help='Do NOT submit changes to Gerrit (and no updates to submitted.txt). Useful for testing how CVE definitions merge.')
parser.add_argument('--verbose', action='store_true', help='Verbose output (in some places).')
parser.add_argument('--autoclean', action='store_true', help='Delete downloaded repositories after submitting changes. Vulnerable repos will be downloaded multiple times (once per CVE). Cached upstream repos will not be deleted. Useful for patching single CVE with limited diskspace.')

args = parser.parse_args()
branches = list(args.branches.split())
VERBOSE = args.verbose

# Call update reviewers
if args.update_reviewers:
  updateReviewers()

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
  if args.fix or args.dryrun:
    gerrit_user = subprocess.check_output("git config --global --get review.review.lineageos.org.username", shell=True).strip()
    workdir = os.path.abspath(args.workdir)
    for i,r in enumerate(reposToProcess):
      if submitted.count({'cve': cve, 'repo': r['full_name'], 'branch': r['branch']}) > 0:
        print colors.YELLOW+"Already submitted "+cve+" for "+r['full_name']+" ("+r['branch']+")..."+colors.ENDC
        continue
      print colors.BLUE+"Fixing "+cve+" for "+r['full_name']+" ("+r['branch']+")..."+colors.ENDC
      for d in defs:
        if d['versions'].count(r['kernel_version']) == 0:
          continue
        if not prepareRepo(r, workdir, d['upstream']):
          print colors.RED+"FAILURE!!! Skipping "+r['full_name']+" for "+cve+colors.ENDC
          continue
        print "Repository prepared."
        if not patchRepo(r, d['upstream'], cve, d['commits'], gerrit_user, args.dryrun):
          print colors.RED+"FAILURE!!! Skipping "+r['full_name']+" for "+cve+colors.ENDC
          continue
        print colors.GREEN+"Submitted "+cve+" fix for "+r['full_name']+" ("+r['branch']+")..."+colors.ENDC
      if args.autoclean:
        autocleanRepo(i, reposToProcess, workdir)

