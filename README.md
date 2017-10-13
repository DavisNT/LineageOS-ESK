LineageOS Enthusiast's Security Kitchen
===============
LineageOS Enthusiast's Security Kitchen is a set of scripts for (semi-)automatic merging of Linux/Android kernel fixes into LineageOS repositories.

Copyright (C) 2017 Davis Mosenkovs

## Introduction

Each Android device (to be more precise - each set of devices) use a bit different version/adaption of Linux kernel. 
Most of Linux kernel security issues/vulnerabilities affect Android as well. To protect a device the fix must be merged into source 
repository of the kernel that specific device uses. Aim of **LineageOS Enthusiast's Security Kitchen** is to ease process of detecting which 
repositories need the security (and possibly other) fixes and merging commits into those repositories (as automatically as possible).

**LineageOS Enthusiast's Security Kitchen** gets list of [LineageOS kernel repositories](https://github.com/LineageOS?q=kernel) from 
GitHub, uses a text (space separated CSV) file with regular expressions (to determine whether a security issue has been already fixed 
in specific kernel repository) and information from where to take the fix (upstream repository URL and commit SHA1-s), and automatically 
downloads the repository, merges the fix and uploads it to [LineageOS code review system](https://review.lineageos.org).

For determinating whether a kernel repository already contains fix for specific issue/vulnerability only the checked file is downloaded 
from GitHub (via HTTP request). The determination process is fully automated.

Repository downloading, merging and code review uploading is fully automated (assuming Git can merge the code automatically). 
The file with CVE definitions (CVE number/label, kernel versions, file name to check regular expressions in, regular expressions for 
vulnerable and fixed code versions, upstream repository URL, and SHA1(-s) of commit(s) fixing the issue) is named 
[cve_defs.txt](https://github.com/DavisNT/LineageOS-ESK/blob/master/cve_defs.txt).

## Work In Process

## Notices

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see https://www.gnu.org/licenses/
