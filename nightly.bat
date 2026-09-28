@echo off
rem Nightly unattended run for Windows Task Scheduler.
rem Adds seeds, scans some Common Crawl index files, then crawls until the time
rem is up. Unfinished sites continue the next night. Output goes to logs\nightly.log.
cd /d "%~dp0"
if not exist logs mkdir logs
target\release\opendir.exe auto --hours 7 >> logs\nightly.log 2>&1
