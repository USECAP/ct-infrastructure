Parameters for analyzer.py
--
```
usage: python analyzer.py [-h] [-l] [-e] [-u] [-r] [-m] [--t T] [--pg PG] [--es ES]

optional arguments:
  -l          write log file
  -e          enable elasticsearch import
  -u          update expired certs
  -r          update revoked certs (takes veeeery long)
  -m          update metadata certs
  --t=T       time interval between refresh in minutes (default 180)
  --pg=PG     postgres database ip (default localhost)
  --es=ES     elasticsearch database ip (default localhost)
```
