#! /bin/bash

psql --username postgres -c "DROP DATABASE certwatch;"
psql --username postgres -c "CREATE DATABASE certwatch;"
psql --username postgres -d certwatch -f /python_monitor_schema.sql