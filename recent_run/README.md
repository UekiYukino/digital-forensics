# recent_run
The program will parse data from "NTUSER.DAT" registry hive to retrieve information of recent run applications<br/>

#### Registry Module
In order for the program to run, you will need the Registry module, which could be downloaded from:
https://github.com/williballenthin/python-registry

#### NTUSER.DAT
`NTUSER.DAT` is a registry hives that store information of users' activities on the system. From this file, we could retrieve the __UserAssist__ artifact.<br/>
__UserAssist__ stores information of run programs, including:
+ The last execution time in UTC (in FILETIME format)
+ Execution count
+ Session ID

#### Usage
`python .\recent_run.py`
