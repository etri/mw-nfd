# MW-NFD Build & Configuration Instructions

Please refer the NFD installation guide (docs/INSTALL.rst) for basic installation  procedure.
MW-NFD-specific issues are  described in this document.

## Version 
- MW-NFD 0.7.1

## Supported platforms
MW-NFD has been tested on the following platforms:

- Ubuntu 18.04 (amd64, armhf)

Mac OS shall be supported in the future releases.

## Build Options
MW-NFD keeps NFD's forwarding architecture, but has some additional forwarding enhancement features, such as dual-cs mode and pittoken-hash mode.

### 1) ./waf configure --with-dual-cs      
     : This option can yield higher forwarding performance for Intesest and Data with no CanBePrefix flag
        by introducing exact-matching CS.
     : Use dual Content Store(CS) in LRU-policy -- an exact-matching CS using unordered-set
        for Interests with no CanBePrefix flag, and prefix-matching original CS
        using ordered-set for Interests with CanBePrefix flag.
     : CanBePrefix flag is encoded in PIT token of sending Interest.
     : If receiving Data has {CanBePrefix=0} in PIT token, exact-matching PIT lookup is performed,
        and it is stored in exact-matching CS.
     : If receiving Data has {CanBePrefix=1} in PIT token, all-matching PIT lookup is performaned,
        and it is stored in prefix-matching original CS.

### 2) ./waf configure --with-pittoken-hash  
     : Hash of Interest name is added to the PIT token of sending Interest.
     : Receiving Data with PIT token having name hash do exact-matching PIT lookup insted of all-matching PIT lookup.

### 3) ./waf configure --with-nfd-org-arch   
     : Use NFD's original single-thread archtecture  (no input & forwarding worker threads)
     : This option can be used in systems with limited cpu cores such as Rasberry Pi.

For best performance, enable --with-dual-cs and --with-pittoken-hash, even for nfd-org-orch mode.
```
   ./waf configure --with-dual-cs --with-pittoken-hash   
```
or   
```
   ./waf configure --with-nfd-org-arch --with-dual-cs --with-pittoken-hash
```
## Commands   


The MW-NFD programs are installed in /usr/local/bin and /usr/local/etc/ndn with following command.
```
   sudo ./waf install
```
Following NFD commands are renamed but has same features:   
```
   nfd                     --> mw-nfd
   nfd-start               --> mw-nfd-start
   nfd-stop                --> mw-nfd-stop
   nfd-status              --> mw-nfd-status
   nfd-status-http-server  --> mw-nfd-status-http-server
```
Following NFD commands are not changed :   
``` 
   nfdc, nfd-autoreg, ndn-autoconfig, ndn-autoconfig-server  
```
## Configuration File

The sample configuration file name is changed from nfd.conf.sample to mw-nfd.conf.sample,
which is located in /usr/local/etc/ndn/.
It supports all of NFD configuration syntax as is, and have a new section  named "mw-nfd"
related to MW-NFD features.

Please refer the comments on the sample config file how to configure each parameters.

## Core Allocation 

When a physical port and its input thread core are in the same NUMA node, best performance is expected. 
If all of main forwarding ports are in the same NUMA node, forwarding worker cores  within same NUMA node 
shows better performance. 

Generally, the number of NUMA node is same to the number of CPU in the system. 
Intel Xeon Scalable CPU support SNC(Sub-Numa Clustering) feature which makes single CPU to two NUMA nodes. 
You can check the number of NUMA and cpu cores assigned to each NUMA node with following command in Linux systems: 
```
   lscpu
```
The numa node where a ethernet device [dev-name] is connect to can be identified with following command: 
```
   cat /sys/class/net/[dev-name]/device/numa_node
```



