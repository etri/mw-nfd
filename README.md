# MW-NFD( Multi-Worker NFD ): An NFD-compatible High-speed NDN Forwarder

## Overview
The Multi-Worker NFD (MW-NFD) is an NFD-compatible NDN forwarder with parallel forwarding capability on multi-core CPUs.
The NFD (NDN Forwarding Daemon) is a default forwarder in most NDN researches,  but dosen't fully utilze the multi-core power of
modern CPU because  of its single-thread forwarding scheme. 
We extend NFD to have parallel forwarding workers which keeps the NFD's forwading plane architecture.  

MW-NFD consists of multiple input threads, multiple forwarding worker threads, a management thread and a Routing Information Base (RIB) manager thread. It is based on NFD v0.7.0, and RIB manager thread is the same as in NFD. Though all threads can be assigned to single core, it is recommended to allocate each input and forwarding worker thread to different cores to achieve higher performance.  


**The key design goals** of MW-NFD is to provide the following principles:  
&nbsp;&nbsp;&nbsp;&nbsp;(1) high-speed forwarding,  
&nbsp;&nbsp;&nbsp;&nbsp;(2) full compatibility with NFD and existing NDN applications, and  
&nbsp;&nbsp;&nbsp;&nbsp;(3) maintaining NFD’s forwarding plane architecture to inherit its advantages of modularity and extensibility.

The detailed architecture and its forwarding performance results can be found in the paper ["MW-NFD (Multi-Worker NFD): An NFD-compatible High-speed NDN Forwarder"](https://dl.acm.org/doi/10.1145/3405656.3420233), ACM ICN 2020. 

## Credits  
MW-NFD is designed and developed by:   

- Sung Hyuk Byun (shbyun@etri.re.kr)
- Jong Seok Lee (viper@etri.re.kr) 
- Dong Myung Sul (dmsul@etri.re.kr) 


This work is one of research results of the project "Hyper-connected Intelligent Infrastructure Technology Development" conducted by ETRI, Korea. The  project leaders are:  

- Namseok Ko (nsko@etri.re.kr)
- Sun Me Kim (kimsunme@etri.re.kr) 

