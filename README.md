# MW-NFD( Multi-Worker NFD ): An NFD-compatible High-speed NDN Forwarder

## Overview
The Multi-Worker NFD (MW-NFD) is an NFD-compatible NDN forwarder with parallel forwarding capability on multi-core CPUs.
The NFD (NDN Forwarding Daemon) is a default forwarder in most NDN researches,  but dosen't fully utilze the multi-core power of
modern CPU because  of its single-thread forwarding scheme. 
We extend NFD to have parallel forwarding workers which keeps the NFD's forwading plane architecture.  

MW-NFD can allocate dedicate input thread for each physical port, and multiple forwarding worker cores.
Input threads distribute incoming Interest and Data to one of forwarding worker threads,
determined by hashing the name prefix of pre-configured length (default = 2).
The forwarding worker-id of sending Interest is encoded in the PIT token of NDNLP header.
The forwarding worker of receiving Data with PIT token is determined by the worker-id encoded in the PIT token.
If the Data has no PIT token, its forwarding worker is determined by the hash of name prefix of pre-configured length. 

**The key design goals** of MW-NFD is to provide the following principles:      

- high-speed forwarding,  
- compatibility with NFD and existing NDN applications, and  
- maintaining NFD’s forwarding plane architecture to inherit its advantages of modularity and extensibility.

The detailed architecture and its forwarding performance results can be found in the paper ["MW-NFD (Multi-Worker NFD): An NFD-compatible High-speed NDN Forwarder"](https://dl.acm.org/doi/10.1145/3405656.3420233), ACM ICN 2020. 

## Build and Configuration   
Please refer the MW-NFD-CONFIG.md and the sample configuration file (/usr/local/etc/ndn/mw-nfd.conf.sample).   

## Compatibility 

MW-NFD is based on NFD of same verson number. 
Thus compatibility characteritics of MW-NFD follows that of NFD of same version.
MW-NFD use PIT token for forwarding enhancements, and it is recommended to use PIT token-enabled forwarder (NFD 0.7.0 or higher) in peer nodes.
But MW-NFD also supports remote nodes with no PIT token feature.

MW-NFD support all mamagenemt features with nfdc command, and all face types of NFD,
except NDN-LP Reliability option in point-to-point faces, which will be supported in future release. 


## Forwarding Performances   

Detailed forwarding test method is described in the MW-NFD paper (ICN2020), and test environment is as follows: 

 - Forwarding Server : Dual Xeon Gold 6242 (2.8GHz, 16 core)   
 - Packet generator : proprietary ndn-pktgen based on DPDK pktgen 19.11 
 - Interfaces between packet generator and forwarding server : two 10GE ports 
 - FIB : 10K
 - Interest stream : 10M packets with unique name, no CanBePrefix flag (Data has same name to Interest) 
 - Forwarding Throughput(packet-per-second) : the sum of Interest and Data throughput forwarded by MW-NFD

   
| worker cores          | NFD-ORG-ARCH  | 2     | 4     | 6     | 8     | 10    | 12    | 14    | 16    |
|-----------------------|:-------------:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|
| default               |   62K         | 151K  | 287K  | 424K  | 548K  | 698K  | 742K  | 765K  | 765K  |
| no pittoken-hash      |   61K         | 151K  | 281K  | 393K  | 526K  | 684K  | 729K  | 768K  | 755K  |
| no dual_cs            |   54K         | 108K  | 220K  | 324K  | 440K  | 525K  | 577K  | 701K  | 698K  |  
| no dual-cs & no pittoken-hash | 54K   | 107K  | 213K  | 320K  | 433K  | 521K  | 572K  | 689K  | 680K  |

% "NFG-ORG-ARCH with no dual-cs and no pittoken-hash" is equivalent to NFD 0.7.1.    
% This high performance can only be achieved with many distinct traffic flows. 

## Releases   
MW-NFD version is set to same as the base NFD & ndn-cxx version.

### MW-NFD 0.7.1   (Feb. 19, 2021)  
 - Based on NFD 0.7.1 & ndn-cxx 0.7.1
 - Added Features :
      * Encoding forwarding worker-id to PIT token of sending Interest
      * Dual_CS : adding exact-matching Content Store for Interests with no CanBePrefix flag, in LRU CS-policy
      * PITTOKEN_HASH : PIT exact matching for Data with PIT token having interest name hash
      * NFD_ORG_ARCH : running with NFD's original single-thread architecture

 - Not Supported Yet :
      * NDN-LP Reliability Option on point-to-point Faces
      * Mac OS Platform


## Credits  
MW-NFD is designed and developed by:   

- Sung Hyuk Byun (shbyun@etri.re.kr)
- Jong Seok Lee (viper@etri.re.kr) 
- Dong Myung Sul (dmsul@etri.re.kr) 


This work is one of research results of the project "Hyper-connected Intelligent Infrastructure Technology Development" conducted by ETRI, Korea. The  project leaders are:  

- Namseok Ko (nsko@etri.re.kr)
- Sun Me Kim (kimsunme@etri.re.kr) 

