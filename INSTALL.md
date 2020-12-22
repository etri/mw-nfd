# MW-NFD Installation Instructions

## Supported platforms
MW-NFD is built against a continuous integration system and has been tested on the following platforms:


- Ubuntu 16.04 (amd64, armhf)

- Ubuntu 18.04 (amd64)

## Prerequisites

- The [ndn-cxx library(=0.7.0)](https://github.com/named-data/ndn-cxx/archive/ndn-cxx-0.7.0.zip) and its dependencies  
Refer to Getting started with [ndn-cxx](https://named-data.net/doc/ndn-cxx/current/INSTALL.html) for detailed installation and running instruction.

- Fast C++ logging library  
Download the spdlog library and build it according to the instructions available at https://github.com/gabime/spdlog

On Unbuntu, NFD needs the following dependencies to enable optional features:   

**sudo apt install libpcap-dev libsystemd-dev**

## Build

The following commands can be used to build and install MW-NFD from source:  
./waf configure --without-websocket  
./waf  
sudo ./waf install  

The MW-NFD programs are installed in /usr/local/bin. The MW-NFD configuration file is in /usr/local/etc/ndn.

## Customizing the compiler

To build MW-NFD with a different compiler (rather than the platform default), set the **CXX** environment variable to point to the compiler binary. For example, to build with clang on Linux, use the following:

CXX=clang++ ./waf configure  

## Initial configuration  

After installing MW-NFD from source, you need to create a proper configuration file. If the default installation directories were used with ./waf configure, this can be accomplished by simply copying the sample configuration file as follows:  

**sudo cp /usr/local/etc/ndn/mw-nfd.conf.sample /usr/local/etc/ndn/mw-nfd.conf**


## Starting MW-NFD

Open a new terminal window (so you can watch the NFD messages) and enter:  
**mw-nfd-start**

Later, you can stop MW-NFD with **mw-nfd-stop**.
