cookbook-rb-firewall CHANGELOG
===============

## 0.4.4

  - nilsver
    - [fca9ba5] remove flush cache

## 0.4.3

  - Juan Soto
    - [45109cc] Apply firewall rule for sFlow port 6343 to IPs from dstAddress match or nodes with flow-sensor role
    - [f382ba1] Add unified method to allow sFlow traffic based on dstAddress match or flow-sensor role

## 0.4.2

  - Pablo Pérez
    - [d1e0860] Only open 514 port in manager if the vault sensor is in the manager and not in proxy or similar
    - [d486bfe] manage open 514 in proxies using udp
    - [0bc7411] Refactor get_ips_allowed_for_syslog_in_proxy to get the info from node data
    - [9b3cb07] Added properties
    - [c374469] Fix to get the proxy info from the node
    - [aba8e32] Add rules only for the vault sensors in the proxy
    - [80300da] added get_ips_allowed_for_syslog_in_proxy method
    - [fe8a161] Dont open syslog por in proxy - public
    - [35e2253] Don't create rules in home zone bc is open
    - [8c0530d] dont open the port 514 to public to all traffic. Should be only with sensors

## 0.4.1

  - ljblancoredborder
    - [9335889] close port 8084

## 0.4.0

  - Miguel Alvarez
    - [3191f85] Add new druid ports

## 0.3.0

  - Daniel Castro
    - [40c5e47] Open port for CEP on public zone

## 0.2.2

  - jnavarrorb
    - [4e88a8a] Add license
    - [2d9184d] Add more validations
    - [5917a2e] Add valid_ip method
    - [b1d1ab9] Add an IPv4 validation method

## 0.2.1

  - Daniel Castro
    - [534b339] Only open 514/udp for manager

## 0.2.0

  - David Vanhoucke
    - [9fa9cda] open port 9092 for intrusion-sensor

## 0.1.3

  - Miguel Alvarez
    - [1d522d5] Add port 80 to firewall (public zone)

## 0.1.2

  - Pablo Pérez
    - [d7ab30b] delete random file
    - [39f0883] deleted unnecesary notifies
    - [f6ae60e] Check if needs to reload or not

## 0.1.1

  - manegron
    - [3aa377e] Merge pull request #4 from redBorder/avoid_reloading_all_time
    - [a0b70bc] Avoid reloading all time

## 0.1.0

  - manegron
    - [530f692] Merge pull request #2 from redBorder/fix_missing_ports
    - [18d94f5] Add missing ports

## 0.0.2

  - Luis Blanco
    - [edc37b1] open rsyslog port
    - [6d82494] remove execution permission. Cookbooks generally don't need it
    - [bb31d1b] fix wrong pkg name
    - [8d29494] cookbook build instructions
  - nilsver
    - [b857350] fix helper file and refactor
    - [7792e08] add workflow

## 0.0.1
- Nils Verschaeve
    - Initial release of firewall cookbook
