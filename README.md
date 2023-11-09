# CVEAutoMatcher
Metasploit plugin to parse Metasploit DB for CVE numbers and match these with existing exploit and aux modules.

1.1	Setting UP MSFDB

The default Kali instance might not have postgresql by default. The following packages should be installed if postgresql was not installed:

`#sudo apt install postgresql postgresql-contrib -y`

Ensure that the service is started after installation:
```
#sudo systemctl start postgresql
#sudo systemctl enable postgresql
```


Msfdb command which came by default Metasploit installation should be used to initiate and manage the database as shown below:

```
root@kali:~# msfdb init
Creating database user 'msf'
Enter password for new role: 
Enter it again: 
Creating databases 'msf' and 'msf_test'
Creating configuration file in /usr/share/metasploit-framework/config/database.yml
Creating initial database schema
```
1.1	Copying Plugin file to Metasploit

**strike.rb** should be copied under **plugins directory of the metaslpoit installation**. In most cases this directory is under: /usr/share/metasploit/plugins on Kali installations

After successfull connection to metasploit be sure that database is set and nessus results imported

`msf6 > db_stats`

Session Type: Connected to msf. Connection type: postgresql.

Database Stats


      ID     Name     Hosts  Services  Services   Vulnerabil  Vulns per   Notes  Creds  Kerberos C
                                       per Host   ities       Host                      ache
      --     ----     -----  --------  ---------  ----------  ----------  -----  -----  ----------
      1      default  711    1,680     2.36       7,407       10.41       1,449  2      0
      Total  1        711    1,680     2.36       7407        10.41       1449   2      0


`msf6 > load cveautomatcher`

[*] Successfully loaded plugin: CVEAutoMatcher


`msf6 > match_cves`

Matching Modules


   ```
[*] CVE: CVE-2019-4279

Matching Modules
================

   #  Name                                                       Disclosure Date  Rank  Check  Description                                                                     IP Addresses
   -  ----                                                       ---------------  ----  -----  -----------                                                                     ------------
   1  exploit/windows/ibm/ibm_was_dmgr_java_deserialization_rce  2019-05-15       600   No     IBM Websphere Application Server Network Deployment Untrusted Data Deserializa  20.15.66.42 20.15.66.37
                                                                                               tion Remote Code Execution

```
