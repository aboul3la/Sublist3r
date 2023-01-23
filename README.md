# Project Status

Please note I am not actively supporting this project. I may return to subdomain research at some point but my security interests lie elsewhere at the moment and my time is divided among other things. If you find an issue feel free to send a PR or fork it into your own project. Thanks. 

## Turbolist3r

Turbolist3r is a fork of the [sublist3r](https://github.com/aboul3la/sublist3r) subdomain discovery tool. In addition to the original OSINT capabilties of sublist3r, turbolist3r automates some analysis of the results, with a focus on subdomain takeover.

Turbolist3r queries public DNS servers for each discovered subdomain. If the subdomain exists (i.e. the resolver replied with an address), the answer is categorized as CNAME or A record. By examining A records, it is possible to discover potential penetration testing targets for a given domain. Likewise, the process of looking for subdomain takeovers is simple; view the discovered CNAME records and investigate any that point to applicable cloud services.

Please do not use for illegal purposes.

## Screenshots

![Screenshot 1](https://cp270.files.wordpress.com/2019/01/turbo-lister.png)

![Screenshot 2](https://cp270.files.wordpress.com/2018/01/turbo_analysis.png)

## Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-d            | --domain      | Domain name to enumerate subdomains of
-b            | --bruteforce  | Enable the subbrute bruteforce module
-p            | --ports       | Scan the found subdomains against specific tcp ports
-v            | --verbose     | Enable the verbose mode and display results in realtime
-t            | --threads     | Number of threads to use for subbrute bruteforce
-e            | --engines     | Specify a comma-separated list of search engines
-o            | --output      | Save discovered domain names to specified text file
-h            | --help        | show the help message and exit
-a            | --analyze     | Do reverse DNS analysis and output results
(none)        | --saverdns    | Save reverse DNS analysis to specified file
(none)        | --inputfile   | Read domains from specified file, and use them for analysis
(none)        | --debug       | Print debug information during the analysis module (-a). Prints mostly raw DNS data, familarity with the DIG Linux DNS utility and it's output is helpful to interpret the debug output
-r            | --resolvers   | File with DNS servers to populate as resolvers. File must have only one server IP address per line and only IP addresses are accepted
-q            | --quiet       | Only print found domains and/or CNAME mappings. Note errors may be printed as well

### Examples

* To list all the basic options and switches use -h switch:

```python turbolist3r.py -h```

* To enumerate subdomains of a specific domain, perform advanced analysis, and save the analysis to a file:

``python turbolist3r.py -d example.com -a --saverdns analysis_file.txt``

* Read subdomains from a file and perform advanced analysis on them:

``python turbolist3r.py -d example.com -a --inputfile subdomains.txt``

* Using -r to populate DNS resolvers from a file (resolvers used with -a analysis module):

``python turbolist3r.py -d example.com -a --inputfile subdomains.txt -r dns_servers.txt``

* To enumerate subdomains of specific domain:

``python turbolist3r.py -d example.com``

* To enumerate subdomains of specific domain and save discovered subdomains to a file:

``python turbolist3r.py -d example.com -o example_hosts.txt``

* To enumerate subdomains of specific domain and show the results in realtime:

``python turbolist3r.py -v -d example.com``

* To enumerate subdomains and enable the bruteforce module:

``python turbolist3r.py -b -d example.com``

* To enumerate subdomains and use specific engines such Google, Yahoo and Virustotal engines

``python turbolist3r.py -e google,yahoo,virustotal -d example.com``


## Dependencies:
Turbolist3r depends on the `dnslib`, `requests`, and `argparse` python modules. The `subbrute` module is required for bruteforce capability, but Turbolist3r should run without it as long as you don't invoke bruteforce. Submit a PR or contact me if you have issues.

#### dnslib Module

The dnslib module can be downloaded from [https://bitbucket.org/paulc/dnslib/](https://bitbucket.org/paulc/dnslib/) or installed on many systems using:

``pip install dnslib``


#### requests Module

- Install for Ubuntu/Debian:
```
sudo apt-get install python-requests
```

- Install for Centos/Redhat:
```
sudo yum install python-requests
```

- Install using pip on Linux:
```
sudo pip install requests
```

#### argparse Module

- Install for Ubuntu/Debian:
```
sudo apt-get install python-argparse
```

- Install for Centos/Redhat:
```
sudo yum install python-argparse
``` 

- Install using pip:
```
sudo pip install argparse
```

## License

Turbolist3r is licensed under the GNU GPL license. take a look at the [LICENSE](https://github.com/fleetcaptain/Turbolist3r/blob/master/LICENSE) for more information.

Respect legal restrictions and only conduct testing against infrastructure that you have permission to target.

## Credits

* [aboul3la](https://github.com/aboul3la/sublist3r) - The creator of **Sublist3r**; turbolist3r adds some features but is otherwise a near clone of sublist3r. 
* [TheRook](https://github.com/TheRook/) - The bruteforce module was based on his script **subbrute**.
* [bitquark](https://github.com/bitquark) - The Subbrute's wordlist was based on his research **dnspop**.

## Thanks

* Thank you to [aboul3la](https://github.com/aboul3la/) for releasing sublist3r, an incredible subdomain discovery tool!
