## Turbolist3r - Beta

Turbolist3r is a fork of the [sublist3r](https://github.com/aboul3la/sublist3r) subdomain discovery tool. In addition to all original OSINT capabilties of sublist3r, turbolist3r automates some of the results analysis, with a focus on subdomain takeover.

Turbolist3r queries public DNS servers for each discovered subdomain. If the subdomain exists (i.e. the resolver replied with an address), the answer is categorized as CNAME or A record. By examining A records, it is possible to discover potential penetration testing targets for a given domain. Likewise, the process of looking for subdomain takeovers is simple; view the discovered CNAME records and investigate any that point to applicable cloud services.

This is an early release and may contain bugs or other irregularities.

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
-a            | --analysis    | Do analysis of the results and save to specified text file

### Examples

* To enumerate subdomains of a specific domain, perform turbolist3r analysis, and save the analysis to a file:

``python turbolist3r.py -d example.com -a analysis_file.txt``

* To list all the basic options and switches use -h switch:

```python turbolist3r.py -h```

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

Note that turbolist3r has not been tested on Windows.

Turbolist3r depends on the `requests`, `dnspython`, and `argparse` python modules.


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

#### dnspython Module (http://www.dnspython.org/)

- Install for Ubuntu/Debian:
```
sudo apt-get install python-dnspython
```

- Install using pip:
```
sudo pip install dnspython
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

## Thanks

* Thank you to [aboul3la](https://github.com/aboul3la/sublist3r) for releasing sublist3r, an incredible subdomain discovery tool!

## Version
**1/15/18 Version 0.1**
