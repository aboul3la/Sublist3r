##About Sublist3r 

Sublist3r is python tool that is designed to enumerate subdomains of websites through various OSINT sources. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r currenly supports many search engines such as Google, Yahoo, Bing, Baidu, and Ask. More search engines may be added in the future. Sublist3r also gathers subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster and PassiveDNS.

[subbrute](https://github.com/TheRook/subbrute) was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.

##Screenshots

![Sublist3r](http://www.secgeek.net/images/Sublist3r.png "Sublist3r in action")


##Installation

```
git clone https://github.com/aboul3la/Sublist3r.git
```

##Recommended Python Version:

Sublist3r currently supports **Python 2** and **Python 3**.

* The recommended version for Python 2 is **2.7.x**
* The recommened version for Python 3 is **3.4.x**

##Dependencies:

Sublist3r depends on the `requests`, `dnspython` and `argparse` python modules.

These dependencies can be installed using the requirements file:

- Installation on Windows:
```
c:\python27\python.exe -m pip install -r requirements.txt
```

- Installation on Linux
```
sudo pip install -r requirements.txt
```

Alternatively, each module can be installed independently as shown below.

####Requests Module (http://docs.python-requests.org/en/latest/)

- Install for Windows:
```
c:\python27\python.exe -m pip install requests
```

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

####dnspython Module (http://www.dnspython.org/)

- Install for Windows:
```
c:\python27\python.exe -m pip install dnspython
```

- Install for Ubuntu/Debian:
```
sudo apt-get install python-dnspython
```

- Install using pip:
```
sudo pip install dnspython
```

####argparse Module

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

##Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-d            | --domain      | Domain name to enumerate subdomains of
-b            | --bruteforce  | Enable the subbrute bruteforce module
-p            | --ports       | Scan the found subdomains against specific tcp ports
-v            | --verbose     | Enable the verbose mode and display results in realtime
-t            | --threads     | Number of threads to use for subbrute bruteforce
-e            | --engines     | Specify a comma-separated list of search engines
-o            | --output      | Save the results to text file
-h            | --help        | show the help message and exit

###Examples

* To list all the basic options and switches use -h switch:

```python sublist3r.py -h```

* To enumerate subdomains of specific domain:

``python sublist3r.py -d example.com``

* To enumerate subdomains of specific domain and show only subdomains with open ports 80 and 443 :

``python sublist3r.py -d example.com -p 80,443``

* To enumerate subdomains of specific domain and show results in realtime:

``python sublist3r.py -v -d example.com``

* To enumerate subdomains and use the subbrute bruteforce module:

``python sublist3r.py -b -d example.com``

* To enumerate subdomains and use specific engines such Google, Yahoo and Virustotal engines

``python sublist3r.py -e google,yahoo,virustotal -d example.com``


## Using Sublist3r as a module in your python scripts

**Example**

```python
import sublist3r 
subdomains = sublist3r.main(domain, no_threads, savefile, ports, silent, verbose, enable_bruteforce, engines)
```
The main function will return a set of unique subdomains found by Sublist3r

**Function Usage:**
* domain: The domain you want to enumerate subdomains of
* savefile: Save the result into a text file
* ports:  specify a comma-sperated list of tcp ports to scan
* silent: Set Sublist3r to work in silent mode during execution (could be helpful when you don't need a lot of noise)
* verbose: Show the found subdomains in real time
* enable_bruteforce: Enable the subbrute module
* engines: Optional to choose specific OSINT engines

Example to enumerate subdomains of Yahoo.com:
```python
import sublist3r 
subdomains = sublist3r.main('yahoo.com', 40, 'yahoo_subdomains.txt', ports= None, silent=False, verbose= False, enable_bruteforce= False, engines=None)
```

##License

Sublist3r is licensed under the GNU GPL license. take a look at the [LICENSE](https://github.com/aboul3la/Sublist3r/blob/master/LICENSE) for more information.


##Credits

* [TheRook](https://github.com/TheRook) - The bruteforce module was based on his script **subbrute**. 
* [Bitquark](https://github.com/bitquark) - The Subbrute's wordlist was based on his research **dnspop**. 

##Thanks

* Special Thanks to [Ibrahim Mosaad](https://twitter.com/ibrahim_mosaad) for his great contributions that helped in improving the tool.

##Version
**Current version is 1.0**
