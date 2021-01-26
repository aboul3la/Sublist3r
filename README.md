## About Sublist3r2 

Sublist3r2 is an improved and bug-free working version of Sublist3r, the original subdomains enumeration tool but with a much faster bruteforcing routine. It now uses aiodnsbrute instead of subbrute and is capable of bruteforcing 150k subdomains within 15 minutes (at default thread count of 7000).</br>

#### Package Description:
*Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster and ReverseDNS. (from original author page)*
"

### Compatibility notes:

Sublist3r2 currently supports python3 on linux dists. Python3.6+ is the recommended version. </br>
Other operating systems (macos, windows) will be supported in later releases. </br>


## Screenshots

<a href="https://freeimage.host/i/ffJOH7"><img src="https://iili.io/ffJOH7.md.png" alt="ffJOH7.md.png" border="0"></a>

## Dependencies

Sublist3r2 depends on the `requests`, `dnspython` , `argparse` and `aiodnsbrute` python modules.


## Installation

Install **Sublist3r** and its **dependencies**, inside a python3 **virtual env** as detailed in **installation steps below**, in order to avoid non-tool specific python related errors that normally result from broken dependencies when user installs several dependency-conflicting python tools under the system-wide python installation.</br> 
Any issues raised due to inappropriate user installation will be closed to allow focus on resolving real bugs and implementing new features </br>

The installation steps assume you will keep your python virtual envs in a folder called environments under your home directory  directory:

```
1- $ git clone https://github.com/RoninNakomoto/Sublist3r2.git // Download tool from github
2- $ python3 -m venv ~/environments/sublist3r                  // create a python version 3 virtual environment for sublist3r
3- $ source ~/environments/sublist3r/bin/activate              // activate sublist3r python environment. 
4- $ python -m pip install --upgrade pip                       // update pip inside virtual env.
5- $ cd ~/sublist3r/                                           // switch to your sublist3r download folder.
6- $ pip install -r requirements.txt                           // install sublist3r module dependencies.
7- $ python sublist3r.py -d domain.com                         // run sublist3r.py from within activated environment
8- $ deactivate                                                // deactivate environment once done runnning the script.
note: do not use sudo. **Activate/deactivate virtual env. before/after each use**
```

## Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-d            | --domain      | Domain name to use for subdomain enumeration
-b            | --bruteforce  | Turn-on aiodnsbrute bruteforce mode
-p            | --ports       | Check/Filter subdomain results for open tcp ports (provide comma separated ports)
-v            | --verbose     | Enable verbose mode and display results in realtime
-t            | --threads     | Number of threads to use for aiodnsbrute bruteforce
-e            | --engines     | Specify a comma-separated list of search engines
-o            | --output      | Save results to text file
-h            | --help        | show the help message and exit

### Examples

* To list all the basic options and switches use -h switch:

```./sublist3r2.py -h```

* To perform basic enumeration of specified domain:

``./sublist3r2.py -d example.com``

* To check and filter subdomains for results with open ports 80 and 443 :

``./sublist3r2.py -d example.com -p 80,443``

* To enumerate subdomains of specific domain and show the results in realtime:

``./sublist3r2.py -v -d example.com``

* To enable bruteforce mode against specified domain:

``./sublist3r2.py -b -d example.com``

* To enumerate subdomains and use specific engines such as Google, Yahoo and Virustotal engines

``./sublist3r2.py -e google,yahoo,virustotal -d example.com``




## License

Sublist3r is licensed under the GNU GPL license. take a look at the [LICENSE](https://github.com/RoninNakomoto/Sublist3r2/blob/master/LICENSE) for more information.


## Credits

* [aboul3la](https://github.com/aboul3la/) - author of the original sublist3r tool. **sublist3r**. 
* [blark](https://github.com/blark/) - author of aiodns asynchronous bruteforce tool/module **aiodnsbrute**. 
* [danielmiessler](https://github.com/danielmiessler/) - default bruteforce woordlist based on his SecLists release. **SecLists**


## Version
**Current version is Sublist3r2 v1.0**
