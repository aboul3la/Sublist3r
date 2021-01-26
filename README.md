## About Sublist3r2 

Sublist3r2 is an improved and bug-free working version of Sublist3r, the original dns enumeration tool but with a much faster bruteforcing routine.

#### Package Description:
*Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster and ReverseDNS. **(from original page)** *
"

### Compatibility notes:
This particular release is compatible with linux python3 (>3.6) installations only. </br>
Other operating systems (macos, windows) will be supported in later releases. </br>
BruteForcing is now multiple times faster than in the original tool and uses aiodnsbrute instead of subbrute.</br>





## Screenshots

<a href="https://freeimage.host/i/ffJOH7"><img src="https://iili.io/ffJOH7.md.png" alt="ffJOH7.md.png" border="0"></a>


## Installation

Under linux, use a python3 virtual environment specific to sublist3r. </br>

You will be running the tool within this virtual python environment and not the system wide python installation. All python commands you run once the virtual environment is activated are specific to the virtual environment. Changes you make to a virtual environment, including installing dependencies only affect the virtual environment and do not affect the system wide installation of Python which usually ends up breaking python.

Assuming you are going to keep your python virtual environments in a directory called environments under your home directory, please proceed as follows to install virtual environments , required depencies to run the tool:

```
1- $ git clone https://github.com/RoninNakomoto/Sublist3r2.git // Download tool from github
2- $ python3 -m venv ~/environments/sublist3r      // create a python version 3 virtual environment for sublist3r
3- $ source ~/environments/sublist3r/bin/activate  // activate sublist3r python environment. 
4- $ python -m pip install --upgrade pip              // update pip inside virtual env.
5- $ cd ~/sublist3r/                                         // switch to your sublist3r download folder.
6- $ pip install -r requirements.txt                    // install sublist3r module dependencies.
7- $ python sublist3r.py -d domain.com               // run sublist3r.py from within activated environment
8- $ deactivate                                            // deactivate environment once done runnning the script.
note: do not use sudo.
```


```
git clone https://github.com/aboul3la/Sublist3r.git
```

## Recommended Python Version:

Sublist3r currently supports **Python 2** and **Python 3**.

* The recommended version for Python 2 is **2.7.x**
* The recommended version for Python 3 is **3.4.x**

## Dependencies:

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

#### Requests Module (http://docs.python-requests.org/en/latest/)

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

#### dnspython Module (http://www.dnspython.org/)

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

**for coloring in windows install the following libraries**
```
c:\python27\python.exe -m pip install win_unicode_console colorama
```

## Usage

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

### Examples

* To list all the basic options and switches use -h switch:

```python sublist3r.py -h```

* To enumerate subdomains of specific domain:

``python sublist3r.py -d example.com``

* To enumerate subdomains of specific domain and show only subdomains which have open ports 80 and 443 :

``python sublist3r.py -d example.com -p 80,443``

* To enumerate subdomains of specific domain and show the results in realtime:

``python sublist3r.py -v -d example.com``

* To enumerate subdomains and enable the bruteforce module:

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
* **domain**: The domain you want to enumerate subdomains of.
* **savefile**: save the output into text file.
* **ports**: specify a comma-sperated list of the tcp ports to scan.
* **silent**: set sublist3r to work in silent mode during the execution (helpful when you don't need a lot of noise).
* **verbose**: display the found subdomains in real time.
* **enable_bruteforce**: enable the bruteforce module.
* **engines**: (Optional) to choose specific engines.

Example to enumerate subdomains of Yahoo.com:
```python
import sublist3r 
subdomains = sublist3r.main('yahoo.com', 40, 'yahoo_subdomains.txt', ports= None, silent=False, verbose= False, enable_bruteforce= False, engines=None)
```

## License

Sublist3r is licensed under the GNU GPL license. take a look at the [LICENSE](https://github.com/aboul3la/Sublist3r/blob/master/LICENSE) for more information.


## Credits

* [TheRook](https://github.com/TheRook) - The bruteforce module was based on his script **subbrute**. 
* [Bitquark](https://github.com/bitquark) - The Subbrute's wordlist was based on his research **dnspop**. 

## Thanks

* Special Thanks to [Ibrahim Mosaad](https://twitter.com/ibrahim_mosaad) for his great contributions that helped in improving the tool.

## Version
**Current version is 1.0**
