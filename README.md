##About Sublist3r 

Sublist3r is python tool that is designed to enumerate subdomains of websites using search engines. it helps penetration testers and bug hunters to collect and gather all the possible subdomains of the target. Sublist3r currently supports Google,Yahoo,Bing,Baidu,Ask search engines and more search engines could be added soon. it gathers subdomains also using Netcraft and DNSdumpster Service.

[subbrute](https://github.com/TheRook/subbrute) also was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook the author of subbrute

##Screenshots

![Sublist3r](http://www.secgeek.net/images/Sublist3r.png "Sublist3r in action")


##Installation

```
git clone https://github.com/aboul3la/Sublist3r.git
```

##Dependencies:

####Requests library (http://docs.python-requests.org/en/latest/)

- Install for Ubuntu/Debian:
```
sudo apt-get install python-requests
```
- Install for Centos/Redhat:
```
sudo yum install python-requests
```

- Install using pip:
```
sudo pip install requests
```

####dnspython library (http://www.dnspython.org/)


- Install for Ubuntu/Debian:
```
sudo apt-get install python-dnspython
```

- Install using pip:
```
pip install dnspython
```


##Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-d            | --domain      | Domain name to enumrate it's subdomains
-b            | --bruteforce  | Enable the subbrute bruteforce module
-v            | --verbose     | Enable Verbosity and display results in realtime
-t            | --threads     | Number of threads to use for subbrute bruteforce
-o            | --output      | Save the results to text file
-h            | --help        | show the help message and exit

###Examples

* To list all the basic options and switches use -h switch:

```python sublist3r.py -h```

* To enumerate subdomains of specific domain:

``python sublist3r.py -d example.com``

* To enumerate subdomains of specific domain and show results in realtime:

``python sublist3r.py -v -d example.com``

* To enumerate subdomains and use the subbrute bruteforce module:

``python sublist3r.py -b -d example.com``

##License

Sublist3r is licensed under the GNU GPL license. take a look at the [LICENSE](https://github.com/aboul3la/Sublist3r/blob/master/LICENSE) for more information.


##Credits

* [TheRook](https://github.com/TheRook) - The bruteforce module was based on his script **subbrute**. 

##Thanks

* Special Thanks to [Ibrahim Mosaad](https://twitter.com/ibrahim_mosaad) for his great contributions that helped in improving the tool.

##Version
**Current version is 0.1 alpha**
