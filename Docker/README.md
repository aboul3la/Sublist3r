# Run WebSploit with 'Docker'

![docker](https://img.shields.io/badge/Docker-v19.03.12-blue?style=plastic&logo=docker)
![Maintainer](https://img.shields.io/badge/Maintainer-Equinockx-success?style=plastic&logo=terraform)

## Requeriments

- [X] Docker

## Usage Mode

Clone the repo from Github
```bash
git clone https://github.com/aboul3la/Sublist3r 
cd Sublist3r
```

## Build the docker image

```bash
docker build -t sublister .
```
docker images

```bash
➜  Sublist3r git:(master) ✗ docker images
REPOSITORY                    TAG                    IMAGE ID
sublister                   latest                 4f185b4085fd
```

if you wanna put the tag to the image just add :<tag> like this sublister:v1.0

Run the container

```bash
docker run -dti --name sublister sublister:<tag> 
```
## Build the network

```bash
docker network create security 
```

connect the container to the network

                        network container_name
```bash
docker network connect security sublister
```

## Execute websploit in container

```bash
➜  Sublist3r git:(master) ✗ docker exec -ti sublister python2 sublist3r.py -h
```             
## Example

```bash

➜  Sublist3r git:(master) ✗ docker exec -ti sublister python2 sublist3r.py -d microsoft.com

                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|

                # Coded By Ahmed Aboul-Ela - @aboul3la
    
[-] Enumerating subdomains now for microsoft.com
[-] Searching now in Baidu..
[-] Searching now in Yahoo..
[-] Searching now in Google..
[-] Searching now in Bing..
[-] Searching now in Ask..
[-] Searching now in Netcraft..
[-] Searching now in DNSdumpster..
[-] Searching now in Virustotal..
[-] Searching now in ThreatCrowd..
[-] Searching now in SSL Certificates..
[-] Searching now in PassiveDNS..
```
Exit the container 'CTRL + c'
