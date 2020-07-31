FROM  kalilinux/kali
MAINTAINER equinockx

WORKDIR /home/

RUN apt-get update && \
    apt-get install -y  --no-install-recommends python2.7 && \
    apt-get install -y python-pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY . /home/

RUN pip install -r requirements.txt

ENTRYPOINT [ "bash" ]