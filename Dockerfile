FROM python:buster

LABEL version="0.0.1-dev" \
	author="RoninNakomoto (https://github/com/RoninNakomoto)" \
	docker_build="docker build -t sublister ." \
	docker_run_basic="docker run --rm sublister -h"

RUN mkdir /Sublister2

COPY [".", "/Sublist3r2"]

ENV PATH=${PATH}:/Sublist3r2

RUN apt-get update && \
	apt-get install -y build-essential libffi-dev libgit2-dev && \
	pip install /Sublist3r2 && \
	addgroup Sublist3r2 --force-badname && \
	useradd -g Sublist3r2 -d /Sublist3r2 -s /bin/sh Sublist3r2 && \
	chown -R Sublist3r2:Sublist3r2 /Sublist3r2 && \
	export RANDOM_PASSWORD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c44) && \
	echo "root:$RANDOM_PASSWORD" | chpasswd && \
	unset RANDOM_PASSWORD && \
	passwd -l root

USER Sublist3r2

ENTRYPOINT ["sublist3r2"] 

CMD ["-h"]
