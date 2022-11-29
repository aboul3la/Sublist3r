FROM ubuntu:latest

ARG DEBIAN_FRONTEND=noninteractive

COPY . .

RUN apt update && \
  apt install python3-pip python-is-python3 -y && \
  pip install -r requirements.txt

ENTRYPOINT ["python3", "sublist3r.py"]
