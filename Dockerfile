FROM python:3.4-alpine

COPY . /

RUN pip3 install -r /requirements.txt

# Drop privileges
RUN adduser -D -u 49999 -s /usr/sbin/nologin service_user
USER service_user

# Show help by default, with run args overriding CMD
ENTRYPOINT [ "python3", "sublist3r.py" ]
CMD [ "-h" ]