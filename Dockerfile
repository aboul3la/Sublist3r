FROM python:alpine3.13

RUN mkdir /app
WORKDIR /app
COPY . /app

RUN /usr/local/bin/python -m pip install --upgrade pip
RUN /usr/local/bin/python --version

RUN pip3 install --no-cache-dir -r requirements.txt
RUN chmod +x ./*.py
ENTRYPOINT [ "/app/sublist3r2.py" ]