FROM python:3

RUN apt update \
    && apt install -y git

WORKDIR /app

RUN git clone https://github.com/aboul3la/Sublist3r.git .

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "sublist3r.py","-d"]

