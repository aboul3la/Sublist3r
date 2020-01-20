FROM python:3

WORKDIR /app

CP . .

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "sublist3r.py","-d"]

