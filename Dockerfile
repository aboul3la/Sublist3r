FROM python:alpine

COPY . .

RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "sublist3r.py"]
