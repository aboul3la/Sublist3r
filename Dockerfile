FROM python:alpine

COPY . .

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "sublist3r.py"]
