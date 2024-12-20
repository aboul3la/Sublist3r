FROM python:3.9-slim

# Install Sublist3r
RUN apt-get update && apt-get install -y git
RUN git clone https://github.com/aboul3la/Sublist3r.git
RUN pip install -r Sublist3r/requirements.txt

# Make port 80 available to the world outside this container
EXPOSE 80

# Run Sublist3r when the container launches
ENTRYPOINT [ "python3", "Sublist3r/sublist3r.py" ]
