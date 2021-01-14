FROM python:3.6

RUN apt-get update
RUN apt-get install -y python-pip



RUN mkdir /app
COPY scope_tools.py /app
COPY requirements.txt /app

WORKDIR /app

RUN pip install -r requirements.txt

ENTRYPOINT ["python" ,"scope_tools.py"]