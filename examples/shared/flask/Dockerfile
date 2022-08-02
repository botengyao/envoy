FROM python:3.11.0b5-slim-bullseye@sha256:fcbdb871b4695aada028bc9e51eeae28cbcb8a5fe3b0d76542123729eb46cf36

ADD requirements.txt /tmp/flask-requirements.txt
RUN pip3 install -qr /tmp/flask-requirements.txt
RUN mkdir /code

ENTRYPOINT ["python3", "/code/service.py"]
