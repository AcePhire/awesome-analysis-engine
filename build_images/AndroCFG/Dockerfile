FROM python:3.11-slim

WORKDIR /androcfg
COPY . .

RUN apt update && apt install -y git gcc python3-dev libfuzzy-dev graphviz
RUN pip install -r requirements.txt

RUN pip install git+https://github.com/U039b/AndroCFG.git
