FROM python:3.10-slim

RUN apt-get update && apt-get install --no-install-recommends -y git graphviz \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/ev-flow/quark-engine.git

WORKDIR /quark-engine

RUN pip install pipenv && pipenv install --skip-lock
RUN pipenv run freshquark

WORKDIR /quark-engine/quark
ENTRYPOINT ["pipenv", "run"]
