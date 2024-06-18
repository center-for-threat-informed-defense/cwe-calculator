FROM ubuntu:24.04

RUN apt update
RUN apt install -y curl python3 python3-pip python3-venv
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH $PATH:/root/.local/bin
RUN mkdir /ec3-server
COPY pyproject.toml poetry.lock /ec3-server
COPY src /ec3-server/src
WORKDIR /ec3-server
RUN poetry install
EXPOSE 8000
CMD ["poetry", "run", "ec3-server", "--host", "0.0.0.0"]
