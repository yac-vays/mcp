#
# Base Image
#

FROM python:3.15.2-alpine3.24 AS build

WORKDIR /code

COPY ./requirements.* ./

RUN apk add --virtual build-deps build-base libffi-dev && \
    pip install --no-cache-dir --upgrade --compile -r /code/requirements.txt && \
    apk del build-deps && \
    rm -rf /var/cache/apk/*

COPY ./app /code/app

#
# Linting/Testing
#

FROM build AS test

RUN pip install --no-cache-dir --upgrade --compile pylint pytest pytest-asyncio respx
RUN pylint --rcfile /code/app/.pylintrc --exit-zero /code/app /code/app/plugin/*/*.py
COPY ./tests /code/tests
RUN cd /code && PYTHONPATH=/code python -m pytest -c /code/tests/pytest.ini /code/tests
RUN touch /tmp/tested

#
# Final Image
#

FROM build AS production

# Enforce test run
COPY --from=test /tmp/tested /dev/null

ARG version=v0.0
RUN echo 'VERSION = "'${version#v}'"' > /code/app/version.py

RUN addgroup -g 1000 yac && \
    adduser -D -u 1000 -G yac -h /home/yac yac && \
    chown -R yac:yac /code

USER 1000

EXPOSE 8080
ENTRYPOINT ["uvicorn", "--log-config", "app/uvicorn.yml", "--host", "0.0.0.0", "--port", "8080", "app.main:app"]
