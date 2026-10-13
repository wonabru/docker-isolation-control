FROM python:3.12-slim
RUN pip install --no-cache-dir "mitmproxy>=11,<13"
COPY pyproject.toml /src/pyproject.toml
COPY src /src/src
RUN pip install --no-cache-dir /src && \
    cp "$(python -c 'import os, poi; print(os.path.dirname(poi.__file__))')/proxy_addon.py" /opt/proxy_addon.py
ENV POI_RUN=/run/poi HOME=/run/poi/ca
ENTRYPOINT ["mitmdump", "--listen-host", "0.0.0.0", "--listen-port", "8080", \
            "--set", "confdir=/run/poi/ca", "-s", "/opt/proxy_addon.py"]
