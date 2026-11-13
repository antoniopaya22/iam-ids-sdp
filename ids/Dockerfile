# syntax=docker/dockerfile:1
# IDS of the lab: Apollon-style MAB over a classifier pool + per-identity baseline (UEBA).
# The model is trained while the image is built, on the telemetry windows recorded in the
# lab (data/lab-windows.csv, see scripts/ids/record-dataset.sh). Without that file the
# IDS runs with the baseline only.
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin ids
WORKDIR /opt/ids
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY sdp_ids ./sdp_ids
COPY third_party ./third_party
COPY data ./data
RUN if [ -f data/lab-windows.csv ]; then \
        python -m sdp_ids.train --data data/lab-windows.csv --out /opt/ids/model.joblib --report /opt/ids/model.json; \
    else \
        echo "no data/lab-windows.csv: the IDS will run with the UEBA baseline only"; \
    fi
RUN mkdir -p /data && chown 10001:10001 /data
USER 10001
ENTRYPOINT ["python", "-m", "sdp_ids"]
CMD ["serve"]
