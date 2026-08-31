# Build environment for the tpm-fido Debian package, targeting Ubuntu 26.04.
FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      debhelper \
      dpkg-dev \
      fakeroot \
      golang-go \
      lintian \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash builder

COPY build-in-container.sh /usr/local/bin/build-in-container.sh
RUN chmod +x /usr/local/bin/build-in-container.sh

ENTRYPOINT ["/usr/local/bin/build-in-container.sh"]
