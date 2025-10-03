FROM openjdk:8-jdk-alpine
MAINTAINER Johannes M. Scheuermann <ugene@student.kit.edu>

RUN apk --no-cache add ca-certificates wget openssl bash libgomp gcompat && \
    update-ca-certificates

RUN cd / && \
    wget https://github.com/sbt/sbt/releases/download/v0.13.18/sbt-0.13.18.tgz && \
    tar xf sbt-0.13.18.tgz && \
    rm *.tgz && \
    ln -s /sbt/bin/sbt /usr/local/bin/sbt

COPY . /Symnet

WORKDIR /Symnet

RUN sbt compile && \
    sbt sample

CMD bash
