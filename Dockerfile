FROM eclipse-temurin:8-jdk

RUN apt-get update && \
    apt-get install -y wget bash libgomp1 && \
    rm -rf /var/lib/apt/lists/*

RUN cd / && \
    wget https://github.com/sbt/sbt/releases/download/v0.13.18/sbt-0.13.18.tgz && \
    tar xf sbt-0.13.18.tgz && \
    rm *.tgz && \
    ln -s /sbt/bin/sbt /usr/local/bin/sbt

COPY . /Symnet

WORKDIR /Symnet

RUN sbt compile

CMD bash
