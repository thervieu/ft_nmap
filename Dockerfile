FROM debian:latest

MAINTAINER <thervieu@student.42.fr>

RUN apt-get update
RUN apt-get install -y build-essential
RUN apt-get install -y traceroute
RUN apt-get install -y libpcap-dev
RUN apt-get install -y tcpdump

ADD . /app
WORKDIR /app

RUN cd /app && make fclean && make

ENTRYPOINT ["sh"]