FROM ubuntu:16.04
LABEL maintainer Subramani Ramanathan <subramani95@gmail.com>

RUN apt-get update && apt-get install -y \
        gcc \
        libwww-perl \
        libxml-simple-perl \
        libxml-writer-perl \
        libxml-xslt-perl \
        make \
        nginx

RUN PERL_MM_USE_DEFAULT=1 && perl -MCPAN -e \
        'install REST::Client; \
         install JSON; \
         install JSON::Parse'

RUN mkdir -p /opt/REST-Lite/reports
COPY bin   /opt/REST-Lite/bin
COPY lib   /opt/REST-Lite/lib
COPY tests /opt/REST-Lite/tests

RUN ln -s /opt/REST-Lite/reports/ /var/www/html/rest-lite

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
