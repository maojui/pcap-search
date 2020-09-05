FROM ubuntu:16.04
RUN sed -i "s/archive.ubuntu.com/tw.archive.ubuntu.com/g" /etc/apt/sources.list
RUN apt-get update && apt-get install -y \
    vim\
    python2.7 python2.7-dev python-pip\
    libpcap-dev \
    bc \
    inotify-tools \
    ruby \
    ruby-dev \
    nodejs \
    npm \
    locales \
    psmisc \
    zsh \
    git

RUN locale-gen en_US.UTF-8 && \
    pip install dpkt pypcap && \
    gem install sinatra sinatra-contrib tilt sass slim coffee-script && \
    ln -s /usr/bin/nodejs /usr/bin/node && \
    npm i -g bower

RUN apt-get update && apt-get install -y socat
RUN apt-get update && apt-get install -y htop
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

# install google re2
RUN git clone https://github.com/google/re2.git ~/re2 && \
    cd ~/re2 && make && make install

# Install network utils
RUN apt-get update && apt-get install -y \ 
    iptables \
    iputils-ping \
    net-tools \
    rsyslog

COPY . /root/pcap-search/
WORKDIR /root/pcap-search/web/
RUN bower i --allow-root && \
    chmod +x /root/pcap-search/start && \
    make -C /root/pcap-search/
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# build search_regex
RUN cd /root/pcap-search/search_regex && make

WORKDIR /root/pcap-search/
VOLUME /mnt/pcap
EXPOSE 4568
CMD ["/root/pcap-search/start"]
