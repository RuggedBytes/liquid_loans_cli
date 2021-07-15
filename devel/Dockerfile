FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y build-essential libtool autotools-dev autoconf pkg-config libssl-dev libboost-all-dev
RUN apt-get install -y libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler imagemagick librsvg2-bin
RUN apt-get install -y libqrencode-dev autoconf openssl libssl-dev libevent-dev libminiupnpc-dev jq wget git bsdmainutils
RUN apt-get install -y python3-pip
RUN apt-get install -y libdb++-dev

RUN cd /root && git clone https://github.com/ElementsProject/elements.git
WORKDIR /root/elements 
RUN git checkout elements-0.18.1.12
RUN ./autogen.sh && ./configure LDFLAGS="-L/root/bdb4/lib/" CPPFLAGS="-I/root/bdb4/include/" --with-incompatible-bdb --without-gui --without-miniupnpc --disable-tests --disable-bench && make && make install
RUN mkdir ~/elementsdir1
RUN mkdir ~/elementsdir2
RUN sed 's/validatepegin=1/validatepegin=0/g;s/elementsregtest/liquidregtest/g' ~/elements/contrib/assets_tutorial/elements1.conf | tee ~/elementsdir1/elements.conf
RUN echo "chain=liquidregtest" > ~/elementsdir2/elements.conf
RUN sed 's/validatepegin=1/validatepegin=0/g;s/elementsregtest/liquidregtest/g' ~/elements/contrib/assets_tutorial/elements2.conf | tee -a ~/elementsdir2/elements.conf

RUN echo alias e1-dae=\"/root/elements/src/elementsd -datadir=/root/elementsdir1\" >> ~/.bashrc
RUN echo alias e1-cli=\"/root/elements/src/elements-cli -datadir=/root/elementsdir1\" >> ~/.bashrc
RUN echo alias e2-dae=\"/root/elements/src/elementsd -datadir=/root/elementsdir2\" >> ~/.bashrc
RUN echo alias e2-cli=\"/root/elements/src/elements-cli -datadir=/root/elementsdir2\" >> ~/.bashrc
RUN echo export LC_ALL=C.UTF-8 >> ~/.bashrc
RUN echo export LANG=C.UTF-8 >> ~/.bashrc

WORKDIR /root

RUN cd /root && git clone https://github.com/ElementsProject/secp256k1-zkp
WORKDIR /root/secp256k1-zkp
RUN ./autogen.sh && ./configure --prefix=/usr --enable-experimental --enable-module-generator --enable-module-rangeproof --enable-module-surjectionproof --enable-module-ecdh --enable-module-recovery && make && make install

WORKDIR /root
ADD devel/prepare.sh devel/split.py devel/entry.sh poetry.lock pyproject.toml /root/
RUN pip3 install --upgrade pip
RUN pip3 install poetry
RUN poetry config virtualenvs.create false
RUN LC_ALL=C.UTF-8 poetry install
RUN LC_ALL=C.UTF-8 poetry run pip install git+https://github.com/Simplexum/python-elementstx.git
RUN /root/prepare.sh

# cleanup
RUN apt-get --auto-remove remove -yqq --purge manpages \
 && apt-get clean \
 && apt-get autoclean \
 && rm -rf /usr/share/doc* /usr/share/man /usr/share/postgresql/*/man /var/lib/apt/lists/* /var/cache/* /tmp/* /root/.cache /*.deb /root/.cargo

ENTRYPOINT ["/root/entry.sh"]
