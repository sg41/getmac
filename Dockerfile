FROM gcc:latest as build

COPY . /usr/src/myapp

WORKDIR /usr/src/myapp

RUN make

from alpine:latest

COPY --from=build /usr/src/myapp/getmac /usr/local/bin/getmac

ENTRYPOINT ["getmac"]