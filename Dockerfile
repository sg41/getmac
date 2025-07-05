FROM gcc:latest AS build

COPY . /usr/src/myapp

WORKDIR /usr/src/myapp

RUN make

FROM ubuntu:latest

COPY --from=build /usr/src/myapp/getmac /usr/local/bin

ENTRYPOINT ["getmac"]
