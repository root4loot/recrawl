FROM golang:1.19-alpine

RUN mkdir /app
ADD . /app
WORKDIR /app
RUN go build -o recrawl .
RUN chmod a+x ./recrawl
ENTRYPOINT ["/app/recrawl"]