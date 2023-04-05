FROM golang:1.19-alpine

RUN mkdir /app
ADD . /app
WORKDIR /app
RUN go build -o urldiscover .
RUN chmod a+x ./urldiscover
ENTRYPOINT ["/app/urldiscover"]