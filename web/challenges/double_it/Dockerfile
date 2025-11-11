FROM golang:1.21-alpine

WORKDIR /app

# Install necessary tools
RUN apk add --no-cache iputils bash

COPY go.mod ./
COPY main.go ./
COPY flag.txt ./

RUN go build -o app main.go

EXPOSE 5000

CMD ["./app"]
