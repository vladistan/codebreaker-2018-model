FROM spritsail/alpine-cmake:3.8 AS build

COPY *.c /build/
COPY *.cpp /build/
COPY *.h /build/
COPY CMakeLists.txt /build/
WORKDIR /build
RUN apk add openssl-dev && \
    apk add cpputest && \
    cmake . && \
    make find_ips && \
    ls -l /usr/lib/lib*.so


FROM alpine:3.8

RUN mkdir -p /p
WORKDIR /p
COPY --from=build /usr/lib/libgcc_s.so.1 /usr/lib
COPY --from=build /usr/lib/libstdc++.so.6 /usr/lib
COPY --from=build /usr/lib/libcrypto.so.1.0.0 /usr/lib
COPY --from=build /build/find_ips /p/find_ips

CMD ["/p/find_ips"]

