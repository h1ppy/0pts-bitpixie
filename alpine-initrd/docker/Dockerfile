FROM alpine:3.4

COPY build.sh /
COPY init /
COPY dhcp.start /

# Копируем наше ядро линукс  
COPY kernel-modules/lib/modules/5.14.0-1-amd64/ /lib/modules/5.14.0-1-amd64/
# Копируем наш кастомный exploit для извлечения vmk ключей  
COPY CVE-2024-1086/ /root/CVE-2024-1086

CMD /build.sh
