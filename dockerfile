FROM eclipse-temurin:25-jre-alpine
WORKDIR /app
COPY target/gateway-0.0.1-SNAPSHOT.jar app.jar
ENV JAVA_OPTS="-Xms50m -Xmx120m -XX:+UseSerialGC"
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]