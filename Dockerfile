FROM eclipse-temurin:11.0.14.1_1-jdk-alpine
COPY build/libs/*.jar /app/gateway-ecram.jar
WORKDIR /app
# ENTRYPOINT ["java", "-jar","-Dspring.profiles.active=dockerdev", "gateway-ecram.jar"]
ENTRYPOINT ["java", "-jar", "-Dspring.profiles.active=dockerdev", "gateway-ecram.jar"]
#docker build -t ecram/gateway-micro:0.0.1-SNAPSHOT .
#docker run -m 256m -d --name gateway-ecram  -p 8090:8090 ecram/gateway-micro:0.0.1-SNAPSHOT
#docker stop gateway-ecram
#docker push ecram/gateway-micro:0.0.1-SNAPSHOT
#docker pull ecram/gateway-micro:0.0.1-SNAPSHOT