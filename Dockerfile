FROM shibme/codefend-base
LABEL maintainer="shibme"
RUN mkdir -p /codefend-bin
RUN mkdir -p /root/.ssh
ADD target/codefend-jar-with-dependencies.jar /codefend-bin/run-codefend.jar
WORKDIR /codefend
CMD ["java","-jar","/codefend-bin/run-codefend.jar"]