FROM shibme/codefend-base
LABEL maintainer="shibme"
RUN mkdir /codefend-bin
ADD target/codefend-jar-with-dependencies.jar /codefend-bin/run-codefend.jar
WORKDIR /workspace
CMD ["java","-jar","/codefend-bin/run-codefend.jar"]