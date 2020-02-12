FROM shibme/codefender-base
LABEL maintainer="shibme"
RUN mkdir /codefender-bin
ADD target/run-codefender.jar /codefender-bin/run-codefender.jar
WORKDIR /workspace
CMD ["java","-jar","/codefender-bin/run-codefender.jar"]