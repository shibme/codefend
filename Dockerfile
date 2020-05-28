FROM shibme/codeinspect-base
LABEL maintainer="shibme"
RUN mkdir -p /codeinspect-bin
RUN mkdir -p /root/.ssh
ADD target/codeinspect-jar-with-dependencies.jar /codeinspect-bin/run-codeinspect.jar
WORKDIR /codeinspect
CMD ["java","-jar","/codeinspect-bin/run-codeinspect.jar"]