FROM shibme/codeinspect-base
LABEL maintainer="shibme"
RUN mkdir -p /codeinspect-bin
RUN mkdir -p /root/.ssh
ADD target/codeinspect-jar-with-dependencies.jar /codeinspect-bin/run-codeinspect.jar
RUN dependency-check -s /tmp/ && rm dependency-check-report.html
RUN bundle audit update
RUN retire update
WORKDIR /codeinspect
CMD ["java","-jar","/codeinspect-bin/run-codeinspect.jar"]