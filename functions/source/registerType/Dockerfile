FROM lambci/lambda:build-python3.7

COPY . .

RUN rm Dockerfile && \
    zip -X -r lambda.zip ./

CMD mv lambda.zip /output/
