ARG RUBY=ruby:3.3-bookworm
FROM ${RUBY}
RUN apt-get update && apt-get install -y --no-install-recommends libc6-dev gcc make >/dev/null && rm -rf /var/lib/apt/lists/*
RUN gem install webrick --no-document
COPY app.rb /app/app.rb
RUN echo "FLAG{regrush:$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}" > /CANARY && chmod 444 /CANARY
EXPOSE 80
CMD ["ruby", "/app/app.rb"]
