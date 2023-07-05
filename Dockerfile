# Requires Docker build arg: --build-arg PIVNET_API_TOKEN=your_pivnet_api_token
# Start with an Alma Linux image
FROM almalinux:latest AS builder

# Set the working directory to /app
WORKDIR /app

# Pivnet API token taken from build arg
ARG PIVNET_API_TOKEN
ENV PIVNET_API_TOKEN ${PIVNET_API_TOKEN}

RUN echo "Downloading age" && \
    curl -sSL https://github.com/FiloSottile/age/releases/download/v1.1.1/age-v1.1.1-linux-amd64.tar.gz | tar -xz && \
    mv age/age /usr/local/bin/

RUN echo "Downloading sops" && \
    curl -sSL -o sops https://github.com/mozilla/sops/releases/download/v3.7.3/sops-v3.7.3.linux.amd64 && \
    chmod +x sops && \
    mv sops /usr/local/bin/

RUN echo "Downloading yq" && \
    curl -sSL -o yq https://github.com/mikefarah/yq/releases/download/v4.34.1/yq_linux_amd64 && \
    chmod +x yq && \
    mv yq /usr/local/bin/

RUN echo "Downloading jq" && \
    curl -sSL -o jq https://github.com/jqlang/jq/releases/download/jq-1.6/jq-linux64 && \
    chmod +x jq && \
    mv jq /usr/local/bin/

RUN echo "Downloading pivnet" && \
    curl -sSL -o pivnet https://github.com/pivotal-cf/pivnet-cli/releases/download/v3.0.1/pivnet-linux-amd64-3.0.1 && \
    chmod +x pivnet && \
    mv pivnet /usr/local/bin/

RUN echo "Downloading charts-syncer" && \
    curl -sSL https://github.com/bitnami-labs/charts-syncer/releases/download/v0.20.1/charts-syncer_0.20.1_linux_x86_64.tar.gz | tar -xz && \
    mv charts-syncer /usr/local/bin/

RUN echo "Downloading Docker CLI" && \
    curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-20.10.7.tgz -o docker.tgz && \
    tar --extract --file docker.tgz --strip-components 1 docker/docker && \
    mv docker /usr/local/bin/

RUN pivnet login --api-token=${PIVNET_API_TOKEN} && \
    pivnet download-product-files --product-slug='tanzu-application-platform' --release-version='1.4.5' --product-file-id=1478736 && \
    tar xvf tanzu-framework-linux-amd64-v0.25.4.7.tar && \
    install cli/core/v0.25.4/tanzu-core-linux_amd64 /usr/local/bin/tanzu && \
    tanzu plugin install --local cli all

RUN echo "Downloading imgpkg" && \
    curl -sSL -o imgpkg https://github.com/carvel-dev/imgpkg/releases/download/v0.31.5/imgpkg-linux-amd64 && \
    chmod +x imgpkg && \
    mv imgpkg /usr/local/bin/


FROM almalinux:latest

WORKDIR /app

RUN echo "Downloading wget" && \
    dnf -y update && dnf -y install wget

COPY --from=builder /usr/local/bin /usr/local/bin


# docker volume create tanzu-workdir
# git clone git@github.com:BeepBoopRobit/tap-gitops-ri.git
# mount cloned git repo 
# docker run --rm -it -v /home/tanzu/tap-gitops-ri:/app tap-installer:latest bash 