#!/bin/sh
set -eu

IMAGE_NAME=${IMAGE_NAME:-copyfail-ebpf}
GHCR_OWNER=${GHCR_OWNER:-$(git remote get-url origin 2>/dev/null | sed -E 's|.*github\.com[:/]([^/]+).*|\1|' || echo "")}
GHCR_REPO=${GHCR_REPO:-$(git remote get-url origin 2>/dev/null | sed -E 's|.*github\.com[:/]+([^/]+/[^/]+)\.git|\1|' || echo "")}
TAG=${TAG:-latest}
ARCH=${ARCH:-x86_64}

usage() {
    echo "Usage: [VAR=value] $0 <build|push|push-build>"
    echo ""
    echo "Commands:"
    echo "  build       Build and tag the image for ghcr.io"
    echo "  push        Push the already-built image to ghcr.io"
    echo "  push-build  Build and push in one step"
    echo ""
    echo "Variables:"
    echo "  GHCR_OWNER  GitHub org/user (default: auto-detected from git remote)"
    echo "  GHCR_REPO   GitHub repo as org/repo (default: auto-detected from git remote)"
    echo "  IMAGE_NAME  Local image name (default: copyfail-ebpf)"
    echo "  TAG         Image tag (default: latest)"
    echo "  ARCH        Target architecture (default: x86_64)"
    echo ""
    echo "Examples:"
    echo "  $0 push-build"
    echo "  TAG=v1.0.0 $0 push-build"
    echo "  GHCR_OWNER=myorg IMAGE_NAME=copyfail-ebpf $0 build"
    echo ""
    echo "Auth: set GHCR_TOKEN or run 'echo \$TOKEN | docker login ghcr.io -u \$USER --password-stdin'"
}

full_tag() {
    echo "ghcr.io/${GHCR_OWNER}/${IMAGE_NAME}:${TAG}"
}

do_login() {
    if [ -n "${GHCR_TOKEN:-}" ]; then
        echo "${GHCR_TOKEN}" | docker login ghcr.io -u "${GHCR_OWNER}" --password-stdin
    elif ! grep -q ghcr.io ~/.docker/config.json 2>/dev/null; then
        echo "Not logged in to ghcr.io. Set GHCR_TOKEN or run: docker login ghcr.io -u <user>" >&2
        exit 1
    fi
}

do_build() {
    if [ -z "${GHCR_OWNER}" ]; then
        echo "Could not auto-detect GHCR_OWNER. Set it manually." >&2
        exit 1
    fi

    echo "Building ${IMAGE_NAME}:${TAG} for ${ARCH}..."
    docker build -t "${IMAGE_NAME}:${TAG}" --build-arg ARCH="${ARCH}" .

    FT="$(full_tag)"
    docker tag "${IMAGE_NAME}:${TAG}" "${FT}"
    echo "Tagged: ${FT}"
}

do_push() {
    do_login
    FT="$(full_tag)"
    echo "Pushing ${FT}..."
    docker push "${FT}"
    echo "Done: ${FT}"
}

COMMAND=${1:-}
case "$COMMAND" in
    build)
        do_build
        ;;
    push)
        do_push
        ;;
    push-build)
        do_build
        do_push
        ;;
    *)
        usage
        exit 1
        ;;
esac
