FROM squidfunk/mkdocs-material:7.2.2

## If you want to see exactly the same version as is published to GitHub pages
## use a private image for insiders, which requires authentication.

# docker login -u ${GITHUB_USERNAME} -p ${GITHUB_TOKEN} ghcr.io
# FROM ghcr.io/squidfunk/mkdocs-material-insiders

RUN pip install mike
RUN pip install mkdocs-macros-plugin
