#!/bin/sh

# <https://cloud.google.com/storage/docs/using-cors#json-api>

# set your bucket name
BUCKET_NAME=
# set your oauth2 token
# <https://developers.google.com/oauthplayground/>
OAUTH2_TOKEN=
# <https://cloud.google.com/storage/docs/cors-configurations>
CORS_CONFIG_FILE=cors-configuration.json
curl --request PATCH \
 "https://storage.googleapis.com/storage/v1/b/${BUCKET_NAME}?fields=cors" \
 --header "Authorization: Bearer ${OAUTH2_TOKEN}" \
 --header 'Content-Type: application/json' \
 --data-binary "@${CORS_CONFIG_FILE}"
