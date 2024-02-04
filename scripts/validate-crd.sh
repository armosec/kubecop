#!/bin/bash

# print commands and their arguments as they are executed
set -x
# Store the original checksum of the file
original_checksum=$(md5sum chart/kubecop/charts/clustered-crds/crds/runtime-rule-binding.crd.yaml | awk '{print $1}')
original_checksum_namespaced=$(md5sum chart/kubecop/charts/namespaced-crds/crds/runtime-rule-binding.crd.yaml | awk '{print $1}')

# Run md_gen
go run cmd/rule_md_gen/generate_md.go
if [ $? -ne 0 ]; then
  echo "md_gen failed."
  exit 1
fi

# Store the new checksum of the file
new_checksum=$(md5sum chart/kubecop/charts/clustered-crds/crds/runtime-rule-binding.crd.yaml | awk '{print $1}')
new_checksum_namespaced=$(md5sum chart/kubecop/charts/namespaced-crds/crds/runtime-rule-binding.crd.yaml | awk '{print $1}')

# Compare the checksums
if [[ "$original_checksum" == "$new_checksum" ]]; then
  echo "The file is identical before and after running md_gen."
else
  echo "The file has changed after running md_gen."
  exit 1
fi

if [[ "$original_checksum_namespaced" == "$new_checksum_namespaced" ]]; then
  echo "The file is identical before and after running md_gen."
else
  echo "The file has changed after running md_gen."
  exit 1
fi