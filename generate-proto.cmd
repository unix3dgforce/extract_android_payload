@echo off
echo generating proto...
python -m grpc_tools.protoc -I=. --python_out=. proto/update_metadata.proto
echo DONE
