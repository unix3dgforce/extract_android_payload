# extract_android_payload

Extract Android firmware images from an OTA payload.bin file.

Incremental firmware images are not supported

##### extract_android_payload.py - command-line tool for extracting partition images from payload.bin
        usage: extract_android_payload.py [-h] {extract,list} ...

##### positional arguments:  
    	{extract,list}  List of commands

##### optional arguments:
        -h, --help show this help message and exit

## Example

```
# python extract_android_payload.py extract -p system_ext payload.bin /tmp/
Extracting system_ext.img
```

```
# python extract_android_payload.py list payload.bin
....
Partition name: system
Partition size: 4252348416
Partition hash: fb3003033e6534fbc6377adc4078ad480781445d777ccb4d59cfe43caa674c45
....
Partition name: vendor
Partition size: 2112417792
Partition hash: 44704eeb0811f28b8fa31e7c76a3df7bb15b913c12dd3e38f112299fa3e60c8a
....
```

## Dependencies

```
python-protobuf
```


        