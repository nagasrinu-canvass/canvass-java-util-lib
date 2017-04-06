# Canvass Java Util Library

## List of modules
### 1. AWS S3
To generate the signed policy that can be used at client side to upload the files directly to S3
```java
S3Utils.generateSignedPolicy(<accessKey>, <secretKey>, <region>, <bucket>);
```
