/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.cnv.aws.s3;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;

/**
 *
 * @author Owner
 */
public class S3Utils {

    static String generateBucketUrl(String region, String bucket) {
        String url = "https://s3-";
        url += region + ".amazonaws.com/" + bucket + "/";
        return url;
    }

    static String getDate() {
        DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));//server timezone
        return dateFormat.format(new Date());
    }

    static byte[] HmacSHA256(String data, byte[] key) throws Exception {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes("UTF8"));
    }

    static String getDateStamp() {
        TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat df = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'"); // Quoted "Z" to indicate UTC, no timezone offset
        df.setTimeZone(tz);
        return df.format(new Date());
    }

    static String getSignatureKey(String key, String dateStamp, String regionName, String serviceName, String stringToSign) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
        byte[] kDate = HmacSHA256(dateStamp, kSecret);
        byte[] kRegion = HmacSHA256(regionName, kDate);
        byte[] kService = HmacSHA256(serviceName, kRegion);
        byte[] kSigning = HmacSHA256("aws4_request", kService);
        byte[] signature = HmacSHA256(stringToSign, kSigning);
        return Hex.encodeHexString(signature);
    }

    /**
     * This will generate the Signed Policy for the given bucket with the access
     * key and secret
     *
     * @param accessKey S3 access key
     * @param secretKey S3 secret key
     * @param region region where the bucket resides
     * @param bucket the bucket name
     * @return
     */
    public static Map generateSignedPolicy(String accessKey, String secretKey, String region, String bucket) {
        Map map = new HashMap();
        try {
            String url = generateBucketUrl(region, bucket);
            String regionService = "s3";
            String algorithm = "AWS4-HMAC-SHA256";
            String dateStamp = getDateStamp();
            String date = getDate();
            String amzCredential = accessKey + "/" + date + "/" + region + "/" + regionService + "/aws4_request";

            String policyDocument = "{'expiration': '2020-12-01T12:00:00.000Z',"
                    + "'conditions': [{'bucket': '" + bucket + "'},"
                    + "['starts-with', '$key', ''],"
                    + "{'acl': 'public-read'},"
                    + "['starts-with', '$Content-Type', ''],"
                    + "{'x-amz-meta-uuid': '14365123651274'},"
                    + "{'x-amz-server-side-encryption': 'AES256'},"
                    + "{'x-amz-credential': '" + amzCredential + "'},"
                    + "{'x-amz-algorithm': '" + algorithm + "'},"
                    + "{'x-amz-date': '" + dateStamp + "'}]}";
            String encodedContent = Arrays.toString(Base64.getEncoder().encode(policyDocument.getBytes("UTF-8")));
            String stringToSign = encodedContent.replaceAll("\n", "").replaceAll("\r", "");
            String signature = getSignatureKey(secretKey, date, region, regionService, stringToSign);
            map.put("p", stringToSign);
            map.put("sg", signature);
            map.put("si", accessKey);
            map.put("url", url);
            map.put("bucket", bucket);
            map.put("date", dateStamp);
            map.put("amzCredential", amzCredential);
            map.put("algorithm", algorithm);
        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }
        return map;
    }
}
