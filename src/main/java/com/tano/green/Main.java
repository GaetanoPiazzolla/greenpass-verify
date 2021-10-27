package com.tano.green;

import java.awt.image.BufferedImage;
import java.io.*;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Inflater;

import COSE.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.iot.cbor.CborMap;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

import com.upokecenter.cbor.CBORObject;
import nl.minvws.encoding.Base45;
import okhttp3.OkHttpClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.converter.scalars.ScalarsConverterFactory;

import javax.imageio.ImageIO;

public class Main {
    private static final Map<String, PublicKey> keyMap = new HashMap<>();

    private static final int ECDSA_256 = -7;
    private static final int RSA_PSS_256 = -37;
    private static final int BUFFER_SIZE = 1024;

    private static final String BASE_URL = "https://get.dgc.gov.it/v1/dgc/";
    private static final String HEADER_KID = "x-kid";
    private static final String HEADER_RESUME_TOKEN = "x-resume-token";
    private static ApiCertificate apiCertificate = null;

    static {

        try {
            System.out.println("Loading certificates");

            Security.addProvider(new BouncyCastleProvider());

            Gson gson = new GsonBuilder()
                    .setLenient()
                    .create();
            OkHttpClient client = SSLConfig.getHttpClient();
            Retrofit retrofit = new Retrofit.Builder()
                    .baseUrl(BASE_URL)
                    .addConverterFactory(ScalarsConverterFactory.create())
                    .addConverterFactory(GsonConverterFactory.create(gson))
                    .client(client)
                    .build();

            apiCertificate = retrofit.create(ApiCertificate.class);

            List<String> possibleKids = apiCertificate.getCertStatus().execute().body();
            if (possibleKids == null || possibleKids.isEmpty()) {
                throw new Exception("unable to complete certificate validation");
            }

            System.out.println(possibleKids.size() + " available kids");

            // recursive function to fetch all available certificates
            fetchCertificate("", possibleKids);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void fetchCertificate(String resumeToken, List<String> possibleKids) throws CertificateException, IOException {

        System.out.println("Fetching new certificate");

        Response<String> resp = apiCertificate.getCertUpdate(resumeToken).execute();

        if (resp.isSuccessful()) {
            var headers = resp.headers();
            var responseKid = headers.get(HEADER_KID);
            var newResumeToken = headers.get(HEADER_RESUME_TOKEN);
            String keyString = resp.body();

            if (keyString != null && !keyString.isBlank()) {
                if (possibleKids.contains(responseKid)) {
                    PublicKey key = getPublicKey(keyString);
                    keyMap.put(responseKid, key);
                } else {
                    System.out.println(".....mumble.... this should never happen");
                }
                fetchCertificate(newResumeToken, possibleKids);
            }
        }
    }

    public static PublicKey getPublicKey(String key) throws CertificateException {
        var decoded = Base64.getDecoder().decode(key);
        InputStream inputStream = new ByteArrayInputStream(decoded);
        return CertificateFactory.getInstance("X.509").generateCertificate(inputStream).getPublicKey();
    }

    public static void main(String[] args) throws Exception {

        // 1 - read text from file
        File file = new File("C://temp/green-pass.jpg");
        BufferedImage bufferedImage = ImageIO.read(file);
        LuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        Result result = new MultiFormatReader().decode(bitmap);
        String text = result.getText();

        // 2 - remove prefix "HC1:" and decode base45 string
        byte[] bytecompressed = Base45.getDecoder().decode(text.substring(4));

        // 3 - inflate string using zlib
        Inflater inflater = new Inflater();
        inflater.setInput(bytecompressed);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(bytecompressed.length);
        byte[] buffer = new byte[BUFFER_SIZE];
        while (!inflater.finished()) {
            final int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }

        // 4 - decode COSE message
        // and create CborObject MAP
        Message a = Encrypt0Message.DecodeFromBytes(outputStream.toByteArray());
        CborMap cborMap = CborMap.createFromCborByteArray(a.GetContent());
        System.out.println(cborMap.toJsonString());

        // validate
        CBORObject messageObject = CBORObject.DecodeFromBytes(outputStream.toByteArray());
        byte[] coseSignature = messageObject.get(3).GetByteString();
        byte[] protectedHeader = messageObject.get(0).GetByteString();
        byte[] content = messageObject.get(2).GetByteString();
        byte[] dataToBeVerified = getValidationData(protectedHeader, content);
        CBORObject unprotectedHeader = messageObject.get(1);
        byte[] kid = getKid(protectedHeader, unprotectedHeader);
        String kidBase64 = new String(Base64.getEncoder().encode(kid));

        System.out.println("kid=" + kidBase64);
        PublicKey key = keyMap.get(kidBase64);

        switch (getAlgoFromHeader(protectedHeader, unprotectedHeader)) {

            case ECDSA_256:
                System.out.println("ECDSA_256");

                Signature signature = Signature.getInstance("SHA256withECDSA");
                signature.initVerify(key);
                signature.update(dataToBeVerified);
                coseSignature = ConvertToDer.convertToDer(coseSignature);
                if (signature.verify(coseSignature)) {
                    System.out.println("Verified");
                } else {
                    System.out.println("Not verified");
                }
                break;

            case RSA_PSS_256:
                System.out.println("RSA_PSS_256 - not implemented");
                break;
        }


    }

    private static byte[] getKid(byte[] protectedHeader, CBORObject unprotectedHeader) {
        CBORObject key = HeaderKeys.KID.AsCBOR();
        CBORObject kid;
        if (protectedHeader.length != 0) {
            try {
                kid = CBORObject.DecodeFromBytes(protectedHeader).get(key);
                if (kid == null) {
                    kid = unprotectedHeader.get(key);
                }
            } catch (Exception var8) {
                kid = unprotectedHeader.get(key);
            }
        } else {
            kid = unprotectedHeader.get(key);
        }
        return kid.GetByteString();
    }

    private static int getAlgoFromHeader(byte[] protectedHeader, CBORObject unprotectedHeader) {
        int algoNumber;
        if (protectedHeader.length != 0) {
            try {
                CBORObject algo = CBORObject.DecodeFromBytes(protectedHeader).get(1);
                algoNumber = algo != null ? algo.AsInt32Value() : unprotectedHeader.get(1).AsInt32Value();
            } catch (Exception var7) {
                algoNumber = unprotectedHeader.get(1).AsInt32Value();
            }
        } else {
            algoNumber = unprotectedHeader.get(1).AsInt32Value();
        }
        return algoNumber;
    }

    private static byte[] getValidationData(byte[] protectedHeader, byte[] content) {
        return CBORObject.NewArray().
                Add("Signature1").
                Add(protectedHeader).
                Add(new byte[0]).
                Add(content).EncodeToBytes();
    }



}
