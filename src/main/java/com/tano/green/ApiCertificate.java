package com.tano.green;

import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.Header;

import java.util.List;

public interface ApiCertificate {

    @GET("signercertificate/update")
    Call<String> getCertUpdate(@Header("x-resume-token") String token);

    @GET("signercertificate/status")
    Call<List<String>> getCertStatus();

}
