package com.tano.green;

import java.util.ArrayList;
import java.util.Arrays;

public class ConvertToDer {

    public static byte[] convertToDer(byte[] input) {
        int len = input.length / 2;
        byte var4 = 0;
        byte[] r = Arrays.copyOfRange(input, var4, len);
        int var7 = input.length;
        byte[] s = Arrays.copyOfRange(input, len, var7);
        return encodeSignature(r, s);
    }

    private static byte[] encodeSignature(byte[] r, byte[] s) {
        ArrayList<byte[]> x = new ArrayList<>();
        x.add(unsignedInteger(r));
        x.add(unsignedInteger(s));
        return sequence(x);
    }

    private static byte[] sequence(ArrayList<byte[]> members) throws RuntimeException {
        byte[] y = toBytes(members);
        ArrayList<byte[]> x = new ArrayList();
        x.add(new byte[]{48});
        x.add(computeLength(y.length));
        x.add(y);
        return toBytes(x);
    }

    private static byte[] toBytes(ArrayList<byte[]> x) {
        int l = 0;
        l = x.stream()
                .map(r -> r.length).reduce(l, Integer::sum);
        byte[] b = new byte[l];
        l = 0;

        for (byte[] r : x) {
            System.arraycopy(r, 0, b, l, r.length);
            l += r.length;
        }

        return b;
    }

    private static byte[] computeLength(int x) throws RuntimeException {
        byte[] var10000;
        if (x <= 127) {
            var10000 = new byte[]{(byte) x};
        } else {
            if (x >= 256) {
                throw new RuntimeException("Error convert to der");
            }
            var10000 = new byte[]{(byte) 129, (byte) x};
        }
        return var10000;
    }

    private static byte[] unsignedInteger(byte[] $this$unsignedInteger) {
        int pad = 0;

        int offset;
        for (offset = 0; offset < $this$unsignedInteger.length && $this$unsignedInteger[offset] == (byte) 0; ++offset) {
        }

        if (offset == $this$unsignedInteger.length) {
            return new byte[]{2, 1, 0};
        } else {
            byte var3 = $this$unsignedInteger[offset];
            byte var4 = (byte) 128;
            boolean var5 = false;
            if ((byte) (var3 & var4) != (byte) 0) {
                ++pad;
            }

            int length = $this$unsignedInteger.length - offset;
            byte[] der = new byte[2 + length + pad];
            der[0] = 2;
            der[1] = (byte) (length + pad);
            System.arraycopy($this$unsignedInteger, offset, der, 2 + pad, length);
            return der;
        }
    }
}
