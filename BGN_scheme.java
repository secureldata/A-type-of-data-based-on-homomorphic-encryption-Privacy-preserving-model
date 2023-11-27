import java.math.BigInteger;
import java.security.SecureRandom;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1Pairing;
import it.unisa.dia.gas.plaf.jpbc.util.math.BigIntegerUtils;

public class BGN_scheme {

    public static final String start = "start";
    public static final String end = "end";
    private PairingParameters param;
    private BigInteger r;
    private BigInteger q; // This is the private key.
    private BigInteger order;
    private SecureRandom rng;

    public PublicKey gen(int bits) {
        rng = new SecureRandom();
        TypeA1CurveGenerator a1 = new TypeA1CurveGenerator(rng, 2, bits); // Requires
        // 2
        // prime																	// numbers.
        param = a1.generate();
        TypeA1Pairing pairing = new TypeA1Pairing(param);
        order = param.getBigInteger("n"); // Must extract the prime numbers for
        // both keys.
        r = param.getBigInteger("n0");
        q = param.getBigInteger("n1");
        Field<?> f = pairing.getG1();
        Element P = f.newRandomElement();
        P = P.mul(param.getBigInteger("l"));
        Element Q = f.newElement();
        Q = Q.set(P);
        Q = Q.mul(r);
        return new PublicKey(pairing, P, Q, order);
    }

    public Element encrypt(PublicKey PK, int msg) {
        BigInteger t = BigIntegerUtils.getRandom(PK.getN());
        int m = msg;
        //System.out.println("Hash is " + m);
        Field<?> f = PK.getField();
        Element A = f.newElement();
        Element B = f.newElement();
        Element C = f.newElement();
        A = A.set(PK.getP());
        A = A.mul(BigInteger.valueOf(m));
        B = B.set(PK.getQ());
        B = B.mul(t);
        C = C.set(A);
        C = C.add(B);
        return C;
    }

    public Element add(PublicKey PK, Element A, Element B) {
        BigInteger t = BigIntegerUtils.getRandom(PK.getN());
        Field<?> f = PK.getField();
        Element output = f.newElement();
        Element aux = f.newElement();
        aux.set(PK.getQ());
        aux.mul(t);
        output.set(A);
        output.add(B);
        output.add(aux);
        return output;
    }

    public Element mul(PublicKey PK, Element C, Element D) {
        BigInteger t = BigIntegerUtils.getRandom(PK.getN());

        Element T = PK.doPairing(C, D);

        Element K = PK.doPairing(PK.getQ(), PK.getQ());
        K = K.pow(t);
        return T.mul(K);
    }
    public String decryptMul(PublicKey PK, BigInteger sk, Element C) {
        Element PSK = PK.doPairing(PK.getP(), PK.getP());
        PSK.pow(sk);

        Element CSK = C.duplicate();
        CSK.pow(sk);
        Element aux = PSK.duplicate();

        BigInteger m = new BigInteger("1");
        while (!aux.isEqual(CSK)) {
            aux = aux.mul(PSK);
            m = m.add(BigInteger.valueOf(1));
        }
        return m.toString();
    }

    public String decrypt(PublicKey PK, BigInteger sk, Element C) {
        Field<?> f = PK.getField();
        Element T = f.newElement();
        Element K = f.newElement();
        Element aux = f.newElement();
        T = T.set(PK.getP());
        T = T.mul(sk);
        K = K.set(C);
        K = K.mul(sk);
        aux = aux.set(T);
        BigInteger m = new BigInteger("1");
        while (!aux.isEqual(K)) {
            // This is a brute force implementation of finding the discrete
            // logarithm.
            // Performance may be improved using algorithms such as Pollard's
            // Kangaroo.
            aux = aux.add(T);
            m = m.add(BigInteger.valueOf(1));
        }
        return m.toString();
    }
    public static void main(String[] args) {
        BGN_scheme b = new BGN_scheme();
        PublicKey PK = b.gen(256);

        int number=10;
        int Databases[][]=new int[10][number];
        double  result[]=new double [10];
        Element EDatabases[][]=new Element[10][number];
        Element resultend[]=new Element[10];
        for(int i=0;i<10;i++) {  //
            for (int j = 0; j < number; j++) {
                {
                    Databases[i][j]=445301;
                }
            }
        }
        System.out.println("数据库简易模型");
        for(int i=0;i<10;i++) {  //
            for (int j = 0; j < number; j++) {
                {
                    EDatabases[i][j]=b.encrypt(PK,Databases[i][j]);
                }
            }
        }
        System.out.println("数据库简易模型整库加密");
        for(int i=0;i<10;i++) {   //CA receives the encryption matrix and combines the encryption matrix into an encryption vector
            Element temp1=EDatabases[i][0];
            for (int j = 1;j<number; j++) {
                temp1=b.add(PK,EDatabases[i][j],temp1);
                resultend[i]=temp1;
            }
        }
        System.out.println("数据库简易模型加密后求和");
        for(int i=0;i<10;i++) {
            System.out.println(i);//
            result[i]=Double.valueOf(b.decrypt(PK, b.q, resultend[i]));
            System.out.println("result: " + result[i]);
        }
        System.out.println("数据库简易模型解密求和");
    }
}
