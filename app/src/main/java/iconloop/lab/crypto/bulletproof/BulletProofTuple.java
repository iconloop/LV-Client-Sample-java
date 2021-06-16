package iconloop.lab.crypto.bulletproof;

import com.google.gson.JsonObject;
import iconloop.lab.crypto.ec.bouncycastle.curve.EC;
import org.bouncycastle.util.encoders.Hex;

public class BulletProofTuple {
    private final EC CRV;
    private final EC.Point[] V;
    private final EC.Point A;
    private final EC.Point S;
    private final EC.Point T1;
    private final EC.Point T2;
    private final EC.Scalar taux;
    private final EC.Scalar mu;
    private final EC.Point[] L;
    private final EC.Point[] R;
    private final EC.Scalar a;
    private final EC.Scalar b;
    private final EC.Scalar t;

    public static final int Points_V    = 0x01;
    public static final int Point_A     = 0x02;
    public static final int Point_S     = 0x03;
    public static final int Point_T1    = 0x04;
    public static final int Point_T2    = 0x05;
    public static final int Scalar_Taux = 0x11;
    public static final int Scalar_Mu   = 0x12;
    public static final int Points_L    = 0x06;
    public static final int Points_R    = 0x07;
    public static final int Scalar_A    = 0x13;
    public static final int Scalar_B    = 0x14;
    public static final int Scalar_T    = 0x15;

    public BulletProofTuple(EC curve, EC.Point[] V, EC.Point A, EC.Point S, EC.Point T1, EC.Point T2, EC.Scalar taux, EC.Scalar mu, EC.Point[] L, EC.Point[] R, EC.Scalar a, EC.Scalar b, EC.Scalar t) {
        CRV = curve;
        this.V = V;
        this.A = A;
        this.S = S;
        this.T1 = T1;
        this.T2 = T2;
        this.taux = taux;
        this.mu = mu;
        this.L = L;
        this.R = R;
        this.a = a;
        this.b = b;
        this.t = t;
    }

    public BulletProofTuple(JsonObject jsonProof) {
        String strCurve = jsonProof.get("crv").getAsString();
        CRV = new EC(strCurve);

        String str = jsonProof.get("V").getAsString();
        String[] ss = str.split("  ");
        V = new EC.Point[ss.length];
        for(int i=0; i<ss.length; i++)
            V[i] = CRV.point(Hex.decode(ss[i]));
        A   = CRV.point(Hex.decode(jsonProof.get("A").getAsString()));
        S   = CRV.point(Hex.decode(jsonProof.get("S").getAsString()));
        T1  = CRV.point(Hex.decode(jsonProof.get("T1").getAsString()));
        T2  = CRV.point(Hex.decode(jsonProof.get("T2").getAsString()));
        taux= CRV.scalar(Hex.decode(jsonProof.get("taux").getAsString()));
        mu  = CRV.scalar(Hex.decode(jsonProof.get("mu").getAsString()));
        str = jsonProof.get("L").getAsString();
        ss = str.split("  ");
        L = new EC.Point[ss.length];
        for(int i=0; i<ss.length; i++)
            L[i] = CRV.point(Hex.decode(ss[i]));
        str = jsonProof.get("R").getAsString();
        ss = str.split("  ");
        R = new EC.Point[ss.length];
        for(int i=0; i<ss.length; i++)
            R[i] = CRV.point(Hex.decode(ss[i]));
        a   = CRV.scalar(Hex.decode(jsonProof.get("a").getAsString()));
        b   = CRV.scalar(Hex.decode(jsonProof.get("b").getAsString()));
        t   = CRV.scalar(Hex.decode(jsonProof.get("t").getAsString()));
    }

    public EC.Point[] getPointArray(int name) {
        switch (name) {
            case Points_V:
                return V;
            case Points_L:
                return L;
            case Points_R:
                return R;
            default :
                return null;
        }
    }

    public EC.Point getPoint(int name) {
        switch (name) {
            case Point_A:
                return A;
            case Point_S:
                return S;
            case Point_T1:
                return T1;
            case Point_T2:
                return T2;
            default :
                return null;
        }
    }

    public EC.Scalar getScalar(int name) {
        switch (name) {
            case Scalar_Taux:
                return taux;
            case Scalar_Mu:
                return mu;
            case Scalar_A:
                return a;
            case Scalar_B:
                return b;
            case Scalar_T:
                return t;
            default :
                return null;
        }
    }

    public String toJsonString() {
        JsonObject object = new JsonObject();
        object.addProperty("crv", CRV.getCurveName());
        String str = "";
        for(int i=0; i<V.length; i++){
            str = str + V[i].toString();
            if(i < V.length-1)
                str = str + "  ";
        }
        object.addProperty("V", str);
        object.addProperty("A", A.toString());
        object.addProperty("S", S.toString());
        object.addProperty("T1", T1.toString());
        object.addProperty("T2", T2.toString());
        object.addProperty("taux", taux.toString());
        object.addProperty("mu", mu.toString());
        str = "";
        for(int i=0; i<L.length; i++){
            str = str + L[i].toString();
            if(i < L.length-1)
                str = str + "  ";
        }
        object.addProperty("L", str);
        str = "";
        for(int i=0; i<R.length; i++){
            str = str + R[i].toString();
            if(i < R.length-1)
                str = str + "  ";
        }
        object.addProperty("R", str);
        object.addProperty("a", a.toString());
        object.addProperty("b", b.toString());
        object.addProperty("t", t.toString());

        return object.toString();
    }

}
