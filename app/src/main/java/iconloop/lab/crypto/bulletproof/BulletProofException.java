package iconloop.lab.crypto.bulletproof;

public class BulletProofException extends Exception {

    public BulletProofException(String message) {
        super(message);
    }

    public BulletProofException(Throwable cause) {
        super(cause);
    }

    public BulletProofException(String message, Throwable cause) {
        super(message, cause);
    }
}