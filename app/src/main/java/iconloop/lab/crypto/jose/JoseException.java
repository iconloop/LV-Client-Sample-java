package iconloop.lab.crypto.jose;

public class JoseException extends Exception {

    public JoseException(String message) {
        super(message);
    }

    public JoseException(Throwable cause) {
        super(cause);
    }

    public JoseException(String message, Throwable cause) {
        super(message, cause);
    }
}
