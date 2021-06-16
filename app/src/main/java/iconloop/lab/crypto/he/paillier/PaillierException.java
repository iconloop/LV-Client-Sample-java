package iconloop.lab.crypto.he.paillier;

public class PaillierException extends Exception{
    PaillierException(String message) {
        super(message);
    }

    PaillierException(Throwable cause) {
        super(cause);
    }

    PaillierException(String message, Throwable cause) {
        super(message, cause);
    }
}
