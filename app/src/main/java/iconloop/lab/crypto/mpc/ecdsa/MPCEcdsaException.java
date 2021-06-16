package iconloop.lab.crypto.mpc.ecdsa;

public class MPCEcdsaException extends Exception{

    MPCEcdsaException(String message) {
        super(message);
    }

    MPCEcdsaException(Throwable cause) {
        super(cause);
    }

    MPCEcdsaException(String message, Throwable cause) {
        super(message, cause);
    }
}
